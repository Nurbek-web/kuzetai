"""Controller-owned two-epoch production campaign coordination for acceptance V3."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from protector.pilot.acceptance import ExecutionBindingV2, ScheduledFaultV2
from protector.pilot.acceptance_authority import (
    AcceptanceAuthorityTrustContextV2,
    AcceptanceFaultAckResponseV2,
)
from protector.pilot.acceptance_c2 import (
    SQLiteTargetExecutionTransitionJournalV3,
    TargetC2AuthorityV3,
    TargetC2ContinuationEvidenceV3,
    TargetC2EvidenceV3,
    TargetExecutionTransitionEntryV3,
    _execution_binding_from_runtime_identity,
    authorize_target_c2_continuation_v3,
)
from protector.pilot.acceptance_channel import (
    AcceptanceRuntimeGrantV3,
    ControllerAcceptanceChannelV3,
)
from protector.pilot.acceptance_source_profile import (
    VerifiedTargetSourceProfileAttestationV2,
    _require_verified_target_source_profile_attestation,
)
from protector.pilot.acceptance_target import (
    TargetRuntimeLaunchRequestV2,
    TargetRuntimeObservationV2,
)
from protector.pilot.acceptance_target_controller import (
    TargetRuntimeControllerEnvironmentV2,
    _consume_controller_owned_runtime_for_c2,
    launch_and_observe_controller_owned_target_runtime,
)
from protector.pilot.acceptance_trust import canonical_json_bytes
from protector.pilot.acceptance_work import (
    TargetUniqueWorkPlanV2,
    TargetUniqueWorkProjectionV2,
    derive_target_unique_work_plan,
    verify_target_unique_work_projection_value,
)
from protector.pilot.runtime.deepstream import DeepStreamGraphSpec

_MAX_CHANNEL_WAIT_SECONDS = 300.0


def _make_authenticated_fault_acknowledgement_tools():
    """Issue one-shot capabilities for exact durable collector responses."""

    issuer = object()
    key = secrets.token_bytes(32)

    def receipt(
        payload: bytes,
        acknowledgement_bytes: bytes,
        session_bytes: bytes,
    ) -> bytes:
        framed = b"".join(
            len(value).to_bytes(8, "big") + value
            for value in (
                payload,
                acknowledgement_bytes,
                session_bytes,
            )
        )
        return hmac.digest(
            key,
            b"authenticated-target-fault-ack:" + framed,
            "sha256",
        )

    class _AuthenticatedFaultAcknowledgement:
        __slots__ = (
            "__acknowledgement_bytes",
            "__collector",
            "__consumed",
            "__lock",
            "__payload",
            "__receipt",
            "__session_bytes",
        )

        def __init__(
            self,
            *,
            token: object,
            acknowledgement_bytes: bytes,
            collector: object,
            payload: bytes,
            session_bytes: bytes,
        ) -> None:
            if token is not issuer:
                raise TypeError(
                    "authenticated fault acknowledgement requires "
                    "its private issuer"
                )
            self.__acknowledgement_bytes = acknowledgement_bytes
            self.__collector = collector
            self.__payload = payload
            self.__session_bytes = session_bytes
            self.__receipt = receipt(
                payload,
                acknowledgement_bytes,
                session_bytes,
            )
            self.__consumed = False
            self.__lock = threading.Lock()

        def __copy__(self) -> None:
            raise TypeError(
                "authenticated fault acknowledgement cannot be copied "
                "or serialized"
            )

        def __deepcopy__(self, _memo: object) -> None:
            raise TypeError(
                "authenticated fault acknowledgement cannot be copied "
                "or serialized"
            )

        def __reduce_ex__(self, _protocol: int) -> None:
            raise TypeError(
                "authenticated fault acknowledgement cannot be copied "
                "or serialized"
            )

    def payload(
        *,
        acknowledgement: AcceptanceFaultAckResponseV2,
        collector: object,
        session_binding: dict[str, object],
        durable_response: dict[str, object],
    ) -> bytes:
        checked = AcceptanceFaultAckResponseV2.model_validate(
            acknowledgement.model_dump(mode="python"),
            strict=True,
        )
        checked_response = AcceptanceFaultAckResponseV2.model_validate_json(
            canonical_json_bytes(durable_response),
            strict=True,
        )
        normalized_session = canonical_json_bytes(session_binding)
        normalized_response = canonical_json_bytes(checked_response)
        if (
            checked_response != checked
            or any(
                checked_response.model_dump(mode="json").get(field)
                != session_binding.get(field)
                for field in (
                    "collector_id",
                    "site_id",
                    "manifest_sha256",
                    "gate",
                    "launch_attestation_sha256",
                    "execution_binding_sha256",
                    "fault_schedule_sha256",
                    "trust_binding",
                )
            )
        ):
            raise ValueError(
                "authenticated fault acknowledgement differs from "
                "its durable collector session"
            )
        return canonical_json_bytes(
            {
                "schema_version": (
                    "authenticated-target-fault-acknowledgement.v3"
                ),
                "collector_identity": id(collector),
                "collector_session_sha256": hashlib.sha256(
                    normalized_session
                ).hexdigest(),
                "fault_id": checked.fault_id,
                "phase": checked.phase,
                "command_id": checked.command_id,
                "durable_response_sha256": hashlib.sha256(
                    normalized_response
                ).hexdigest(),
            }
        )

    registered_source: type[object] | None = None
    registration_lock = threading.Lock()

    def register(
        collector_type: type[object],
    ) -> Callable[..., object]:
        nonlocal registered_source
        if not isinstance(collector_type, type):
            raise TypeError(
                "authenticated fault acknowledgement source must be a type"
            )
        with registration_lock:
            if registered_source is not None:
                raise RuntimeError(
                    "authenticated fault acknowledgement source "
                    "is already registered"
                )
            registered_source = collector_type

        def issue(
            *,
            acknowledgement: AcceptanceFaultAckResponseV2,
            collector: object,
        ) -> object:
            if type(collector) is not collector_type:
                raise TypeError(
                    "authenticated fault acknowledgement source is invalid"
                )
            checked = AcceptanceFaultAckResponseV2.model_validate(
                acknowledgement.model_dump(mode="python"),
                strict=True,
            )
            operation_lock = getattr(collector, "_operation_lock", None)
            if type(operation_lock) is not type(threading.RLock()):
                raise RuntimeError(
                    "authenticated collector operation lock is unavailable"
                )
            with operation_lock:
                session_binding = getattr(collector, "_binding", None)
                journal = getattr(collector, "_journal", None)
                schedule = getattr(collector, "_schedule", None)
                recorded = getattr(
                    collector,
                    "_fault_acknowledgements",
                    None,
                )
                if (
                    type(session_binding) is not dict
                    or journal is None
                    or type(schedule) is not dict
                    or type(recorded) is not dict
                    or checked.fault_id not in schedule
                    or recorded.get(
                        (checked.fault_id, checked.phase)
                    )
                    != checked.model_dump(mode="json")
                ):
                    raise RuntimeError(
                        "authenticated collector session is unavailable"
                    )
                durable_response = journal.response(
                    f"fault-ack:{checked.command_id}"
                )
                if durable_response is None:
                    durable_response = journal.response(
                        "fault-prepare:"
                        f"{checked.fault_id}:{checked.phase}"
                    )
                    if (
                        type(durable_response) is not dict
                        or durable_response.get("state") != "COMMITTED"
                    ):
                        raise RuntimeError(
                            "durable fault acknowledgement is unavailable"
                        )
                    scheduled_fault = schedule[checked.fault_id]
                    durable_response = {
                        **durable_response,
                        "schema_version": (
                            "acceptance-fault-ack-response.v2"
                        ),
                        "state": (
                            scheduled_fault.expected_degraded
                            if checked.phase == "inject"
                            else scheduled_fault.expected_recovery
                        ),
                    }
                if type(durable_response) is not dict:
                    raise RuntimeError(
                        "durable fault acknowledgement is invalid"
                    )
                serialized = payload(
                    acknowledgement=checked,
                    collector=collector,
                    session_binding=dict(session_binding),
                    durable_response=durable_response,
                )
                acknowledgement_bytes = canonical_json_bytes(checked)
                session_bytes = canonical_json_bytes(session_binding)
            return _AuthenticatedFaultAcknowledgement(
                token=issuer,
                acknowledgement_bytes=acknowledgement_bytes,
                collector=collector,
                payload=serialized,
                session_bytes=session_bytes,
            )

        return issue

    def consume(
        candidate: object,
        *,
        collector: object,
    ) -> AcceptanceFaultAckResponseV2:
        if type(candidate) is not _AuthenticatedFaultAcknowledgement:
            raise TypeError(
                "target continuation requires an authenticated "
                "collector acknowledgement capability"
            )
        with candidate._AuthenticatedFaultAcknowledgement__lock:
            if candidate._AuthenticatedFaultAcknowledgement__consumed:
                raise RuntimeError(
                    "authenticated fault acknowledgement was already consumed"
                )
            stored_collector = (
                candidate._AuthenticatedFaultAcknowledgement__collector
            )
            stored_acknowledgement_bytes = (
                candidate
                ._AuthenticatedFaultAcknowledgement__acknowledgement_bytes
            )
            stored_payload = (
                candidate._AuthenticatedFaultAcknowledgement__payload
            )
            stored_receipt = (
                candidate._AuthenticatedFaultAcknowledgement__receipt
            )
            stored_session_bytes = (
                candidate._AuthenticatedFaultAcknowledgement__session_bytes
            )
            current_session = getattr(collector, "_binding", None)
            if (
                stored_collector is not collector
                or type(stored_acknowledgement_bytes) is not bytes
                or type(stored_payload) is not bytes
                or type(stored_receipt) is not bytes
                or type(stored_session_bytes) is not bytes
                or type(current_session) is not dict
                or not hmac.compare_digest(
                    stored_session_bytes,
                    canonical_json_bytes(current_session),
                )
                or not hmac.compare_digest(
                    stored_receipt,
                    receipt(
                        stored_payload,
                        stored_acknowledgement_bytes,
                        stored_session_bytes,
                    ),
                )
            ):
                raise RuntimeError(
                    "authenticated fault acknowledgement provenance changed"
                )
            candidate._AuthenticatedFaultAcknowledgement__consumed = True
            return AcceptanceFaultAckResponseV2.model_validate_json(
                stored_acknowledgement_bytes,
                strict=True,
            )

    return register, consume


(
    _register_authenticated_fault_acknowledgement_source,
    _consume_authenticated_fault_acknowledgement,
) = _make_authenticated_fault_acknowledgement_tools()


def _make_campaign_configuration_tools():
    issuer = object()
    key = secrets.token_bytes(32)

    def payload(
        *,
        owner: object,
        collector_id: str,
        trust_context: AcceptanceAuthorityTrustContextV2,
        requests: tuple[TargetRuntimeLaunchRequestV2, ...],
        graph: DeepStreamGraphSpec,
        channel_root: Path,
        environment_factory: TargetEnvironmentFactoryV3,
        source_profile_provider: TargetSourceProfileProviderV3,
        runtime_launcher: TargetRuntimeLauncherV3,
        child_grant_hook: Callable[
            [Path, AcceptanceRuntimeGrantV3],
            None,
        ]
        | None,
        authenticated_collector: object | None,
        monotonic: Callable[[], float],
        sleep: Callable[[float], None],
        channel_wait_seconds: float,
        reviewed_mount_sources: frozenset[Path],
    ) -> bytes:
        return canonical_json_bytes(
            {
                "schema_version": "target-campaign-configuration.v3",
                "owner_identity": id(owner),
                "collector_id": collector_id,
                "trust_context_identity": id(trust_context),
                "launch_requests": [
                    request.model_dump(mode="json")
                    for request in requests
                ],
                "graph": graph.model_dump(mode="json"),
                "channel_root": str(channel_root),
                "environment_factory_identity": id(environment_factory),
                "source_profile_provider_identity": id(
                    source_profile_provider
                ),
                "runtime_launcher_identity": id(runtime_launcher),
                "child_grant_hook_identity": (
                    None
                    if child_grant_hook is None
                    else id(child_grant_hook)
                ),
                "authenticated_collector_identity": (
                    None
                    if authenticated_collector is None
                    else id(authenticated_collector)
                ),
                "monotonic_identity": id(monotonic),
                "sleep_identity": id(sleep),
                "channel_wait_seconds_hex": channel_wait_seconds.hex(),
                "reviewed_mount_sources": sorted(
                    str(path) for path in reviewed_mount_sources
                ),
            }
        )

    class _CampaignConfiguration:
        __slots__ = ("__payload", "__receipt")

        def __init__(
            self,
            *,
            token: object,
            serialized: bytes,
        ) -> None:
            if token is not issuer:
                raise TypeError(
                    "campaign configuration requires its private issuer"
                )
            self.__payload = serialized
            self.__receipt = hmac.digest(
                key,
                b"target-campaign:" + serialized,
                "sha256",
            )

        def __copy__(self) -> None:
            raise TypeError(
                "campaign configuration cannot be copied or serialized"
            )

        def __deepcopy__(self, _memo: object) -> None:
            raise TypeError(
                "campaign configuration cannot be copied or serialized"
            )

        def __reduce_ex__(self, _protocol: int) -> None:
            raise TypeError(
                "campaign configuration cannot be copied or serialized"
            )

    def issue(**configuration: object) -> object | None:
        if (
            configuration["runtime_launcher"]
            is not launch_and_observe_controller_owned_target_runtime
            or configuration["child_grant_hook"] is not None
        ):
            return None
        serialized = payload(**configuration)  # type: ignore[arg-type]
        return _CampaignConfiguration(
            token=issuer,
            serialized=serialized,
        )

    def require(candidate: object, **configuration: object) -> None:
        if type(candidate) is not _CampaignConfiguration:
            raise RuntimeError(
                "injected target campaign components are explicitly "
                "non-authorizing"
            )
        serialized = payload(**configuration)  # type: ignore[arg-type]
        if (
            configuration["runtime_launcher"]
            is not launch_and_observe_controller_owned_target_runtime
            or configuration["child_grant_hook"] is not None
            or type(candidate._CampaignConfiguration__payload) is not bytes
            or type(candidate._CampaignConfiguration__receipt) is not bytes
            or not hmac.compare_digest(
                candidate._CampaignConfiguration__payload,
                serialized,
            )
            or not hmac.compare_digest(
                candidate._CampaignConfiguration__receipt,
                hmac.digest(
                    key,
                    b"target-campaign:" + serialized,
                    "sha256",
                ),
            )
        ):
            raise RuntimeError(
                "injected target campaign components are explicitly "
                "non-authorizing"
            )

    return issue, require


(
    _issue_campaign_configuration,
    _require_campaign_configuration,
) = _make_campaign_configuration_tools()


def _require_exact_channel_mount(
    environment: TargetRuntimeControllerEnvironmentV2,
    channel_path: Path,
    *,
    reviewed_mount_sources: frozenset[Path] = frozenset(),
) -> None:
    try:
        channel_resolved = channel_path.resolve(strict=True)
        channel_metadata = channel_resolved.stat()
    except OSError as exc:
        raise ValueError("target runtime channel mount is unavailable") from exc
    if channel_resolved != channel_path:
        raise ValueError("target runtime channel mount cannot use an alias")
    allowed_sources = {channel_resolved}
    allowed_identities = {
        (channel_metadata.st_dev, channel_metadata.st_ino): channel_resolved
    }
    for reviewed in reviewed_mount_sources:
        try:
            resolved = reviewed.resolve(strict=True)
            metadata = resolved.stat()
        except OSError as exc:
            raise ValueError("reviewed runtime mount source is unavailable") from exc
        if resolved != reviewed:
            raise ValueError("reviewed runtime mount source cannot use an alias")
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in allowed_identities:
            raise ValueError(
                "reviewed runtime mount sources contain an inode alias"
            )
        allowed_identities[identity] = resolved
        allowed_sources.add(resolved)
    destinations: list[str] = []
    seen_destinations: set[str] = set()
    seen_source_identities: set[tuple[int, int]] = set()
    arguments = environment.reviewed_mount_argv
    for option, specification in zip(
        arguments[::2],
        arguments[1::2],
        strict=True,
    ):
        if option != "--mount":
            raise ValueError("target runtime environment contains a non-mount option")
        matched = re.fullmatch(
            r"type=bind,src=([^,]+),dst=([^,]+)(,readonly)?",
            specification,
        )
        if matched is None:
            raise ValueError("target runtime channel mount syntax is invalid")
        source, destination, readonly = matched.groups()
        if destination in seen_destinations:
            raise ValueError(
                "target runtime mount destination is duplicated"
            )
        seen_destinations.add(destination)
        source_path = Path(source)
        try:
            source_resolved = source_path.resolve(strict=True)
            source_metadata = source_resolved.stat()
        except OSError as exc:
            raise ValueError("target runtime mount source is unavailable") from exc
        source_identity = (
            source_metadata.st_dev,
            source_metadata.st_ino,
        )
        if (
            not source_path.is_absolute()
            or not Path(destination).is_absolute()
            or source != os.path.normpath(source)
            or destination != os.path.normpath(destination)
            or source_resolved != source_path
            or source_resolved not in allowed_sources
            or allowed_identities.get(source_identity) != source_resolved
            or source_identity in seen_source_identities
            or (
                source_resolved != channel_resolved
                and (
                    source_resolved == channel_resolved.parent
                    or source_resolved.parent == channel_resolved.parent
                    or source_resolved in channel_resolved.parents
                )
            )
        ):
            raise ValueError(
                "target runtime mount is outside the exact resolved allowlist "
                "or would expose controller authority"
            )
        seen_source_identities.add(source_identity)
        if source_resolved == channel_resolved:
            if readonly is not None:
                raise ValueError("target runtime channel must be a read/write mount")
            destinations.append(destination)
    if len(destinations) != 1:
        raise ValueError("target runtime requires one exact protected channel mount")
    command_values = tuple(environment.command)
    occurrences = tuple(
        index
        for index, value in enumerate(command_values)
        if value == "--acceptance-channel"
    )
    if (
        len(occurrences) != 1
        or occurrences[0] + 1 >= len(command_values)
        or command_values[occurrences[0] + 1] != destinations[0]
    ):
        raise ValueError("target runtime command differs from its protected channel mount")


class TargetEnvironmentFactoryV3(Protocol):
    def __call__(
        self,
        request: TargetRuntimeLaunchRequestV2,
        channel_path: Path,
    ) -> TargetRuntimeControllerEnvironmentV2: ...


class TargetSourceProfileProviderV3(Protocol):
    def __call__(
        self,
        request: TargetRuntimeLaunchRequestV2,
    ) -> VerifiedTargetSourceProfileAttestationV2: ...


class TargetRuntimeLauncherV3(Protocol):
    def __call__(
        self,
        request: TargetRuntimeLaunchRequestV2,
        environment: TargetRuntimeControllerEnvironmentV2,
    ) -> tuple[object, TargetRuntimeObservationV2]: ...


@dataclass(frozen=True)
class TargetCampaignCompletionV3:
    c2_evidence: TargetC2EvidenceV3
    c2_capability: object
    final_runtime: object
    final_channel: ControllerAcceptanceChannelV3


@dataclass(frozen=True)
class TargetRuntimeContinuationCompletionV3:
    """Private-capability-backed completion of the canonical +40s restart."""

    evidence: TargetC2ContinuationEvidenceV3
    capability: object
    final_runtime: object
    final_channel: ControllerAcceptanceChannelV3


def _raise_with_cleanup(
    primary: BaseException,
    runtime: object | None,
    channel: ControllerAcceptanceChannelV3 | None,
) -> None:
    failures: list[BaseException] = [primary]
    if runtime is not None:
        try:
            runtime.cleanup()
        except BaseException as cleanup:
            failures.append(cleanup)
    if channel is not None:
        try:
            channel.abort()
        except BaseException as cleanup:
            failures.append(cleanup)
    if len(failures) == 1:
        raise primary
    raise BaseExceptionGroup(
        "target campaign failed and runtime cleanup also failed",
        failures,
    ) from primary


class TargetCampaignCoordinatorV3:
    """Run exactly restart epoch + authorized epoch before any V2 collector."""

    def __init__(
        self,
        *,
        collector_id: str,
        trust_context: AcceptanceAuthorityTrustContextV2,
        launch_requests: tuple[
            TargetRuntimeLaunchRequestV2,
            TargetRuntimeLaunchRequestV2,
        ],
        graph: DeepStreamGraphSpec,
        channel_root: Path,
        environment_factory: TargetEnvironmentFactoryV3,
        source_profile_provider: TargetSourceProfileProviderV3,
        runtime_launcher: TargetRuntimeLauncherV3 = (
            launch_and_observe_controller_owned_target_runtime
        ),
        child_grant_hook: Callable[
            [Path, AcceptanceRuntimeGrantV3],
            None,
        ]
        | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        channel_wait_seconds: float = _MAX_CHANNEL_WAIT_SECONDS,
        reviewed_mount_sources: tuple[Path, ...] = (),
    ) -> None:
        if (
            type(launch_requests) is not tuple
            or len(launch_requests) != 2
            or any(
                type(request) is not TargetRuntimeLaunchRequestV2
                for request in launch_requests
            )
        ):
            raise ValueError(
                "target campaign requires one exact two-epoch launch chain"
            )
        requests = tuple(
            TargetRuntimeLaunchRequestV2.model_validate(
                request.model_dump(mode="python")
            )
            for request in launch_requests
        )
        first, second = requests
        if (
            type(first) is not TargetRuntimeLaunchRequestV2
            or type(second) is not TargetRuntimeLaunchRequestV2
            or second.runtime_epoch != first.runtime_epoch + 1
            or first.runtime_epoch_started_generation != first.runtime_epoch
            or second.runtime_epoch_started_generation != second.runtime_epoch
            or first.launch_nonce == second.launch_nonce
            or first.launch != second.launch
            or first.campaign_id != second.campaign_id
            or first.gate != second.gate
            or first.manifest_sha256 != second.manifest_sha256
            or not channel_root.is_absolute()
            or not callable(environment_factory)
            or not callable(source_profile_provider)
            or not callable(runtime_launcher)
            or not callable(monotonic)
            or not callable(sleep)
            or type(channel_wait_seconds) is not float
            or not 0.0 < channel_wait_seconds <= _MAX_CHANNEL_WAIT_SECONDS
            or type(reviewed_mount_sources) is not tuple
            or any(
                not isinstance(path, Path)
                for path in reviewed_mount_sources
            )
        ):
            raise ValueError("target campaign requires one exact two-epoch launch chain")
        self._collector_id = collector_id
        self._trust_context = trust_context
        self._requests = requests
        self._graph = graph
        self._channel_root = channel_root
        self._environment_factory = environment_factory
        self._source_profile_provider = source_profile_provider
        self._runtime_launcher = runtime_launcher
        self._child_grant_hook = child_grant_hook
        self._monotonic = monotonic
        self._sleep = sleep
        self._wait_seconds = channel_wait_seconds
        self._reviewed_mount_sources = frozenset(reviewed_mount_sources)
        self._configuration_capability = _issue_campaign_configuration(
            owner=self,
            collector_id=self._collector_id,
            trust_context=self._trust_context,
            requests=self._requests,
            graph=self._graph,
            channel_root=self._channel_root,
            environment_factory=self._environment_factory,
            source_profile_provider=self._source_profile_provider,
            runtime_launcher=self._runtime_launcher,
            child_grant_hook=self._child_grant_hook,
            authenticated_collector=None,
            monotonic=self._monotonic,
            sleep=self._sleep,
            channel_wait_seconds=self._wait_seconds,
            reviewed_mount_sources=self._reviewed_mount_sources,
        )

    def _wait(self, operation: Callable[[], object], label: str) -> object:
        deadline = self._monotonic() + self._wait_seconds
        while True:
            try:
                return operation()
            except FileNotFoundError:
                if self._monotonic() >= deadline:
                    raise RuntimeError(
                        f"target campaign timed out waiting for {label}"
                    ) from None
                self._sleep(0.05)

    def run(self) -> TargetCampaignCompletionV3:
        _require_campaign_configuration(
            self._configuration_capability,
            owner=self,
            collector_id=self._collector_id,
            trust_context=self._trust_context,
            requests=self._requests,
            graph=self._graph,
            channel_root=self._channel_root,
            environment_factory=self._environment_factory,
            source_profile_provider=self._source_profile_provider,
            runtime_launcher=self._runtime_launcher,
            child_grant_hook=self._child_grant_hook,
            authenticated_collector=None,
            monotonic=self._monotonic,
            sleep=self._sleep,
            channel_wait_seconds=self._wait_seconds,
            reviewed_mount_sources=self._reviewed_mount_sources,
        )
        c2 = TargetC2AuthorityV3(
            collector_id=self._collector_id,
            site_id=self._requests[0].launch.site_id,
            campaign_id=self._requests[0].campaign_id,
            gate=self._requests[0].gate,
        )
        final_runtime: object | None = None
        final_channel: ControllerAcceptanceChannelV3 | None = None
        for index, request in enumerate(self._requests):
            runtime: object | None = None
            channel: ControllerAcceptanceChannelV3 | None = None
            try:
                channel = ControllerAcceptanceChannelV3.create(
                    root=self._channel_root,
                    collector_id=self._collector_id,
                    launch_request=request,
                )
                environment = self._environment_factory(
                    request,
                    channel.runtime_claim_path,
                )
                if (
                    type(environment) is not TargetRuntimeControllerEnvironmentV2
                ):
                    raise ValueError(
                        "target runtime environment omits the exact protected channel"
                    )
                _require_exact_channel_mount(
                    environment,
                    channel.runtime_claim_path,
                    reviewed_mount_sources=self._reviewed_mount_sources,
                )
                runtime, observation = self._runtime_launcher(request, environment)
                if type(observation) is not TargetRuntimeObservationV2:
                    raise TypeError(
                        "target runtime launcher returned invalid observation"
                    )
                identity = observation.identity
                source_profile = self._source_profile_provider(request)
                _require_verified_target_source_profile_attestation(source_profile)
                plan, plan_authority = derive_target_unique_work_plan(
                    trust_context=self._trust_context,
                    launch_request=request,
                    runtime_identity=identity,
                    graph=self._graph,
                )
                grant = channel.publish_grant(
                    runtime_identity=identity,
                    unique_work_plan=plan,
                    verified_source_profile=source_profile,
                )
                if self._child_grant_hook is not None:
                    self._child_grant_hook(channel.runtime_claim_path, grant)
                result, channel_receipt = self._wait(
                    channel.consume_result,
                    "runtime result",
                )
                _projection, work_capability = (
                    verify_target_unique_work_projection_value(
                        result.unique_work_projection,
                        plan_authority=plan_authority,
                        native_prewarm=result.native_prewarm,
                    )
                )
                action = "restart" if index == 0 else "authorize"
                channel.publish_directive(action=action)
                self._wait(channel.consume_ack, "runtime acknowledgement")
                runtime_capability = _consume_controller_owned_runtime_for_c2(
                    runtime
                )
                c2.add_epoch(
                    runtime_capability=runtime_capability,
                    channel_receipt=channel_receipt,
                    verified_work=work_capability,
                    verified_source_profile=source_profile,
                    disposition=action,
                )
                if action == "restart":
                    channel.abort()
                    channel = None
                else:
                    final_runtime = runtime
                    final_channel = channel
                    runtime = None
                    channel = None
            except BaseException as primary:
                _raise_with_cleanup(primary, runtime, channel)
        try:
            evidence, capability = c2.finalize()
        except BaseException as primary:
            _raise_with_cleanup(primary, final_runtime, final_channel)
        if final_runtime is None or final_channel is None:
            raise RuntimeError("target campaign did not retain its authorized epoch")
        return TargetCampaignCompletionV3(
            c2_evidence=evidence,
            c2_capability=capability,
            final_runtime=final_runtime,
            final_channel=final_channel,
        )


class TargetRuntimeContinuationCoordinatorV3:
    """Replace epoch two at +40/+43 and authorize fresh epoch three later."""

    def __init__(
        self,
        *,
        collector_id: str,
        trust_context: AcceptanceAuthorityTrustContextV2,
        launch_request: TargetRuntimeLaunchRequestV2,
        graph: DeepStreamGraphSpec,
        channel_root: Path,
        environment_factory: TargetEnvironmentFactoryV3,
        source_profile_provider: TargetSourceProfileProviderV3,
        transition_journal: SQLiteTargetExecutionTransitionJournalV3,
        authenticated_collector: object,
        runtime_launcher: TargetRuntimeLauncherV3 = (
            launch_and_observe_controller_owned_target_runtime
        ),
        child_grant_hook: Callable[
            [Path, AcceptanceRuntimeGrantV3],
            None,
        ]
        | None = None,
        reviewed_mount_sources: tuple[Path, ...] = (),
        stop_grace_seconds: int = 30,
    ) -> None:
        if (
            type(launch_request) is not TargetRuntimeLaunchRequestV2
            or not channel_root.is_absolute()
            or not callable(environment_factory)
            or not callable(source_profile_provider)
            or not callable(runtime_launcher)
            or type(transition_journal)
            is not SQLiteTargetExecutionTransitionJournalV3
            or authenticated_collector is None
            or type(reviewed_mount_sources) is not tuple
            or any(
                not isinstance(path, Path)
                for path in reviewed_mount_sources
            )
            or type(stop_grace_seconds) is not int
            or not 1 <= stop_grace_seconds <= 60
        ):
            raise ValueError(
                "target continuation configuration is invalid"
            )
        request = TargetRuntimeLaunchRequestV2.model_validate(
            launch_request.model_dump(mode="python")
        )
        self._collector_id = collector_id
        self._trust_context = trust_context
        self._request = request
        self._graph = graph
        self._channel_root = channel_root
        self._environment_factory = environment_factory
        self._source_profile_provider = source_profile_provider
        self._transition_journal = transition_journal
        self._authenticated_collector = authenticated_collector
        self._runtime_launcher = runtime_launcher
        self._child_grant_hook = child_grant_hook
        self._reviewed_mount_sources = frozenset(reviewed_mount_sources)
        self._stop_grace_seconds = stop_grace_seconds
        self._configuration_capability = _issue_campaign_configuration(
            owner=self,
            collector_id=self._collector_id,
            trust_context=self._trust_context,
            requests=(self._request,),
            graph=self._graph,
            channel_root=self._channel_root,
            environment_factory=self._environment_factory,
            source_profile_provider=self._source_profile_provider,
            runtime_launcher=self._runtime_launcher,
            child_grant_hook=self._child_grant_hook,
            authenticated_collector=self._authenticated_collector,
            monotonic=time.monotonic,
            sleep=time.sleep,
            channel_wait_seconds=_MAX_CHANNEL_WAIT_SECONDS,
            reviewed_mount_sources=self._reviewed_mount_sources,
        )
        self._stage = "configured"
        self._campaign: TargetCampaignCompletionV3 | None = None
        self._fault: ScheduledFaultV2 | None = None
        self._previous_execution: ExecutionBindingV2 | None = None
        self._requested: TargetExecutionTransitionEntryV3 | None = None
        self._observed: TargetExecutionTransitionEntryV3 | None = None
        self._runtime: object | None = None
        self._channel: ControllerAcceptanceChannelV3 | None = None
        self._identity: TargetRuntimeObservationV2 | None = None
        self._source_profile: (
            VerifiedTargetSourceProfileAttestationV2 | None
        ) = None
        self._plan: TargetUniqueWorkPlanV2 | None = None
        self._plan_authority: object | None = None
        self._result: object | None = None
        self._channel_receipt: object | None = None
        self._work_capability: object | None = None
        self._work_projection: TargetUniqueWorkProjectionV2 | None = None
        self._directive_published = False
        self._completion: (
            TargetRuntimeContinuationCompletionV3 | None
        ) = None
        self._cleanup_started = False
        self._lock = threading.RLock()

    def __copy__(self) -> None:
        raise TypeError(
            "target continuation coordinator cannot be copied or serialized"
        )

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError(
            "target continuation coordinator cannot be copied or serialized"
        )

    def __reduce_ex__(self, _protocol: int) -> None:
        raise TypeError(
            "target continuation coordinator cannot be copied or serialized"
        )

    def _require_configuration(self) -> None:
        _require_campaign_configuration(
            self._configuration_capability,
            owner=self,
            collector_id=self._collector_id,
            trust_context=self._trust_context,
            requests=(self._request,),
            graph=self._graph,
            channel_root=self._channel_root,
            environment_factory=self._environment_factory,
            source_profile_provider=self._source_profile_provider,
            runtime_launcher=self._runtime_launcher,
            child_grant_hook=self._child_grant_hook,
            authenticated_collector=self._authenticated_collector,
            monotonic=time.monotonic,
            sleep=time.sleep,
            channel_wait_seconds=_MAX_CHANNEL_WAIT_SECONDS,
            reviewed_mount_sources=self._reviewed_mount_sources,
        )

    @staticmethod
    def _recorded_after(
        previous: TargetExecutionTransitionEntryV3 | None,
    ) -> int:
        observed = time.monotonic_ns()
        if previous is not None and observed <= previous.recorded_monotonic_ns:
            raise RuntimeError(
                "execution transition monotonic clock did not advance"
            )
        return observed

    @staticmethod
    def _raise_failures(
        label: str,
        failures: list[BaseException],
    ) -> None:
        if len(failures) == 1:
            raise failures[0]
        if failures:
            raise BaseExceptionGroup(label, failures)

    def request_restart(
        self,
        *,
        campaign: TargetCampaignCompletionV3,
        previous_execution: ExecutionBindingV2,
        fault: ScheduledFaultV2,
        at_offset: float,
    ) -> None:
        """Durably request epoch three, then retire epoch two exactly at +40."""

        with self._lock:
            self._require_configuration()
            if (
                self._stage != "configured"
                or type(campaign) is not TargetCampaignCompletionV3
                or type(previous_execution) is not ExecutionBindingV2
                or type(fault) is not ScheduledFaultV2
                or fault.kind != "runtime_restart"
                or fault.target != "shared-runtime"
                or fault.offset_seconds != 40.0
                or fault.duration_seconds != 3.0
                or fault.expected_degraded != "offline"
                or fault.expected_recovery != "online"
                or at_offset != 40.0
            ):
                raise ValueError(
                    "target continuation requires the exact +40s restart"
                )
            prior = campaign.c2_evidence.epochs[-1]
            checked_previous = ExecutionBindingV2.model_validate(
                previous_execution.model_dump(mode="python")
            )
            request = self._request
            if (
                campaign.c2_evidence.collector_id != self._collector_id
                or request.launch.site_id != campaign.c2_evidence.site_id
                or request.campaign_id != campaign.c2_evidence.campaign_id
                or request.gate != campaign.c2_evidence.gate
                or request.runtime_epoch != prior.runtime_epoch + 1
                or request.runtime_epoch_started_generation
                != request.runtime_epoch
                or request.launch_nonce
                in {epoch.launch_nonce for epoch in campaign.c2_evidence.epochs}
                or checked_previous.launch_nonce != prior.launch_nonce
                or checked_previous.container_id != prior.container_id
            ):
                raise ValueError(
                    "target continuation request differs from base C2"
                )
            common = {
                "schema_version": (
                    "target-execution-transition-entry.v3"
                ),
                "collector_id": self._collector_id,
                "site_id": campaign.c2_evidence.site_id,
                "campaign_id": campaign.c2_evidence.campaign_id,
                "gate": campaign.c2_evidence.gate,
                "runtime_restart_fault_id": fault.fault_id,
                "base_c2_evidence_sha256": (
                    campaign.c2_evidence.evidence_sha256
                ),
                "previous_epoch_sha256": prior.epoch_sha256,
                "previous_execution_binding_sha256": (
                    checked_previous.binding_sha256
                ),
                "previous_runtime_identity_sha256": (
                    prior.runtime_identity_sha256
                ),
                "continuation_launch_request_sha256": (
                    request.request_sha256
                ),
                "continuation_launch_nonce": request.launch_nonce,
                "continuation_runtime_epoch": request.runtime_epoch,
            }
            requested = TargetExecutionTransitionEntryV3(
                **common,
                sequence=1,
                phase="requested",
                previous_entry_sha256="0" * 64,
                recorded_monotonic_ns=self._recorded_after(None),
            )
            self._transition_journal.append(requested)
            self._campaign = campaign
            self._fault = fault
            self._previous_execution = checked_previous
            self._requested = requested
            self._stage = "retiring"
            failures: list[BaseException] = []
            runtime = campaign.final_runtime
            channel = campaign.final_channel
            try:
                identity = runtime.reverify_identity()
                if (
                    identity.identity_sha256
                    != prior.runtime_identity_sha256
                ):
                    raise ValueError(
                        "retiring runtime differs from base C2"
                    )
                runtime.terminate(
                    timeout_seconds=self._stop_grace_seconds
                )
                if (
                    runtime.wait(
                        timeout_seconds=float(self._stop_grace_seconds)
                    )
                    != 0
                ):
                    raise RuntimeError(
                        "retiring runtime did not stop cleanly"
                    )
            except BaseException as primary:
                failures.append(primary)
            for operation in (runtime.cleanup, channel.abort):
                try:
                    operation()
                except BaseException as cleanup:
                    failures.append(cleanup)
            if failures:
                self._stage = "failed"
                self._raise_failures(
                    "target restart retirement and cleanup failed",
                    failures,
                )
            self._stage = "requested"

    def launch_replacement(
        self,
        *,
        at_offset: float,
    ) -> str:
        """Launch fresh epoch three at +43; do not invent V2 observer evidence."""

        with self._lock:
            self._require_configuration()
            if self._stage != "requested" or at_offset != 43.0:
                raise ValueError(
                    "target replacement requires the exact +43s recovery"
                )
            runtime: object | None = None
            channel: ControllerAcceptanceChannelV3 | None = None
            try:
                channel = ControllerAcceptanceChannelV3.create(
                    root=self._channel_root,
                    collector_id=self._collector_id,
                    launch_request=self._request,
                )
                environment = self._environment_factory(
                    self._request,
                    channel.runtime_claim_path,
                )
                if (
                    type(environment)
                    is not TargetRuntimeControllerEnvironmentV2
                ):
                    raise ValueError(
                        "target continuation environment is invalid"
                    )
                _require_exact_channel_mount(
                    environment,
                    channel.runtime_claim_path,
                    reviewed_mount_sources=self._reviewed_mount_sources,
                )
                runtime, observation = self._runtime_launcher(
                    self._request,
                    environment,
                )
                if type(observation) is not TargetRuntimeObservationV2:
                    raise TypeError(
                        "target continuation launcher returned "
                        "invalid observation"
                    )
                identity = observation.identity
                profile = self._source_profile_provider(self._request)
                _require_verified_target_source_profile_attestation(profile)
                plan, plan_authority = derive_target_unique_work_plan(
                    trust_context=self._trust_context,
                    launch_request=self._request,
                    runtime_identity=identity,
                    graph=self._graph,
                )
                grant = channel.publish_grant(
                    runtime_identity=identity,
                    unique_work_plan=plan,
                    verified_source_profile=profile,
                )
                if self._child_grant_hook is not None:
                    self._child_grant_hook(
                        channel.runtime_claim_path,
                        grant,
                    )
            except BaseException as primary:
                self._stage = "failed"
                _raise_with_cleanup(primary, runtime, channel)
            self._runtime = runtime
            self._channel = channel
            self._identity = observation
            self._source_profile = profile
            self._plan = plan
            self._plan_authority = plan_authority
            self._stage = "launched"
            previous = self._previous_execution
            assert previous is not None
            return (
                f"{previous.launch_nonce}.container-"
                f"{identity.container_id[:32]}"
            )

    def record_v2_recovery(
        self,
        acknowledgement_capability: object,
    ) -> None:
        """Bind only the pinned adapter/observer ACK to actual epoch three."""

        with self._lock:
            self._require_configuration()
            if self._stage != "launched":
                raise RuntimeError(
                    "target continuation is not awaiting V2 recovery"
                )
            ack = _consume_authenticated_fault_acknowledgement(
                acknowledgement_capability,
                collector=self._authenticated_collector,
            )
            previous = self._previous_execution
            requested = self._requested
            observation = self._identity
            fault = self._fault
            campaign = self._campaign
            assert previous is not None
            assert requested is not None
            assert observation is not None
            assert fault is not None
            assert campaign is not None
            runtime = self._runtime
            assert runtime is not None
            live_identity = runtime.reverify_identity()
            identity = observation.identity
            if live_identity != identity or runtime.poll() is not None:
                raise RuntimeError(
                    "target continuation runtime changed before V2 recovery"
                )
            compatibility_boot = (
                f"{previous.launch_nonce}.container-"
                f"{identity.container_id[:32]}"
            )
            if (
                ack.collector_id != self._collector_id
                or ack.fault_id != fault.fault_id
                or ack.phase != "recover"
                or ack.commanded_monotonic_offset_seconds != 43.0
                or ack.state != fault.expected_recovery
                or ack.runtime_boot_id != compatibility_boot
                or ack.execution_binding_sha256
                != previous.binding_sha256
            ):
                raise ValueError(
                    "V2 adapter/observer recovery ACK differs from "
                    "the fresh controller runtime"
                )
            observed = TargetExecutionTransitionEntryV3(
                **{
                    field: getattr(requested, field)
                    for field in (
                        "schema_version",
                        "collector_id",
                        "site_id",
                        "campaign_id",
                        "gate",
                        "runtime_restart_fault_id",
                        "base_c2_evidence_sha256",
                        "previous_epoch_sha256",
                        "previous_execution_binding_sha256",
                        "previous_runtime_identity_sha256",
                        "continuation_launch_request_sha256",
                        "continuation_launch_nonce",
                        "continuation_runtime_epoch",
                    )
                },
                sequence=2,
                phase="runtime_observed",
                continuation_execution_binding_sha256=(
                    _execution_binding_from_runtime_identity(
                        identity
                    ).binding_sha256
                ),
                continuation_runtime_identity_sha256=(
                    identity.identity_sha256
                ),
                continuation_runtime_boot_id=identity.runtime_boot_id,
                v2_compatibility_runtime_boot_id=ack.runtime_boot_id,
                previous_entry_sha256=requested.entry_sha256,
                recorded_monotonic_ns=self._recorded_after(requested),
            )
            self._transition_journal.append(observed)
            self._observed = observed
            self._stage = "observed"

    @property
    def active_runtime(self) -> object:
        with self._lock:
            if self._runtime is None or self._stage in {
                "configured",
                "retiring",
                "requested",
                "failed",
                "cleaned",
            }:
                raise RuntimeError(
                    "target continuation runtime is unavailable"
                )
            return self._runtime

    def poll_authorization(
        self,
    ) -> TargetRuntimeContinuationCompletionV3 | None:
        """Poll child work without blocking the canonical V2 collector loop."""

        with self._lock:
            self._require_configuration()
            if self._completion is not None:
                return self._completion
            if self._stage not in {
                "observed",
                "result",
                "directive",
            }:
                if self._stage == "failed":
                    raise RuntimeError(
                        "target continuation previously failed"
                    )
                return None
            runtime = self._runtime
            channel = self._channel
            observation = self._identity
            profile = self._source_profile
            plan_authority = self._plan_authority
            observed = self._observed
            campaign = self._campaign
            previous = self._previous_execution
            fault = self._fault
            assert runtime is not None
            assert channel is not None
            assert observation is not None
            assert profile is not None
            assert plan_authority is not None
            assert observed is not None
            assert campaign is not None
            assert previous is not None
            assert fault is not None
            runtime.reverify_identity()
            if runtime.poll() is not None:
                self._stage = "failed"
                raise RuntimeError(
                    "target continuation runtime exited before authorization"
                )
            if self._result is None:
                try:
                    result, receipt = channel.consume_result()
                except FileNotFoundError:
                    return None
                projection, work_capability = (
                    verify_target_unique_work_projection_value(
                        result.unique_work_projection,
                        plan_authority=plan_authority,
                        native_prewarm=result.native_prewarm,
                    )
                )
                self._result = result
                self._channel_receipt = receipt
                self._work_capability = work_capability
                self._work_projection = projection
                self._stage = "result"
            if not self._directive_published:
                channel.publish_directive(action="authorize")
                self._directive_published = True
                self._stage = "directive"
            try:
                channel.consume_ack()
            except FileNotFoundError:
                return None
            result = self._result
            work_capability = self._work_capability
            channel_receipt = self._channel_receipt
            plan = self._plan
            projection = self._work_projection
            assert result is not None
            assert work_capability is not None
            assert channel_receipt is not None
            assert plan is not None
            assert projection is not None
            runtime_capability = _consume_controller_owned_runtime_for_c2(
                runtime
            )
            authorized = TargetExecutionTransitionEntryV3(
                **{
                    field: getattr(observed, field)
                    for field in (
                        "schema_version",
                        "collector_id",
                        "site_id",
                        "campaign_id",
                        "gate",
                        "runtime_restart_fault_id",
                        "base_c2_evidence_sha256",
                        "previous_epoch_sha256",
                        "previous_execution_binding_sha256",
                        "previous_runtime_identity_sha256",
                        "continuation_launch_request_sha256",
                        "continuation_launch_nonce",
                        "continuation_runtime_epoch",
                        "continuation_execution_binding_sha256",
                        "continuation_runtime_identity_sha256",
                        "continuation_runtime_boot_id",
                        "v2_compatibility_runtime_boot_id",
                    )
                },
                sequence=3,
                phase="authorized",
                source_profile_sha256=profile.verified_binding_sha256,
                native_prewarm_sha256=(
                    result.native_prewarm.projection_sha256
                ),
                unique_work_plan_sha256=plan.plan_sha256,
                unique_work_sha256=projection.projection_sha256,
                completion_sha256=(
                    projection.completed_work_ledger_sha256
                ),
                previous_entry_sha256=observed.entry_sha256,
                recorded_monotonic_ns=self._recorded_after(observed),
            )
            self._transition_journal.append(authorized)
            _journal, journal_capability = (
                self._transition_journal.finalize(self._collector_id)
            )
            evidence, capability = authorize_target_c2_continuation_v3(
                c2_capability=campaign.c2_capability,
                previous_execution=previous,
                runtime_capability=runtime_capability,
                channel_receipt=channel_receipt,
                verified_work=work_capability,
                verified_source_profile=profile,
                transition_journal_capability=journal_capability,
                runtime_restart_fault_id=fault.fault_id,
            )
            completion = TargetRuntimeContinuationCompletionV3(
                evidence=evidence,
                capability=capability,
                final_runtime=runtime,
                final_channel=channel,
            )
            self._completion = completion
            self._stage = "authorized"
            return completion

    def cleanup(
        self,
        campaign: TargetCampaignCompletionV3 | None = None,
    ) -> None:
        """Clean the epoch currently owned by this continuation exactly once."""

        with self._lock:
            if self._cleanup_started:
                return
            if (
                campaign is not None
                and type(campaign) is not TargetCampaignCompletionV3
            ):
                raise TypeError(
                    "target continuation cleanup campaign is invalid"
                )
            if (
                campaign is not None
                and self._campaign is not None
                and campaign is not self._campaign
            ):
                raise ValueError(
                    "target continuation cleanup campaign changed"
                )
            self._cleanup_started = True
            failures: list[BaseException] = []
            owned_runtime = self._runtime
            owned_channel = self._channel
            if self._campaign is None and campaign is not None:
                owned_runtime = campaign.final_runtime
                owned_channel = campaign.final_channel
            if owned_runtime is not None:
                try:
                    owned_runtime.cleanup()
                except BaseException as cleanup:
                    failures.append(cleanup)
            if owned_channel is not None:
                try:
                    owned_channel.abort()
                except BaseException as cleanup:
                    failures.append(cleanup)
            self._stage = "cleaned"
            self._raise_failures(
                "target continuation cleanup failed",
                failures,
            )


def _advance_target_runtime_restart_v3(
    *,
    continuation: TargetRuntimeContinuationCoordinatorV3,
    collector: object,
    campaign: TargetCampaignCompletionV3,
    previous_execution: ExecutionBindingV2,
    fault: ScheduledFaultV2,
    phase: str,
    at_offset: float,
) -> object | None:
    """Execute the exact external-observer handoff at +40/+43."""

    command_fault = getattr(collector, "command_fault", None)
    if (
        type(continuation) is not TargetRuntimeContinuationCoordinatorV3
        or type(campaign) is not TargetCampaignCompletionV3
        or type(previous_execution) is not ExecutionBindingV2
        or type(fault) is not ScheduledFaultV2
        or not callable(command_fault)
    ):
        raise TypeError("target runtime restart handoff inputs are invalid")
    if phase == "inject" and at_offset == 40.0:
        continuation.request_restart(
            campaign=campaign,
            previous_execution=previous_execution,
            fault=fault,
            at_offset=at_offset,
        )
        command_fault(
            fault_id=fault.fault_id,
            phase=phase,
            at_offset=at_offset,
        )
        return None
    if phase != "recover" or at_offset != 43.0:
        raise ValueError(
            "target runtime restart handoff requires exact +40/+43 phases"
        )
    continuation.launch_replacement(at_offset=at_offset)
    runtime = continuation.active_runtime
    identity_before = runtime.reverify_identity()
    if runtime.poll() is not None:
        raise RuntimeError(
            "fresh target continuation runtime exited before recovery"
        )
    acknowledgement = command_fault(
        fault_id=fault.fault_id,
        phase=phase,
        at_offset=at_offset,
    )
    continuation.record_v2_recovery(acknowledgement)
    identity_after = runtime.reverify_identity()
    if identity_after != identity_before or runtime.poll() is not None:
        raise RuntimeError(
            "fresh target continuation runtime changed during recovery"
        )
    return runtime


def _require_distinct_authority_files(
    paths: tuple[tuple[str, Path], ...],
) -> None:
    """Reject lexical and existing inode aliases among controller databases."""

    if (
        type(paths) is not tuple
        or len(paths) < 2
        or any(
            type(label) is not str
            or not label
            or not isinstance(path, Path)
            or not path.is_absolute()
            for label, path in paths
        )
    ):
        raise ValueError("acceptance authority file paths are invalid")
    resolved: dict[Path, str] = {}
    identities: dict[tuple[int, int], str] = {}
    for label, path in paths:
        try:
            parent = path.parent.resolve(strict=True)
            candidate = parent / path.name
            metadata = path.lstat()
        except FileNotFoundError:
            metadata = None
            candidate = path.parent.resolve(strict=True) / path.name
        except OSError as exc:
            raise ValueError(
                f"acceptance {label} authority path is unavailable"
            ) from exc
        if (
            candidate != path
            or candidate in resolved
            or (
                metadata is not None
                and (
                    stat.S_ISLNK(metadata.st_mode)
                    or not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                )
            )
        ):
            raise ValueError(
                "acceptance authority files must be lexically distinct "
                "regular files"
            )
        resolved[candidate] = label
        if metadata is not None:
            identity = (metadata.st_dev, metadata.st_ino)
            if identity in identities:
                raise ValueError(
                    "acceptance authority files contain an inode alias"
                )
            identities[identity] = label


__all__ = (
    "TargetCampaignCompletionV3",
    "TargetCampaignCoordinatorV3",
    "TargetEnvironmentFactoryV3",
    "TargetRuntimeContinuationCompletionV3",
    "TargetRuntimeContinuationCoordinatorV3",
    "TargetRuntimeLauncherV3",
    "TargetSourceProfileProviderV3",
)
