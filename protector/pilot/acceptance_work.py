"""Centrally derived unique-work authority for target capacity acceptance.

Serializable plans and projections are evidence only.  A process-local plan
authority is minted from the already verified acceptance trust context, and a
separate private capability is minted only after the controller captures and
recomputes a complete runtime ledger.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
from decimal import Decimal
from fractions import Fraction
from pathlib import Path
from typing import Annotated, Literal, TypeVar

from pydantic import ConfigDict, Field, field_validator, model_validator

from protector.pilot.acceptance import AnalyticName
from protector.pilot.acceptance_authority import (
    AcceptanceAuthorityTrustContextV2,
    _require_authority_trust_context,
)
from protector.pilot.acceptance_target import (
    TargetNativePrewarmProjectionV2,
    TargetRuntimeIdentityV2,
    TargetRuntimeLaunchRequestV2,
)
from protector.pilot.acceptance_trust import (
    canonical_json_bytes,
    load_canonical_json_bytes,
)
from protector.pilot.config import FrozenModel
from protector.pilot.runtime.deepstream import DeepStreamGraphSpec

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
PositiveInt64 = Annotated[int, Field(ge=1, le=2**63 - 1)]
NonNegativeInt64 = Annotated[int, Field(ge=0, le=2**63 - 1)]
MAX_TARGET_UNIQUE_WORK_SLOTS = 100_000
MAX_TARGET_UNIQUE_WORK_PROJECTION_BYTES = 32 * 1024 * 1024
TARGET_WORK_MEASUREMENT_DURATION_NS = 60_000_000_000
_PROJECTION_NAME_MAX_BYTES = 128
_M = TypeVar("_M", bound=FrozenModel)


class _StrictFrozenModel(FrozenModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )


def _strict_exact(value: object, model: type[_M], label: str) -> _M:
    if type(value) is not model:
        raise TypeError(f"{label} must use the exact typed contract")
    return model.model_validate(value.model_dump(mode="python"))


def _reduced_fraction(numerator: int, denominator: int, *, label: str) -> Fraction:
    if (
        type(numerator) is not int
        or type(denominator) is not int
        or numerator < 0
        or denominator <= 0
    ):
        raise ValueError(f"{label} fraction is invalid")
    reduced = Fraction(numerator, denominator)
    if reduced.numerator != numerator or reduced.denominator != denominator:
        raise ValueError(f"{label} fraction must be reduced")
    return reduced


def _ceil_fraction(value: Fraction) -> int:
    return -(-value.numerator // value.denominator)


def _work_id(
    *,
    manifest_sha256: str,
    launch_request_sha256: str,
    runtime_identity_sha256: str,
    graph_contract_sha256: str,
    runtime_epoch: int,
    runtime_epoch_started_generation: int,
    camera_id: str,
    source_index: int,
    module: str,
    ordinal: int,
    slot_index: int,
    scheduled_offset_ns: int,
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "schema_version": "target-unique-work-id.v2",
                "manifest_sha256": manifest_sha256,
                "launch_request_sha256": launch_request_sha256,
                "runtime_identity_sha256": runtime_identity_sha256,
                "graph_contract_sha256": graph_contract_sha256,
                "runtime_epoch": runtime_epoch,
                "runtime_epoch_started_generation": runtime_epoch_started_generation,
                "camera_id": camera_id,
                "source_index": source_index,
                "module": module,
                "ordinal": ordinal,
                "slot_index": slot_index,
                "scheduled_offset_ns": scheduled_offset_ns,
            }
        )
    ).hexdigest()


class TargetUniqueWorkSlotV2(_StrictFrozenModel):
    work_id: Digest
    slot_index: Annotated[int, Field(ge=0, lt=MAX_TARGET_UNIQUE_WORK_SLOTS)]
    scheduled_offset_ns: Annotated[
        int,
        Field(ge=0, lt=TARGET_WORK_MEASUREMENT_DURATION_NS),
    ]
    camera_id: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"),
    ]
    source_index: Annotated[int, Field(ge=0, lt=20)]
    module: AnalyticName
    ordinal: Annotated[int, Field(ge=0, lt=MAX_TARGET_UNIQUE_WORK_SLOTS)]


def _reparse_slots(value: object) -> tuple[TargetUniqueWorkSlotV2, ...]:
    if type(value) not in {tuple, list}:
        raise TypeError("unique-work slots must be one finite sequence")
    if not 1 <= len(value) <= MAX_TARGET_UNIQUE_WORK_SLOTS:
        raise ValueError("unique-work slots exceed their finite bound")
    return tuple(TargetUniqueWorkSlotV2.model_validate(item) for item in value)


class TargetUniqueWorkPlanV2(_StrictFrozenModel):
    schema_version: Literal["target-unique-work-plan.v2"]
    manifest_sha256: Digest
    launch_request_sha256: Digest
    runtime_identity_sha256: Digest
    graph_contract_sha256: Digest
    site_id: Annotated[str, Field(min_length=1, max_length=128)]
    campaign_id: Annotated[str, Field(min_length=1, max_length=128)]
    launch_nonce: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    runtime_epoch: PositiveInt64
    runtime_epoch_started_generation: PositiveInt64
    measurement_duration_ns: Literal[TARGET_WORK_MEASUREMENT_DURATION_NS]
    required_work_numerator: PositiveInt64
    required_work_denominator: PositiveInt64
    stress_numerator: Literal[5] = 5
    stress_denominator: Literal[4] = 4
    offered_work_units: Annotated[
        int,
        Field(ge=1, le=MAX_TARGET_UNIQUE_WORK_SLOTS),
    ]
    enabled_shared_graph_modules: Annotated[
        tuple[AnalyticName, ...],
        Field(min_length=1, max_length=16),
    ]
    slots: Annotated[
        tuple[TargetUniqueWorkSlotV2, ...],
        Field(min_length=1, max_length=MAX_TARGET_UNIQUE_WORK_SLOTS),
    ]
    authorizing: Literal[False] = False

    @field_validator("enabled_shared_graph_modules", mode="before")
    @classmethod
    def enabled_modules_are_one_exact_tuple(cls, value: object) -> object:
        if type(value) not in {tuple, list}:
            raise TypeError("enabled shared graph modules must be one finite sequence")
        return tuple(value)

    @field_validator("slots", mode="before")
    @classmethod
    def slots_are_strictly_reparsed(
        cls,
        value: object,
    ) -> tuple[TargetUniqueWorkSlotV2, ...]:
        return _reparse_slots(value)

    @model_validator(mode="after")
    def schedule_is_exact_bounded_and_self_consistent(self) -> TargetUniqueWorkPlanV2:
        required = _reduced_fraction(
            self.required_work_numerator,
            self.required_work_denominator,
            label="required work",
        )
        if len(self.slots) != self.offered_work_units:
            raise ValueError("offered work differs from the finite slot schedule")
        if len(set(self.enabled_shared_graph_modules)) != len(self.enabled_shared_graph_modules):
            raise ValueError("enabled shared graph modules must be unique")
        if tuple(slot.slot_index for slot in self.slots) != tuple(range(self.offered_work_units)):
            raise ValueError("unique-work slot indices must be exact and contiguous")
        if len({slot.work_id for slot in self.slots}) != self.offered_work_units:
            raise ValueError("unique-work identifiers must be unique")
        if any(slot.module not in self.enabled_shared_graph_modules for slot in self.slots):
            raise ValueError("unique work references a disabled shared graph module")
        if any(
            current.scheduled_offset_ns > following.scheduled_offset_ns
            for current, following in zip(self.slots, self.slots[1:], strict=False)
        ):
            raise ValueError("unique-work slots must use a monotonic schedule")
        ordinals: dict[tuple[str, int, str], list[int]] = {}
        for slot in self.slots:
            expected = _work_id(
                manifest_sha256=self.manifest_sha256,
                launch_request_sha256=self.launch_request_sha256,
                runtime_identity_sha256=self.runtime_identity_sha256,
                graph_contract_sha256=self.graph_contract_sha256,
                runtime_epoch=self.runtime_epoch,
                runtime_epoch_started_generation=self.runtime_epoch_started_generation,
                camera_id=slot.camera_id,
                source_index=slot.source_index,
                module=slot.module,
                ordinal=slot.ordinal,
                slot_index=slot.slot_index,
                scheduled_offset_ns=slot.scheduled_offset_ns,
            )
            if not hmac.compare_digest(slot.work_id, expected):
                raise ValueError("unique-work identifier differs from its exact slot")
            ordinals.setdefault(
                (slot.camera_id, slot.source_index, slot.module),
                [],
            ).append(slot.ordinal)
        if any(values != list(range(len(values))) for values in ordinals.values()):
            raise ValueError("camera/module unique-work ordinals must be contiguous")
        if Fraction(self.offered_work_units, 1) < required * Fraction(5, 4):
            raise ValueError("unique-work schedule lacks 25 percent offered headroom")
        return self

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self)

    @property
    def plan_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()


class TargetUniqueWorkCompletionV2(_StrictFrozenModel):
    work_id: Digest
    slot_index: Annotated[int, Field(ge=0, lt=MAX_TARGET_UNIQUE_WORK_SLOTS)]
    completed_at_monotonic_ns: PositiveInt64
    camera_id: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"),
    ]
    source_index: Annotated[int, Field(ge=0, lt=20)]
    module: AnalyticName
    detection_count: Annotated[int, Field(ge=0, le=1_000_000)]


def _reparse_completions(
    value: object,
) -> tuple[TargetUniqueWorkCompletionV2, ...]:
    if type(value) not in {tuple, list}:
        raise TypeError("unique-work completions must be one finite sequence")
    if len(value) > MAX_TARGET_UNIQUE_WORK_SLOTS:
        raise ValueError("unique-work completions exceed their finite bound")
    return tuple(TargetUniqueWorkCompletionV2.model_validate(item) for item in value)


def completed_work_ledger_sha256(
    completions: tuple[TargetUniqueWorkCompletionV2, ...],
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "schema_version": "target-unique-work-completion-ledger.v2",
                "completions": [item.model_dump(mode="json") for item in completions],
            }
        )
    ).hexdigest()


class TargetUniqueWorkProjectionV2(_StrictFrozenModel):
    schema_version: Literal["target-unique-work-projection.v2"]
    plan_sha256: Digest
    launch_request_sha256: Digest
    runtime_identity_sha256: Digest
    native_prewarm_projection_sha256: Digest
    measurement_started_monotonic_ns: PositiveInt64
    measurement_completed_monotonic_ns: PositiveInt64
    offered_work_units: Annotated[
        int,
        Field(ge=1, le=MAX_TARGET_UNIQUE_WORK_SLOTS),
    ]
    completed_unique_work_units: Annotated[
        int,
        Field(ge=0, le=MAX_TARGET_UNIQUE_WORK_SLOTS),
    ]
    required_work_numerator: PositiveInt64
    required_work_denominator: PositiveInt64
    effective_rate_numerator: NonNegativeInt64
    effective_rate_denominator: PositiveInt64
    headroom_numerator: Annotated[int, Field(ge=-(2**63), le=2**63 - 1)]
    headroom_denominator: PositiveInt64
    completed_work_ledger_sha256: Digest
    completions: Annotated[
        tuple[TargetUniqueWorkCompletionV2, ...],
        Field(max_length=MAX_TARGET_UNIQUE_WORK_SLOTS),
    ]
    authorizing: Literal[False] = False

    @field_validator("completions", mode="before")
    @classmethod
    def completions_are_strictly_reparsed(
        cls,
        value: object,
    ) -> tuple[TargetUniqueWorkCompletionV2, ...]:
        return _reparse_completions(value)

    @model_validator(mode="after")
    def public_projection_is_canonical_but_non_authorizing(
        self,
    ) -> TargetUniqueWorkProjectionV2:
        if self.measurement_completed_monotonic_ns <= self.measurement_started_monotonic_ns:
            raise ValueError("unique-work measurement interval is invalid")
        if (
            len(self.completions) != self.completed_unique_work_units
            or self.completed_unique_work_units > self.offered_work_units
            or len({item.work_id for item in self.completions}) != len(self.completions)
            or tuple(item.slot_index for item in self.completions)
            != tuple(range(len(self.completions)))
        ):
            raise ValueError("unique-work completion accounting is invalid")
        _reduced_fraction(
            self.required_work_numerator,
            self.required_work_denominator,
            label="required work",
        )
        _reduced_fraction(
            self.effective_rate_numerator,
            self.effective_rate_denominator,
            label="effective rate",
        )
        _reduced_fraction(
            abs(self.headroom_numerator),
            self.headroom_denominator,
            label="headroom",
        )
        if self.completed_work_ledger_sha256 != completed_work_ledger_sha256(self.completions):
            raise ValueError("completed unique-work ledger digest differs")
        if any(
            current.completed_at_monotonic_ns > following.completed_at_monotonic_ns
            for current, following in zip(
                self.completions,
                self.completions[1:],
                strict=False,
            )
        ):
            raise ValueError("unique-work completion times must be monotonic")
        return self

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self)

    @property
    def projection_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()


def _module_bindings_sha256(context: AcceptanceAuthorityTrustContextV2) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            [item.model_dump(mode="json") for item in context.trust.manifest.modules]
        )
    ).hexdigest()


def _trust_binding_sha256(context: AcceptanceAuthorityTrustContextV2) -> str:
    return hashlib.sha256(canonical_json_bytes(context.binding)).hexdigest()


def _launch_without_historical_throughput(
    request: TargetRuntimeLaunchRequestV2,
) -> dict[str, object]:
    return request.launch.model_dump(
        mode="python",
        exclude={
            "required_throughput_hz",
            "measured_effective_throughput_hz",
        },
    )


def _graph_contract(
    graph: DeepStreamGraphSpec,
) -> tuple[DeepStreamGraphSpec, str, tuple[AnalyticName, ...]]:
    if type(graph) is not DeepStreamGraphSpec:
        raise TypeError("unique-work derivation requires the exact shared graph contract")
    checked = DeepStreamGraphSpec.model_validate(graph.model_dump(mode="python"))
    checked.validate()
    enabled: list[AnalyticName] = []
    if (
        checked.primary_inference_count == 1
        and checked.tracker_count == 1
        and checked.analytics_count == 1
        and checked.metadata_only_publication
    ):
        enabled.append("person")
    # The current reviewed graph contract deliberately starts optional branches
    # behind closed valves.  They become schedulable only after that graph
    # contract grows an independently reviewed enabled-branch representation.
    return (
        checked,
        hashlib.sha256(canonical_json_bytes(checked)).hexdigest(),
        tuple(enabled),
    )


def _make_plan_authority_tools():
    token = object()
    key = secrets.token_bytes(32)

    class _TargetUniqueWorkPlanAuthority:
        __slots__ = ("__context", "__plan_bytes", "__receipt")

        def __init__(
            self,
            *,
            issuer: object,
            context: AcceptanceAuthorityTrustContextV2,
            plan: TargetUniqueWorkPlanV2,
        ) -> None:
            if issuer is not token:
                raise TypeError("unique-work plan authority requires the verified issuer")
            self.__context = context
            self.__plan_bytes = plan.canonical_bytes
            self.__receipt = hmac.digest(
                key,
                context._context_receipt + self.__plan_bytes,
                "sha256",
            )

        def __copy__(self):
            raise TypeError("unique-work plan capability cannot be copied or serialized")

        def __deepcopy__(self, _memo: object):
            raise TypeError("unique-work plan capability cannot be copied or serialized")

        def __reduce_ex__(self, _protocol: int):
            raise TypeError("unique-work plan capability cannot be copied or serialized")

    def issue(
        context: AcceptanceAuthorityTrustContextV2,
        plan: TargetUniqueWorkPlanV2,
    ) -> object:
        checked = _require_authority_trust_context(context)
        return _TargetUniqueWorkPlanAuthority(
            issuer=token,
            context=checked,
            plan=plan,
        )

    def require(
        candidate: object,
    ) -> tuple[
        AcceptanceAuthorityTrustContextV2,
        TargetUniqueWorkPlanV2,
    ]:
        if type(candidate) is not _TargetUniqueWorkPlanAuthority:
            raise TypeError("verified unique-work plan capability is required")
        context = _require_authority_trust_context(
            candidate._TargetUniqueWorkPlanAuthority__context
        )
        plan_bytes = candidate._TargetUniqueWorkPlanAuthority__plan_bytes
        receipt = candidate._TargetUniqueWorkPlanAuthority__receipt
        expected = hmac.digest(
            key,
            context._context_receipt + plan_bytes,
            "sha256",
        )
        if (
            type(plan_bytes) is not bytes
            or type(receipt) is not bytes
            or not hmac.compare_digest(receipt, expected)
        ):
            raise ValueError("unique-work plan capability provenance is invalid")
        plan = load_canonical_json_bytes(
            plan_bytes,
            TargetUniqueWorkPlanV2,
            max_bytes=MAX_TARGET_UNIQUE_WORK_PROJECTION_BYTES,
            label="unique-work plan",
        )
        return context, plan

    return issue, require


_issue_plan_authority, _require_plan_authority = _make_plan_authority_tools()


def _make_verified_work_tools():
    token = object()
    key = secrets.token_bytes(32)

    class _VerifiedTargetWorkCapability:
        __slots__ = ("__plan_sha256", "__projection_sha256", "__receipt")

        def __init__(
            self,
            *,
            issuer: object,
            plan: TargetUniqueWorkPlanV2,
            projection: TargetUniqueWorkProjectionV2,
        ) -> None:
            if issuer is not token:
                raise TypeError("verified target work requires the controller verifier")
            self.__plan_sha256 = plan.plan_sha256
            self.__projection_sha256 = projection.projection_sha256
            self.__receipt = hmac.digest(
                key,
                (self.__plan_sha256 + self.__projection_sha256).encode("ascii"),
                "sha256",
            )

        def __copy__(self):
            raise TypeError("verified target-work capability cannot be copied or serialized")

        def __deepcopy__(self, _memo: object):
            raise TypeError("verified target-work capability cannot be copied or serialized")

        def __reduce_ex__(self, _protocol: int):
            raise TypeError("verified target-work capability cannot be copied or serialized")

    def issue(
        plan: TargetUniqueWorkPlanV2,
        projection: TargetUniqueWorkProjectionV2,
    ) -> object:
        return _VerifiedTargetWorkCapability(
            issuer=token,
            plan=plan,
            projection=projection,
        )

    return issue


_issue_verified_work = _make_verified_work_tools()


def derive_target_unique_work_plan(
    *,
    trust_context: AcceptanceAuthorityTrustContextV2,
    launch_request: TargetRuntimeLaunchRequestV2,
    runtime_identity: TargetRuntimeIdentityV2,
    graph: DeepStreamGraphSpec,
) -> tuple[TargetUniqueWorkPlanV2, object]:
    """Derive the only admissible 60-second stress schedule from trusted inputs."""

    context = _require_authority_trust_context(trust_context)
    request = _strict_exact(
        launch_request,
        TargetRuntimeLaunchRequestV2,
        "target launch request",
    )
    identity = _strict_exact(
        runtime_identity,
        TargetRuntimeIdentityV2,
        "target runtime identity",
    )
    manifest = context.trust.manifest
    if (
        request.manifest_sha256 != manifest.manifest_sha256
        or request.acceptance_trust_binding_sha256 != _trust_binding_sha256(context)
        or request.module_gate_bindings_sha256 != _module_bindings_sha256(context)
        or request.campaign_id != context.configured_campaign_id
        or request.gate != context.configured_gate
        or request.launch.site_id != manifest.site_id
        or _launch_without_historical_throughput(request)
        != _launch_without_historical_throughput(
            request.model_copy(update={"launch": manifest.launch})
        )
        or identity.launch_request != request
        or identity.runtime_epoch != request.runtime_epoch
        or identity.runtime_epoch_started_generation != request.runtime_epoch_started_generation
    ):
        raise ValueError("target work launch/runtime differs from the verified manifest")
    if tuple((item.camera_id, item.source_index) for item in request.source_bindings) != tuple(
        (source.camera_id, source.source_index) for source in manifest.sources
    ):
        raise ValueError("target work source bindings differ from the verified manifest")

    checked_graph, graph_sha256, enabled_modules = _graph_contract(graph)
    if tuple(
        (
            source.camera_id,
            source.source_id,
            source.codec,
            source.width,
            source.height,
            source.fps,
            source.bitrate_kbps,
        )
        for source in checked_graph.sources
    ) != tuple(
        (
            source.camera_id,
            source.source_index,
            source.codec,
            source.width,
            source.height,
            source.fps,
            source.bitrate_kbps,
        )
        for source in manifest.sources
    ):
        raise ValueError("shared graph sources differ from the verified manifest")

    dispositions = {item.module: item for item in manifest.modules}
    raw_slots: list[tuple[int, int, int, str, int]] = []
    required_work = Fraction(0, 1)
    module_order = {item.module: index for index, item in enumerate(manifest.modules)}
    for source in manifest.sources:
        for module, rate in source.analytics_hz.items():
            rate_fraction = Fraction(Decimal(str(rate)))
            if rate_fraction <= 0:
                continue
            disposition = dispositions[module]
            if disposition.mode == "disabled":
                raise ValueError(f"positive scheduled module {module} is disabled by the manifest")
            if module not in enabled_modules:
                raise ValueError(
                    f"positive scheduled module {module} has no enabled real shared graph branch"
                )
            pair_required = rate_fraction * 60
            required_work += pair_required
            pair_offered = _ceil_fraction(pair_required * Fraction(5, 4))
            for ordinal in range(pair_offered):
                offset_ns = ordinal * TARGET_WORK_MEASUREMENT_DURATION_NS // pair_offered
                raw_slots.append(
                    (
                        offset_ns,
                        source.source_index,
                        module_order[module],
                        module,
                        ordinal,
                    )
                )
    if required_work <= 0 or not raw_slots:
        raise ValueError("verified manifest contains no positive enabled shared work")
    if len(raw_slots) > MAX_TARGET_UNIQUE_WORK_SLOTS:
        raise ValueError("derived unique-work schedule exceeds its finite bound")

    source_by_index = {source.source_index: source for source in manifest.sources}
    slots: list[TargetUniqueWorkSlotV2] = []
    for slot_index, (
        offset_ns,
        source_index,
        _module_order,
        module,
        ordinal,
    ) in enumerate(sorted(raw_slots)):
        source = source_by_index[source_index]
        work_id = _work_id(
            manifest_sha256=manifest.manifest_sha256,
            launch_request_sha256=request.request_sha256,
            runtime_identity_sha256=identity.identity_sha256,
            graph_contract_sha256=graph_sha256,
            runtime_epoch=request.runtime_epoch,
            runtime_epoch_started_generation=request.runtime_epoch_started_generation,
            camera_id=source.camera_id,
            source_index=source_index,
            module=module,
            ordinal=ordinal,
            slot_index=slot_index,
            scheduled_offset_ns=offset_ns,
        )
        slots.append(
            TargetUniqueWorkSlotV2(
                work_id=work_id,
                slot_index=slot_index,
                scheduled_offset_ns=offset_ns,
                camera_id=source.camera_id,
                source_index=source_index,
                module=module,
                ordinal=ordinal,
            )
        )
    plan = TargetUniqueWorkPlanV2(
        schema_version="target-unique-work-plan.v2",
        manifest_sha256=manifest.manifest_sha256,
        launch_request_sha256=request.request_sha256,
        runtime_identity_sha256=identity.identity_sha256,
        graph_contract_sha256=graph_sha256,
        site_id=manifest.site_id,
        campaign_id=request.campaign_id,
        launch_nonce=request.launch_nonce,
        runtime_epoch=request.runtime_epoch,
        runtime_epoch_started_generation=request.runtime_epoch_started_generation,
        measurement_duration_ns=TARGET_WORK_MEASUREMENT_DURATION_NS,
        required_work_numerator=required_work.numerator,
        required_work_denominator=required_work.denominator,
        offered_work_units=len(slots),
        enabled_shared_graph_modules=enabled_modules,
        slots=tuple(slots),
    )
    return plan, _issue_plan_authority(context, plan)


def _open_parent(path: Path) -> tuple[int, str]:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or not path.name
        or len(path.name.encode()) > _PROJECTION_NAME_MAX_BYTES
        or any(
            character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
            for character in path.name
        )
        or path.name[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        or path.parent.resolve(strict=True) != path.parent
    ):
        raise ValueError("unique-work projection path is not canonical")
    descriptor = os.open(
        path.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("unique-work projection parent is not a directory")
    except BaseException as primary:
        try:
            os.close(descriptor)
        except BaseException as cleanup:
            raise BaseExceptionGroup(
                "projection parent inspection and cleanup failed",
                [primary, cleanup],
            ) from primary
        raise
    return descriptor, path.name


def _close_all(
    descriptors: tuple[int | None, ...],
    failures: list[BaseException],
) -> None:
    for descriptor in descriptors:
        if descriptor is None:
            continue
        try:
            os.close(descriptor)
        except BaseException as exc:
            failures.append(exc)


def _raise_failures(label: str, failures: list[BaseException]) -> None:
    if len(failures) == 1:
        raise failures[0]
    if failures:
        raise BaseExceptionGroup(label, failures)


def _read_projection_once(path: Path) -> bytes:
    parent, name = _open_parent(path)
    descriptor: int | None = None
    payload: bytes | None = None
    failures: list[BaseException] = []
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 1 <= before.st_size <= MAX_TARGET_UNIQUE_WORK_PROJECTION_BYTES
        ):
            raise ValueError("unique-work projection must be one private bounded regular file")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise ValueError("unique-work projection changed while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("unique-work projection exceeds its captured size")
        after = os.fstat(descriptor)
        leaf = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (after.st_dev, after.st_ino, after.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ) or (leaf.st_dev, leaf.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("unique-work projection was replaced while reading")
        payload = b"".join(chunks)
    except (FileNotFoundError, IsADirectoryError, OSError):
        failures.append(ValueError("unique-work projection is not a readable regular file"))
    except BaseException as primary:
        failures.append(primary)
    finally:
        _close_all((descriptor, parent), failures)
    _raise_failures("unique-work projection capture or cleanup failed", failures)
    if payload is None:
        raise AssertionError("unique-work projection capture returned no bytes")
    return payload


def verify_target_unique_work_projection(
    path: Path,
    *,
    plan_authority: object,
    native_prewarm: TargetNativePrewarmProjectionV2,
) -> tuple[TargetUniqueWorkProjectionV2, object]:
    """Single-capture, reparse, and independently recompute runtime work."""

    context, plan = _require_plan_authority(plan_authority)
    prewarm = _strict_exact(
        native_prewarm,
        TargetNativePrewarmProjectionV2,
        "native prewarm projection",
    )
    if (
        prewarm.launch_request_sha256 != plan.launch_request_sha256
        or prewarm.runtime_identity_sha256 != plan.runtime_identity_sha256
        or prewarm.site_id != plan.site_id
        or prewarm.campaign_id != plan.campaign_id
        or prewarm.launch_nonce != plan.launch_nonce
        or prewarm.runtime_epoch != plan.runtime_epoch
        or prewarm.runtime_epoch_started_generation != plan.runtime_epoch_started_generation
        or context.trust.manifest.manifest_sha256 != plan.manifest_sha256
    ):
        raise ValueError("native prewarm differs from the verified unique-work plan")
    payload = _read_projection_once(path)
    projection = load_canonical_json_bytes(
        payload,
        TargetUniqueWorkProjectionV2,
        max_bytes=MAX_TARGET_UNIQUE_WORK_PROJECTION_BYTES,
        label="target unique-work projection",
    )
    if (
        projection.plan_sha256 != plan.plan_sha256
        or projection.launch_request_sha256 != plan.launch_request_sha256
        or projection.runtime_identity_sha256 != plan.runtime_identity_sha256
        or projection.native_prewarm_projection_sha256 != prewarm.projection_sha256
        or projection.measurement_started_monotonic_ns < prewarm.ready_at_monotonic_ns
        or projection.measurement_completed_monotonic_ns
        - projection.measurement_started_monotonic_ns
        != plan.measurement_duration_ns
        or projection.offered_work_units != plan.offered_work_units
        or projection.completed_unique_work_units != plan.offered_work_units
        or projection.required_work_numerator != plan.required_work_numerator
        or projection.required_work_denominator != plan.required_work_denominator
        or len(projection.completions) != len(plan.slots)
    ):
        raise ValueError("runtime unique-work projection is incomplete or differs from plan")
    for slot, completion in zip(plan.slots, projection.completions, strict=True):
        if (
            completion.work_id != slot.work_id
            or completion.slot_index != slot.slot_index
            or completion.camera_id != slot.camera_id
            or completion.source_index != slot.source_index
            or completion.module != slot.module
            or completion.completed_at_monotonic_ns
            < (projection.measurement_started_monotonic_ns + slot.scheduled_offset_ns)
            or completion.completed_at_monotonic_ns > projection.measurement_completed_monotonic_ns
        ):
            raise ValueError("runtime completion differs from its planned unique-work slot")
    effective_rate = Fraction(
        projection.completed_unique_work_units * 1_000_000_000,
        plan.measurement_duration_ns,
    )
    required_work = Fraction(
        plan.required_work_numerator,
        plan.required_work_denominator,
    )
    headroom = Fraction(projection.completed_unique_work_units, 1) / required_work - 1
    if (
        (projection.effective_rate_numerator, projection.effective_rate_denominator)
        != (effective_rate.numerator, effective_rate.denominator)
        or (projection.headroom_numerator, projection.headroom_denominator)
        != (headroom.numerator, headroom.denominator)
        or headroom < Fraction(1, 4)
    ):
        raise ValueError("runtime effective rate or 25 percent headroom differs")
    capability = _issue_verified_work(plan, projection)
    return projection, capability


__all__ = (
    "MAX_TARGET_UNIQUE_WORK_PROJECTION_BYTES",
    "MAX_TARGET_UNIQUE_WORK_SLOTS",
    "TARGET_WORK_MEASUREMENT_DURATION_NS",
    "TargetUniqueWorkCompletionV2",
    "TargetUniqueWorkPlanV2",
    "TargetUniqueWorkProjectionV2",
    "TargetUniqueWorkSlotV2",
    "completed_work_ledger_sha256",
    "derive_target_unique_work_plan",
    "verify_target_unique_work_projection",
)
