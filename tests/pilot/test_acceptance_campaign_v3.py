from __future__ import annotations

import argparse
import hashlib
import itertools
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.pilot.replay_20 as replay
from protector.pilot import acceptance_target_controller
from protector.pilot.acceptance import AcceptanceRunRecordV2
from protector.pilot.acceptance_c2 import (
    TargetC2EvidenceV3,
    TargetEpochEvidenceV3,
)
from protector.pilot.acceptance_campaign import (
    TargetCampaignCompletionV3,
    TargetCampaignCoordinatorV3,
    _require_exact_channel_mount,
)
from protector.pilot.acceptance_proof import (
    AcceptanceFinalEnvelopeV2,
    TargetRunAttestationV2,
)
from protector.pilot.acceptance_source_profile import (
    capture_verified_target_source_profile_attestation,
)
from protector.pilot.acceptance_target import (
    TargetNativePrewarmProjectionV2,
    TargetRuntimeIdentityV2,
    TargetRuntimeLaunchRequestV2,
)
from protector.pilot.acceptance_target_controller import (
    TargetRuntimeControllerEnvironmentV2,
    _ControllerOwnedDockerRuntime,
    launch_and_observe_controller_owned_target_runtime,
)
from protector.pilot.acceptance_trust import canonical_json_bytes
from protector.pilot.runtime.source_profile import (
    Ed25519SourceProfileProofSigner,
    SourceProfileExpectation,
)
from protector.pilot.runtime.container_runner import (
    DockerRuntimeProcess,
    _issue_docker_runtime_process,
)
from protector.pilot.runtime.work_authority import (
    TargetUniqueWorkRuntimeLedger,
)
from tests.pilot.test_acceptance_source_profile import (
    PROOF_KEY_ID,
    PROOF_SEED,
    _attestation,
)
from tests.pilot.test_acceptance_work import _target_inputs
from tests.pilot.test_work_authority import _record_all


class _Runtime:
    def __init__(self, events: list[str], *, cleanup_failure: bool = False) -> None:
        self.events = events
        self.cleanup_failure = cleanup_failure

    def cleanup(self) -> None:
        self.events.append("cleanup")
        if self.cleanup_failure:
            raise RuntimeError("hostile cleanup failure")


class _Channel:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def abort(self) -> None:
        self.events.append("channel-cleanup")


def _campaign(
    events: list[str],
    *,
    cleanup_failure: bool = False,
) -> TargetCampaignCompletionV3:
    epochs = tuple(
        TargetEpochEvidenceV3.model_construct(
            schema_version="target-epoch-evidence.v3",
            collector_id="collector-01",
            site_id="school-01",
            campaign_id="campaign-01",
            gate="8h",
            runtime_epoch=number,
            disposition=disposition,
        )
        for number, disposition in (
            (1, "restart"),
            (2, "authorize"),
        )
    )
    c2 = TargetC2EvidenceV3.model_construct(
        schema_version="target-c2-evidence.v3",
        collector_id="collector-01",
        site_id="school-01",
        campaign_id="campaign-01",
        gate="8h",
        epochs=epochs,
    )
    return TargetCampaignCompletionV3(
        c2_evidence=c2,
        c2_capability=object(),
        final_runtime=_Runtime(events, cleanup_failure=cleanup_failure),
        final_channel=_Channel(events),  # type: ignore[arg-type]
    )


def _collected(
    path: Path,
    *,
    continuation_capability: object | None = None,
) -> replay.TargetV3CollectedEvidence:
    record = AcceptanceRunRecordV2.model_construct(
        run_id="collector-01",
        site_id="school-01",
        gate="8h",
        environment="target",
    )
    envelope = AcceptanceFinalEnvelopeV2.model_construct(
        schema_version="acceptance-final-envelope.v2",
        record=record,
        attestation=TargetRunAttestationV2.model_construct(),
        signature_hex="0" * 128,
    )
    return replay.TargetV3CollectedEvidence(
        final_envelope=envelope,
        journal_proof_path=path,
        continuation_capability=(
            continuation_capability or object()
        ),
    )


def test_campaign_rejects_a_reused_restart_nonce_before_any_launch(
    tmp_path: Path,
) -> None:
    input_root = tmp_path / "inputs"
    input_root.mkdir()
    context, request, _identity, graph = _target_inputs(input_root)
    reused = request.model_copy(
        update={
            "runtime_epoch": request.runtime_epoch + 1,
            "runtime_epoch_started_generation": request.runtime_epoch + 1,
        }
    )
    launched: list[object] = []

    with pytest.raises(ValueError, match="two-epoch|launch chain"):
        TargetCampaignCoordinatorV3(
            collector_id="collector-01",
            trust_context=context,
            launch_requests=(request, reused),
            graph=graph,
            channel_root=tmp_path,
            environment_factory=lambda *_args: launched.append(object()),  # type: ignore[arg-type]
            source_profile_provider=lambda *_args: launched.append(object()),  # type: ignore[arg-type]
        )

    assert launched == []


def test_campaign_snapshots_two_requests_and_custom_launcher_cannot_authorize(
    tmp_path: Path,
) -> None:
    input_root = tmp_path / "inputs"
    input_root.mkdir()
    context, first, _identity, graph = _target_inputs(input_root)
    second = TargetRuntimeLaunchRequestV2.model_validate(
        {
            **first.model_dump(mode="python"),
            "launch_nonce": "2" * 32,
            "runtime_epoch": first.runtime_epoch + 1,
            "runtime_epoch_started_generation": first.runtime_epoch + 1,
        }
    )
    launched: list[object] = []
    coordinator = TargetCampaignCoordinatorV3(
        collector_id="collector-01",
        trust_context=context,
        launch_requests=(first, second),
        graph=graph,
        channel_root=tmp_path,
        environment_factory=lambda *_args: launched.append(object()),  # type: ignore[arg-type]
        source_profile_provider=lambda *_args: launched.append(object()),  # type: ignore[arg-type]
        runtime_launcher=lambda *_args: launched.append(object()),  # type: ignore[arg-type]
    )
    original_nonce = coordinator._requests[0].launch_nonce
    object.__setattr__(first, "launch_nonce", "f" * 32)

    assert coordinator._requests[0].launch_nonce == original_nonce
    coordinator._runtime_launcher = (
        launch_and_observe_controller_owned_target_runtime
    )
    with pytest.raises(RuntimeError, match="non-authorizing"):
        coordinator.run()
    assert launched == []


def test_controller_runtime_owner_rejects_unissued_fake_process(
    tmp_path: Path,
) -> None:
    input_root = tmp_path / "inputs"
    input_root.mkdir()
    _context, request, identity, _graph = _target_inputs(input_root)

    with pytest.raises(TypeError, match="private Docker provenance"):
        _ControllerOwnedDockerRuntime(
            process=object(),  # type: ignore[arg-type]
            request=request,
            identity=identity,
            started_monotonic_ns=1,
        )


def test_campaign_rejects_mounting_the_controller_key_parent(
    tmp_path: Path,
) -> None:
    channel = tmp_path / "channel-00000000000000000000000000000001"
    channel.mkdir()
    exposed = TargetRuntimeControllerEnvironmentV2(
        engine_path=Path("/usr/bin/docker"),
        nvidia_ctk_path=Path("/usr/bin/nvidia-ctk"),
        command=("runtime", "--acceptance-channel", "/run/acceptance"),
        reviewed_mount_argv=(
            "--mount",
            f"type=bind,src={tmp_path},dst=/run/acceptance",
        ),
    )
    with pytest.raises(ValueError, match="controller|authority|mount"):
        _require_exact_channel_mount(exposed, channel)

    exact = exposed.model_copy(
        update={
            "reviewed_mount_argv": (
                "--mount",
                f"type=bind,src={channel},dst=/run/acceptance",
            )
        }
    )
    _require_exact_channel_mount(exact, channel)


def test_campaign_external_fake_child_parses_channel_prewarm_and_c2_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_root = tmp_path / "inputs"
    input_root.mkdir()
    context, base_request, base_identity, graph = _target_inputs(
        input_root
    )
    expectations = tuple(
        SourceProfileExpectation(
            camera_id=source.camera_id,
            source_index=source.source_index,
            source_identity_commitment=(
                base_request.source_bindings[
                    source.source_index
                ].source_identity_commitment
            ),
            codec=source.codec,
            width=source.width,
            height=source.height,
            fps_min=source.fps,
            fps_max=source.fps,
            bitrate_kbps_min=source.bitrate_kbps,
            bitrate_kbps_max=source.bitrate_kbps,
            max_timestamp_gap_ns=2_000_000_000,
            max_timestamp_skew_ns=500_000_000,
            stale_after_ns=5_000_000_000,
            signature=hashlib.sha256(
                f"profile:{source.camera_id}".encode()
            ).hexdigest(),
        )
        for source in context.workloads
    )
    profile_signer = Ed25519SourceProfileProofSigner(
        key_id=PROOF_KEY_ID,
        signing_seed=PROOF_SEED,
    )

    def epoch_inputs(
        number: int,
    ) -> tuple[TargetRuntimeLaunchRequestV2, TargetRuntimeIdentityV2]:
        request = TargetRuntimeLaunchRequestV2.model_validate(
            {
                **base_request.model_dump(mode="python"),
                "launch_nonce": f"{number:032x}",
                "runtime_epoch": number,
                "runtime_epoch_started_generation": number,
            }
        )
        identity = TargetRuntimeIdentityV2.model_validate(
            {
                **base_identity.model_dump(mode="python"),
                "launch_request": request,
                "process_id": f"docker:{number:064x}",
                "runtime_boot_id": f"container:{number:064x}",
                "container_id": f"{number:064x}",
                "runtime_epoch": number,
                "runtime_epoch_started_generation": number,
                "runtime_epoch_started_monotonic_ns": (
                    number * 1_000_000_000
                ),
                "identity_observed_monotonic_ns": (
                    number * 1_000_000_000 + 1
                ),
            }
        )
        return request, identity

    first_request, first_identity = epoch_inputs(1)
    second_request, second_identity = epoch_inputs(2)
    first_attestation = _attestation(
        context,
        first_request,
        expectations,
        profile_signer,
    )
    second_attestation = _attestation(
        context,
        second_request,
        expectations,
        profile_signer,
    )
    verified_profiles = []
    for label, request, attestation in (
        ("first", first_request, first_attestation),
        ("second", second_request, second_attestation),
    ):
        profile_path = tmp_path / f"{label}-profile.json"
        signature_path = tmp_path / f"{label}-profile.sig"
        profile_path.write_bytes(canonical_json_bytes(attestation))
        profile_path.chmod(0o600)
        subprocess.run(
            (
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(
                    next(
                        input_root.glob(
                            "acceptance-trust-*/manifest.private.pem"
                        )
                    )
                ),
                "-in",
                str(profile_path),
                "-out",
                str(signature_path),
            ),
            check=True,
            capture_output=True,
        )
        signature_path.chmod(0o600)
        verified_profiles.append(
            capture_verified_target_source_profile_attestation(
                context=context,
                launch_request=request,
                attestation_path=profile_path,
                signature_path=signature_path,
            )
        )
    first_profile, second_profile = verified_profiles
    identities_by_nonce = {
        first_request.launch_nonce: first_identity,
        second_request.launch_nonce: second_identity,
    }
    profiles = {
        first_request.request_sha256: first_profile,
        second_request.request_sha256: second_profile,
    }
    removed: list[int] = []
    child_events: list[str] = []
    child_threads: list[threading.Thread] = []
    child_failures: list[BaseException] = []
    monotonic_ticks = itertools.count(1_000_000_000)
    monkeypatch.setattr(
        acceptance_target_controller,
        "time",
        SimpleNamespace(monotonic_ns=lambda: next(monotonic_ticks)),
    )

    def launch_process(**arguments: object) -> DockerRuntimeProcess:
        nonce = str(arguments["launch_nonce"])
        identity = identities_by_nonce[nonce]
        process = _issue_docker_runtime_process(
            engine="/usr/bin/docker",
            container_id=identity.container_id,
            container_config_sha256=identity.container_config_sha256,
            control_network_id=identity.control_network_id,
            control_network_config_sha256=(
                identity.control_network_config_sha256
            ),
            camera_network_id=identity.camera_network_id,
            camera_network_config_sha256=(
                identity.camera_network_config_sha256
            ),
            observed_gpu_inventory=identity.observed_gpu_inventory,
            name=f"runtime-{identity.runtime_epoch}",
            launch_nonce=nonce,
            verify_identity=lambda: identity.observed_gpu_inventory,
            run=lambda *_args, **_kwargs: subprocess.CompletedProcess(
                args=(),
                returncode=0,
                stdout="",
                stderr="",
            ),
        )
        process._test_epoch = identity.runtime_epoch
        return process

    def remove_process(process: DockerRuntimeProcess) -> None:
        if not process._removed:
            removed.append(process._test_epoch)
            process._removed = True

    monkeypatch.setattr(
        acceptance_target_controller,
        "launch_docker_runtime",
        launch_process,
    )
    monkeypatch.setattr(DockerRuntimeProcess, "remove", remove_process)

    def prepare_child(path: Path) -> None:
        from protector.pilot.acceptance_channel import (
            RuntimeAcceptanceChannelV3,
        )
        from protector.pilot.runtime import work_authority

        try:
            runtime = RuntimeAcceptanceChannelV3.claim_path(path)
            child_events.append(f"claim:{path.name}")
            grant = runtime.consume_grant_wait(timeout_seconds=2.0)
            runtime.verified_source_profile()
            prewarm = TargetNativePrewarmProjectionV2(
                schema_version="target-native-prewarm-projection.v2",
                launch_request_sha256=(
                    grant.launch_request.request_sha256
                ),
                runtime_identity_sha256=(
                    grant.runtime_identity.identity_sha256
                ),
                site_id=grant.launch_request.launch.site_id,
                campaign_id=grant.launch_request.campaign_id,
                launch_nonce=grant.launch_request.launch_nonce,
                runtime_epoch=grant.launch_request.runtime_epoch,
                runtime_epoch_started_generation=(
                    grant.launch_request.runtime_epoch_started_generation
                ),
                runtime_epoch_started_monotonic_ns=(
                    grant.runtime_identity.runtime_epoch_started_monotonic_ns
                ),
                ready_at_monotonic_ns=(
                    grant.runtime_identity.runtime_epoch_started_monotonic_ns
                    + 60_000_000_000
                ),
                source_bindings=grant.launch_request.source_bindings,
                source_identity_commitments_sha256="8" * 64,
                native_claims_sha256="9" * 64,
                source_profile_proof_sha256="a" * 64,
            )
            monkeypatch.setattr(
                work_authority,
                "_monotonic_ns",
                lambda: prewarm.ready_at_monotonic_ns + 1_000_000_000,
            )
            ledger = TargetUniqueWorkRuntimeLedger(
                plan=grant.unique_work_plan,
                native_prewarm=prewarm,
            )
            child_events.append(
                f"prewarm:{grant.launch_request.runtime_epoch}"
            )
            _record_all(ledger, grant.unique_work_plan, monkeypatch)
            projection = ledger.publish_projection(
                tmp_path / f"work-{grant.channel_nonce}.json"
            )
            runtime.publish_result(
                native_prewarm=prewarm,
                unique_work_projection=projection,
            )
            child_events.append(
                f"work:{grant.launch_request.runtime_epoch}"
            )
        except BaseException as exc:
            child_failures.append(exc)
            raise

        def finish_ack() -> None:
            try:
                deadline = time.monotonic() + 10.0
                while True:
                    try:
                        runtime.consume_directive()
                        break
                    except FileNotFoundError:
                        if time.monotonic() >= deadline:
                            raise RuntimeError("directive wait timed out")
                        time.sleep(0.01)
                runtime.publish_ack()
            except BaseException as exc:
                child_failures.append(exc)

        thread = threading.Thread(target=finish_ack)
        child_threads.append(thread)
        thread.start()

    channel_root = tmp_path / "channels"
    channel_root.mkdir(mode=0o700)

    def environment(
        _request: object,
        channel_path: Path,
    ) -> TargetRuntimeControllerEnvironmentV2:
        return TargetRuntimeControllerEnvironmentV2(
            engine_path=Path("/usr/bin/docker"),
            nvidia_ctk_path=Path("/usr/bin/nvidia-ctk"),
            command=(
                "runtime",
                "--acceptance-channel",
                "/run/acceptance",
            ),
            reviewed_mount_argv=(
                "--mount",
                (
                    f"type=bind,src={channel_path},"
                    "dst=/run/acceptance"
                ),
            ),
        )

    coordinator = TargetCampaignCoordinatorV3(
        collector_id="collector-01",
        trust_context=context,
        launch_requests=(first_request, second_request),
        graph=graph,
        channel_root=channel_root,
        environment_factory=environment,
        source_profile_provider=lambda request: profiles[
            request.request_sha256
        ],
        channel_wait_seconds=10.0,
    )

    def run_external_child() -> None:
        try:
            for request in (first_request, second_request):
                channel_path = (
                    channel_root / f"channel-{request.launch_nonce}"
                )
                deadline = time.monotonic() + 10.0
                while not channel_path.exists():
                    if time.monotonic() >= deadline:
                        raise RuntimeError(
                            "external fake child channel wait timed out"
                        )
                    time.sleep(0.01)
                prepare_child(channel_path)
        except BaseException as exc:
            child_failures.append(exc)

    fake_child = threading.Thread(target=run_external_child)
    fake_child.start()
    completion = coordinator.run()
    fake_child.join(timeout=10.0)
    for thread in child_threads:
        thread.join(timeout=10.0)

    assert child_failures == []
    assert fake_child.is_alive() is False
    assert all(thread.is_alive() is False for thread in child_threads)
    assert tuple(
        (epoch.runtime_epoch, epoch.disposition)
        for epoch in completion.c2_evidence.epochs
    ) == ((1, "restart"), (2, "authorize"))
    assert child_events == [
        f"claim:channel-{first_request.launch_nonce}",
        "prewarm:1",
        "work:1",
        f"claim:channel-{second_request.launch_nonce}",
        "prewarm:2",
        "work:2",
    ]
    assert removed == [1]
    completion.final_runtime.cleanup()
    completion.final_channel.abort()
    assert removed == [1, 2]


def test_campaign_refuses_injected_child_grant_hook_before_launch(
    tmp_path: Path,
) -> None:
    input_root = tmp_path / "inputs"
    input_root.mkdir()
    context, first, _identity, graph = _target_inputs(input_root)
    second = TargetRuntimeLaunchRequestV2.model_validate(
        {
            **first.model_dump(mode="python"),
            "launch_nonce": "2" * 32,
            "runtime_epoch": first.runtime_epoch + 1,
            "runtime_epoch_started_generation": first.runtime_epoch + 1,
        }
    )
    launched: list[object] = []
    coordinator = TargetCampaignCoordinatorV3(
        collector_id="collector-01",
        trust_context=context,
        launch_requests=(first, second),
        graph=graph,
        channel_root=tmp_path,
        environment_factory=lambda *_args: launched.append(object()),  # type: ignore[arg-type]
        source_profile_provider=lambda *_args: launched.append(object()),  # type: ignore[arg-type]
        child_grant_hook=lambda *_args: launched.append(object()),
    )

    with pytest.raises(RuntimeError, match="non-authorizing"):
        coordinator.run()
    assert launched == []


def test_target_v3_replay_passes_continuation_capability_into_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_root = tmp_path / "inputs"
    input_root.mkdir()
    context, _request, _identity, _graph = _target_inputs(input_root)
    events: list[str] = []
    coordinator = object.__new__(TargetCampaignCoordinatorV3)
    collector_runner = object.__new__(
        replay.RetainedRuntimeTargetV3Collector
    )
    campaign = _campaign(events)
    continuation_capability = object()

    def run_campaign(_self: object) -> TargetCampaignCompletionV3:
        events.append("campaign")
        return campaign

    def collect(
        _self: object,
        _arguments: argparse.Namespace,
        observed: TargetCampaignCompletionV3,
    ) -> replay.TargetV3CollectedEvidence:
        assert observed is campaign
        events.append("collector")
        return _collected(
            tmp_path / "proof.jsonl",
            continuation_capability=continuation_capability,
        )

    expected = (object(), object())

    def bind(**kwargs: object) -> tuple[object, object]:
        assert kwargs["c2_capability"] is campaign.c2_capability
        assert (
            kwargs["continuation_capability"]
            is continuation_capability
        )
        events.append("bind")
        return expected

    monkeypatch.setattr(TargetCampaignCoordinatorV3, "run", run_campaign)
    monkeypatch.setattr(
        replay.RetainedRuntimeTargetV3Collector,
        "__call__",
        collect,
    )
    monkeypatch.setattr(replay, "bind_target_authority_v3", bind)

    observed = replay.run_target_v3(
        argparse.Namespace(),
        coordinator=coordinator,
        collector_runner=collector_runner,
        trust_context=context,
        signer=object(),  # type: ignore[arg-type]
    )

    assert observed is expected
    assert events == ["campaign", "collector", "bind"]


def test_target_v3_replay_hostile_collector_cleans_owned_epoch_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_root = tmp_path / "inputs"
    input_root.mkdir()
    context, _request, _identity, _graph = _target_inputs(input_root)
    events: list[str] = []
    coordinator = object.__new__(TargetCampaignCoordinatorV3)
    campaign = _campaign(events)
    collector_runner = object.__new__(
        replay.RetainedRuntimeTargetV3Collector
    )

    class Cleanup:
        def cleanup(
            self,
            observed: TargetCampaignCompletionV3,
        ) -> None:
            assert observed is campaign
            observed.final_runtime.cleanup()
            observed.final_channel.abort()

    collector_runner._continuation = Cleanup()
    monkeypatch.setattr(
        TargetCampaignCoordinatorV3,
        "run",
        lambda _self: events.append("campaign") or campaign,
    )

    def fail(
        _self: object,
        _arguments: argparse.Namespace,
        _campaign: TargetCampaignCompletionV3,
    ) -> replay.TargetV3CollectedEvidence:
        events.append("collector")
        raise ValueError("hostile collector failure")

    monkeypatch.setattr(
        replay.RetainedRuntimeTargetV3Collector,
        "_collect",
        fail,
    )
    with pytest.raises(ValueError, match="hostile collector failure"):
        replay.run_target_v3(
            argparse.Namespace(),
            coordinator=coordinator,
            collector_runner=collector_runner,
            trust_context=context,
            signer=object(),  # type: ignore[arg-type]
        )

    assert events == [
        "campaign",
        "collector",
        "cleanup",
        "channel-cleanup",
    ]
