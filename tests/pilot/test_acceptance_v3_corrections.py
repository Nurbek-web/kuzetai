from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
import sqlite3
import stat
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

import scripts.pilot.replay_20 as replay
from protector.pilot.acceptance import ExecutionBindingV2
from protector.pilot.api import acceptance_controller
from protector.pilot.acceptance_c2 import (
    SQLiteTargetExecutionTransitionJournalV3,
    TargetC2AuthorityV3,
    TargetC2ContinuationEvidenceV3,
    TargetC2EvidenceV3,
    TargetEpochEvidenceV3,
    TargetExecutionTransitionEntryV3,
    TargetExecutionTransitionJournalV3,
)
from protector.pilot.acceptance_campaign import _require_exact_channel_mount
from protector.pilot.acceptance_capture_v3 import (
    ReviewedAcceptanceCaptureProducerV3,
)
from protector.pilot.acceptance_channel import (
    ControllerAcceptanceChannelV3,
    RuntimeAcceptanceChannelV3,
)
from protector.pilot.acceptance_source_profile import (
    VerifiedTargetSourceProfileAttestationV2,
    export_verified_target_source_profile,
    verify_transmitted_target_source_profile,
)
from protector.pilot.acceptance_target_controller import (
    TargetRuntimeControllerEnvironmentV2,
)
from protector.pilot.acceptance_work import derive_target_unique_work_plan
from tests.pilot.test_acceptance_source_profile import _verified_fixture
from tests.pilot.test_acceptance_work import _target_inputs


def _epoch(number: int, disposition: str) -> TargetEpochEvidenceV3:
    digest = f"{number:x}" * 64
    return TargetEpochEvidenceV3(
        schema_version="target-epoch-evidence.v3",
        collector_id="collector-01",
        site_id="school-01",
        campaign_id="campaign-01",
        gate="8h",
        runtime_epoch=number,
        runtime_epoch_started_generation=number,
        launch_nonce=f"{number:032x}",
        container_id=digest,
        launch_request_sha256=digest,
        runtime_identity_sha256=digest,
        gpu_inventory_sha256=digest,
        source_profile_sha256=digest,
        native_prewarm_sha256=digest,
        unique_work_plan_sha256=digest,
        unique_work_sha256=digest,
        completion_sha256=digest,
        runtime_epoch_started_monotonic_ns=number * 1_000_000_000,
        identity_observed_monotonic_ns=number * 1_000_000_000 + 1,
        prewarm_ready_at_monotonic_ns=number * 1_000_000_000 + 2,
        measurement_started_monotonic_ns=number * 1_000_000_000 + 3,
        measurement_completed_monotonic_ns=number * 1_000_000_000
        + 60_000_000_003,
        disposition=disposition,
    )


def _execution(number: int) -> ExecutionBindingV2:
    digest = f"{number:x}" * 64
    return ExecutionBindingV2(
        schema_version="acceptance-execution-binding.v2",
        launch_attestation_sha256="a" * 64,
        launch_nonce=f"{number:032x}",
        container_id=digest,
        container_config_sha256="b" * 64,
        runtime_image_id_sha256="c" * 64,
        acceptance_adapter_sha256="d" * 64,
        acceptance_adapter_policy_sha256="e" * 64,
        acceptance_observer_sha256="f" * 64,
        acceptance_observer_policy_sha256="1" * 64,
        control_network_id="2" * 64,
        control_network_config_sha256="3" * 64,
        camera_network_id="4" * 64,
        camera_network_config_sha256="5" * 64,
        observed_gpu_inventory_sha256="6" * 64,
    )


def _continuation_fixture() -> tuple[
    TargetC2EvidenceV3,
    ExecutionBindingV2,
    ExecutionBindingV2,
    TargetEpochEvidenceV3,
    tuple[TargetExecutionTransitionEntryV3, ...],
]:
    base_c2 = TargetC2EvidenceV3(
        schema_version="target-c2-evidence.v3",
        collector_id="collector-01",
        site_id="school-01",
        campaign_id="campaign-01",
        gate="8h",
        epochs=(_epoch(1, "restart"), _epoch(2, "authorize")),
    )
    previous_execution = _execution(2)
    continuation_execution = _execution(3)
    continuation_epoch = _epoch(3, "authorize")
    actual_boot_id = f"container:{'3' * 64}"
    compatibility_boot_id = (
        f"{previous_execution.launch_nonce}.container-{'3' * 32}"
    )
    common = {
        "schema_version": "target-execution-transition-entry.v3",
        "collector_id": base_c2.collector_id,
        "site_id": base_c2.site_id,
        "campaign_id": base_c2.campaign_id,
        "gate": base_c2.gate,
        "runtime_restart_fault_id": "runtime-restart-01",
        "base_c2_evidence_sha256": base_c2.evidence_sha256,
        "previous_epoch_sha256": base_c2.epochs[-1].epoch_sha256,
        "previous_execution_binding_sha256": (
            previous_execution.binding_sha256
        ),
        "previous_runtime_identity_sha256": (
            base_c2.epochs[-1].runtime_identity_sha256
        ),
        "continuation_launch_request_sha256": (
            continuation_epoch.launch_request_sha256
        ),
        "continuation_launch_nonce": continuation_epoch.launch_nonce,
        "continuation_runtime_epoch": continuation_epoch.runtime_epoch,
    }
    requested = TargetExecutionTransitionEntryV3(
        **common,
        sequence=1,
        phase="requested",
        previous_entry_sha256="0" * 64,
        recorded_monotonic_ns=1,
    )
    runtime_fields = {
        "continuation_execution_binding_sha256": (
            continuation_execution.binding_sha256
        ),
        "continuation_runtime_identity_sha256": (
            continuation_epoch.runtime_identity_sha256
        ),
        "continuation_runtime_boot_id": actual_boot_id,
        "v2_compatibility_runtime_boot_id": compatibility_boot_id,
    }
    observed = TargetExecutionTransitionEntryV3(
        **common,
        **runtime_fields,
        sequence=2,
        phase="runtime_observed",
        previous_entry_sha256=requested.entry_sha256,
        recorded_monotonic_ns=2,
    )
    authorized = TargetExecutionTransitionEntryV3(
        **common,
        **runtime_fields,
        sequence=3,
        phase="authorized",
        source_profile_sha256=continuation_epoch.source_profile_sha256,
        native_prewarm_sha256=continuation_epoch.native_prewarm_sha256,
        unique_work_plan_sha256=(
            continuation_epoch.unique_work_plan_sha256
        ),
        unique_work_sha256=continuation_epoch.unique_work_sha256,
        completion_sha256=continuation_epoch.completion_sha256,
        previous_entry_sha256=observed.entry_sha256,
        recorded_monotonic_ns=3,
    )
    return (
        base_c2,
        previous_execution,
        continuation_execution,
        continuation_epoch,
        (requested, observed, authorized),
    )


def test_c2_wire_contract_is_exactly_two_epochs() -> None:
    exact = TargetC2EvidenceV3(
        schema_version="target-c2-evidence.v3",
        collector_id="collector-01",
        site_id="school-01",
        campaign_id="campaign-01",
        gate="8h",
        epochs=(_epoch(1, "restart"), _epoch(2, "authorize")),
    )
    assert len(exact.epochs) == 2

    with pytest.raises(ValidationError, match="2|two|length"):
        TargetC2EvidenceV3(
            schema_version="target-c2-evidence.v3",
            collector_id="collector-01",
            site_id="school-01",
            campaign_id="campaign-01",
            gate="8h",
            epochs=(
                _epoch(1, "restart"),
                _epoch(2, "restart"),
                _epoch(3, "authorize"),
            ),
        )


def test_c2_committed_state_cannot_be_injected_or_reset_by_callers() -> None:
    authority = TargetC2AuthorityV3(
        collector_id="collector-01",
        site_id="school-01",
        campaign_id="campaign-01",
        gate="8h",
    )
    for name, value in (
        ("_epochs", [_epoch(1, "restart"), _epoch(2, "authorize")]),
        ("_finalized", False),
    ):
        with pytest.raises(AttributeError):
            setattr(authority, name, value)
        with pytest.raises(AttributeError):
            object.__setattr__(authority, name, value)

    with pytest.raises(RuntimeError, match="restart|epoch|complete"):
        authority.finalize()


def test_continuation_schema_binds_fresh_runtime_and_restart_evidence() -> None:
    (
        base_c2,
        previous_execution,
        continuation_execution,
        continuation_epoch,
        entries,
    ) = _continuation_fixture()
    journal = TargetExecutionTransitionJournalV3(
        schema_version="target-execution-transition-journal.v3",
        entries=entries,
    )
    evidence = TargetC2ContinuationEvidenceV3(
        schema_version="target-c2-continuation-evidence.v3",
        base_c2=base_c2,
        runtime_restart_fault_id="runtime-restart-01",
        injected_monotonic_offset_seconds=40.0,
        recovered_monotonic_offset_seconds=43.0,
        previous_execution=previous_execution,
        continuation_execution=continuation_execution,
        continuation_epoch=continuation_epoch,
        continuation_runtime_boot_id=entries[-1].continuation_runtime_boot_id,
        v2_compatibility_runtime_boot_id=(
            entries[-1].v2_compatibility_runtime_boot_id
        ),
        transition_journal=journal,
    )

    assert evidence.continuation_epoch.runtime_epoch == 3
    assert evidence.continuation_runtime_boot_id != (
        evidence.v2_compatibility_runtime_boot_id
    )

    tampered_previous = previous_execution.model_dump(mode="python")
    tampered_previous["container_id"] = "9" * 64
    with pytest.raises(ValidationError, match="fresh runtime|restart|bind"):
        TargetC2ContinuationEvidenceV3.model_validate(
            {
                **evidence.model_dump(mode="python"),
                "previous_execution": tampered_previous,
            }
        )
    with pytest.raises(ValidationError):
        TargetC2ContinuationEvidenceV3.model_validate(
            {
                **evidence.model_dump(mode="python"),
                "recovered_monotonic_offset_seconds": 44.0,
            }
        )


def test_transition_journal_detects_tamper_after_reopen(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    _base, _previous, _continuation, _epoch_three, entries = (
        _continuation_fixture()
    )
    path = tmp_path / "transition.sqlite3"
    store = SQLiteTargetExecutionTransitionJournalV3(path)
    store.append(entries[0])
    reopened = SQLiteTargetExecutionTransitionJournalV3(path)
    reopened.append(entries[1])
    reopened.append(entries[2])

    with sqlite3.connect(path) as connection:
        encoded = connection.execute(
            "SELECT entry_json FROM target_execution_transitions "
            "WHERE collector_id = ? AND sequence = 3",
            (entries[2].collector_id,),
        ).fetchone()[0]
        payload = json.loads(encoded)
        payload["completion_sha256"] = "9" * 64
        connection.execute(
            "UPDATE target_execution_transitions SET entry_json = ? "
            "WHERE collector_id = ? AND sequence = 3",
            (
                json.dumps(
                    payload,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                entries[2].collector_id,
            ),
        )

    with pytest.raises(RuntimeError, match="digest|tamper"):
        SQLiteTargetExecutionTransitionJournalV3(path).finalize(
            entries[2].collector_id
        )


def test_transition_journal_finalization_is_durable_one_shot(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    _base, _previous, _continuation, _epoch_three, entries = (
        _continuation_fixture()
    )
    path = tmp_path / "transition.sqlite3"
    store = SQLiteTargetExecutionTransitionJournalV3(path)
    for entry in entries:
        store.append(entry)

    journal, capability = store.finalize(entries[0].collector_id)

    assert journal.entries == entries
    assert type(capability) is not object
    with pytest.raises(RuntimeError, match="finalized|sealed|replay"):
        store.finalize(entries[0].collector_id)
    with pytest.raises(RuntimeError, match="finalized|sealed"):
        store.append(entries[-1])
    reopened = SQLiteTargetExecutionTransitionJournalV3(path)
    with pytest.raises(RuntimeError, match="finalized|sealed|replay"):
        reopened.finalize(entries[0].collector_id)
    assert {
        "SQLiteTargetExecutionTransitionJournalV3",
        "TargetC2ContinuationEvidenceV3",
        "TargetExecutionTransitionEntryV3",
        "TargetExecutionTransitionJournalV3",
        "authorize_target_c2_continuation_v3",
    }.isdisjoint(__import__("protector.pilot.acceptance_c2", fromlist=["__all__"]).__all__)


def test_transition_journal_rejects_database_inode_alias(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    _base, _previous, _continuation, _epoch_three, entries = (
        _continuation_fixture()
    )
    path = tmp_path / "transition.sqlite3"
    store = SQLiteTargetExecutionTransitionJournalV3(path)
    alias = tmp_path / "transition-alias.sqlite3"
    alias.hardlink_to(path)

    with pytest.raises(RuntimeError, match="unsafe|identity"):
        store.append(entries[0])


def test_runtime_waits_for_controller_grant_after_claim(
    tmp_path: Path,
) -> None:
    input_root = tmp_path / "inputs"
    input_root.mkdir()
    context, request, identity, graph = _target_inputs(input_root)
    plan, _authority = derive_target_unique_work_plan(
        trust_context=context,
        launch_request=request,
        runtime_identity=identity,
        graph=graph,
    )
    root = tmp_path / "channels"
    root.mkdir(mode=0o700)
    controller = ControllerAcceptanceChannelV3.create(
        root=root,
        collector_id="collector-01",
        launch_request=request,
    )
    runtime = RuntimeAcceptanceChannelV3.claim_path(controller.runtime_claim_path)

    publisher = threading.Thread(
        target=lambda: (
            time.sleep(0.05),
            controller.publish_grant(
                runtime_identity=identity,
                unique_work_plan=plan,
            ),
        )
    )
    publisher.start()
    try:
        grant = runtime.consume_grant_wait(
            timeout_seconds=1.0,
            poll_seconds=0.01,
        )
    finally:
        publisher.join()
        controller.abort()
    assert grant.runtime_identity_sha256 == identity.identity_sha256


def test_failed_runtime_claim_rolls_back_for_one_safe_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from protector.pilot import acceptance_channel

    input_root = tmp_path / "inputs"
    input_root.mkdir()
    _context, request, _identity, _graph = _target_inputs(input_root)
    root = tmp_path / "channels"
    root.mkdir(mode=0o700)
    controller = ControllerAcceptanceChannelV3.create(
        root=root,
        collector_id="collector-01",
        launch_request=request,
    )
    real_read = acceptance_channel._read_private
    attempts = 0

    def fail_once(path: Path, *, max_bytes: int) -> bytes:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("simulated key read interruption")
        return real_read(path, max_bytes=max_bytes)

    monkeypatch.setattr(
        acceptance_channel,
        "_read_private",
        fail_once,
    )
    with pytest.raises(OSError, match="interruption"):
        RuntimeAcceptanceChannelV3.claim_path(
            controller.runtime_claim_path
        )
    assert not (controller.runtime_claim_path / "runtime.claim").exists()

    RuntimeAcceptanceChannelV3.claim_path(controller.runtime_claim_path)
    controller.abort()


def test_child_reverifies_transmitted_signed_source_profile(
    tmp_path: Path,
) -> None:
    context, request, *_rest, verified, _profile, _signature, _bundle = (
        _verified_fixture(tmp_path)
    )
    transmitted = export_verified_target_source_profile(verified)
    reparsed = verify_transmitted_target_source_profile(
        transmitted,
        launch_request=request,
    )

    assert reparsed.attestation == verified.attestation
    assert reparsed.verified_binding_sha256 == verified.verified_binding_sha256
    assert "_mint_verified" not in inspect.getsource(
        RuntimeAcceptanceChannelV3.verified_source_profile
    )
    forged = object.__new__(VerifiedTargetSourceProfileAttestationV2)
    for slot in VerifiedTargetSourceProfileAttestationV2.__slots__:
        object.__setattr__(forged, slot, getattr(verified, slot))
    object.__setattr__(forged, "_verified_binding_sha256", "f" * 64)
    with pytest.raises(ValueError, match="provenance"):
        export_verified_target_source_profile(forged)
    with pytest.raises(TypeError, match="typed|operational|capture"):
        ReviewedAcceptanceCaptureProducerV3(
            trust_context=context,
            controller_image_sha256="1" * 64,
            controller_code_sha256="2" * 64,
            operational_limits=object(),  # type: ignore[arg-type]
            operational_evidence=object(),  # type: ignore[arg-type]
            repository_boundary=object(),  # type: ignore[arg-type]
            conditional_gate_decisions=(),
        )


def test_runtime_result_requires_child_verified_signed_profile() -> None:
    runtime = object.__new__(RuntimeAcceptanceChannelV3)
    runtime._grant = SimpleNamespace(signed_source_profile=object())
    runtime._verified_source_profile = None
    runtime._result_published = False

    with pytest.raises(RuntimeError, match="verify|profile"):
        runtime.publish_result(
            native_prewarm=None,  # type: ignore[arg-type]
            unique_work_projection=None,  # type: ignore[arg-type]
        )


def test_channel_mount_rejects_controller_key_sibling_and_alias(
    tmp_path: Path,
) -> None:
    channel = tmp_path / "channel-00000000000000000000000000000001"
    channel.mkdir()
    controller_key = tmp_path / ".controller-key-00000000000000000000000000000001"
    controller_key.write_bytes(b"x")
    alias = tmp_path / "channel-alias"
    alias.symlink_to(channel, target_is_directory=True)

    def environment(source: Path) -> TargetRuntimeControllerEnvironmentV2:
        return TargetRuntimeControllerEnvironmentV2(
            engine_path=Path("/usr/bin/docker"),
            nvidia_ctk_path=Path("/usr/bin/nvidia-ctk"),
            command=("runtime", "--acceptance-channel", "/run/acceptance"),
            reviewed_mount_argv=(
                "--mount",
                f"type=bind,src={source},dst=/run/acceptance",
            ),
        )

    with pytest.raises(ValueError, match="controller|authority|allowlist|alias"):
        _require_exact_channel_mount(environment(controller_key), channel)
    with pytest.raises(ValueError, match="controller|authority|allowlist|alias"):
        _require_exact_channel_mount(environment(alias), channel)
    _require_exact_channel_mount(environment(channel), channel)
    other = tmp_path / "other-reviewed"
    other.mkdir()
    duplicate_destination = environment(channel).model_copy(
        update={
            "reviewed_mount_argv": (
                "--mount",
                f"type=bind,src={other},dst=/run/acceptance",
                "--mount",
                f"type=bind,src={channel},dst=/run/acceptance",
            )
        }
    )
    with pytest.raises(ValueError, match="destination|mount"):
        _require_exact_channel_mount(
            duplicate_destination,
            channel,
            reviewed_mount_sources=frozenset({other}),
        )


def test_run_signing_key_cannot_be_beneath_a_child_mount(
    tmp_path: Path,
) -> None:
    mounted = tmp_path / "source-secrets"
    mounted.mkdir(mode=0o700)
    key = mounted / "run-private.pem"
    key.write_bytes(b"private-key")
    key.chmod(0o600)

    with pytest.raises(ValueError, match="signing key|mount"):
        replay._require_unmounted_signer_path(
            key,
            forbidden_roots=(mounted,),
        )


def test_controller_token_and_collector_state_cannot_be_child_visible(
    tmp_path: Path,
) -> None:
    mounted = tmp_path / "source-secrets"
    mounted.mkdir(mode=0o700)
    token = mounted / "controller.token"
    token.write_text("controller-token-01", encoding="utf-8")
    token.chmod(0o600)

    with pytest.raises(ValueError, match="outside|child-visible"):
        replay._require_host_authority_path_outside_child_mounts(
            token,
            label="acceptance controller token",
            forbidden_roots=(mounted,),
            require_existing=True,
        )
    with pytest.raises(ValueError, match="outside|child-visible"):
        replay._require_host_authority_path_outside_child_mounts(
            mounted / "collector.sqlite3",
            label="acceptance collector state",
            forbidden_roots=(mounted,),
            require_existing=False,
        )


def test_host_authority_rejects_hardlink_and_symlink_mount_sources(
    tmp_path: Path,
) -> None:
    mounted_file = tmp_path / "mounted-secret"
    mounted_file.write_bytes(b"shared-inode")
    mounted_file.chmod(0o600)
    hardlinked_token = tmp_path / "controller.token"
    hardlinked_token.hardlink_to(mounted_file)
    hardlinked_token.chmod(0o600)

    with pytest.raises(ValueError, match="outside|child-visible|alias"):
        replay._require_host_authority_path_outside_child_mounts(
            hardlinked_token,
            label="acceptance controller token",
            forbidden_roots=(mounted_file,),
            require_existing=True,
        )

    mounted_target = tmp_path / "mounted-target"
    mounted_target.write_bytes(b"immutable")
    mounted_symlink = tmp_path / "mounted-link"
    mounted_symlink.symlink_to(mounted_target)
    separate_token = tmp_path / "separate.token"
    separate_token.write_text("controller-token-01", encoding="utf-8")
    separate_token.chmod(0o600)
    with pytest.raises(ValueError, match="outside|child-visible|canonical"):
        replay._require_host_authority_path_outside_child_mounts(
            separate_token,
            label="acceptance controller token",
            forbidden_roots=(mounted_symlink,),
            require_existing=True,
        )


def test_collector_state_rejects_child_mount_inode_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mounted = tmp_path / "source-secrets"
    authority_parent = tmp_path / "authority"
    mounted.mkdir(mode=0o700)
    authority_parent.mkdir(mode=0o700)
    mounted_identity = mounted.stat()
    real_stat = Path.stat

    def bind_aliased_stat(
        path: Path,
        *args: object,
        **kwargs: object,
    ) -> object:
        metadata = real_stat(path, *args, **kwargs)
        if path == authority_parent:
            return SimpleNamespace(
                st_dev=mounted_identity.st_dev,
                st_ino=mounted_identity.st_ino,
                st_mode=metadata.st_mode,
            )
        return metadata

    monkeypatch.setattr(Path, "stat", bind_aliased_stat)
    with pytest.raises(ValueError, match="outside|child-visible"):
        replay._require_host_authority_path_outside_child_mounts(
            authority_parent / "collector.sqlite3",
            label="acceptance collector state",
            forbidden_roots=(mounted,),
            require_existing=False,
        )


def test_protected_roots_reject_pairwise_nesting(tmp_path: Path) -> None:
    outer = tmp_path / "outer"
    inner = outer / "inner"
    inner.mkdir(parents=True, mode=0o700)
    outer.chmod(0o700)

    with pytest.raises(ValueError, match="nested|alias|distinct"):
        replay._require_distinct_directory_identities(
            (outer, inner),
            label="protected roots",
        )


def test_private_v3_roots_require_fixed_runtime_uid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "runtime-root"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(replay.os, "geteuid", lambda: 0)
    monkeypatch.setattr(replay.os, "getegid", lambda: 0)

    with pytest.raises(ValueError, match="10001|runtime UID|child UID"):
        replay._require_private_v3_directory(
            root,
            label="acceptance channel root",
        )
    assert "chown" not in inspect.getsource(
        replay._require_private_v3_directory
    )


def test_private_v3_roots_accept_exact_runtime_uid_ownership(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "runtime-root"
    root.mkdir(mode=0o700)
    metadata = root.lstat()
    real_lstat = Path.lstat

    def runtime_owned_lstat(
        path: Path,
        *args: object,
        **kwargs: object,
    ) -> object:
        observed = real_lstat(path, *args, **kwargs)
        if path == root:
            return SimpleNamespace(
                st_dev=metadata.st_dev,
                st_gid=10_001,
                st_ino=metadata.st_ino,
                st_mode=observed.st_mode,
                st_uid=10_001,
            )
        return observed

    monkeypatch.setattr(replay.os, "geteuid", lambda: 10_001)
    monkeypatch.setattr(replay.os, "getegid", lambda: 10_001)
    monkeypatch.setattr(Path, "lstat", runtime_owned_lstat)

    assert (
        replay._require_private_v3_directory(
            root,
            label="acceptance channel root",
        )
        == root
    )


def test_protected_roots_reject_a_bind_mount_inode_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = tmp_path / "first"
    alias = tmp_path / "bind-alias"
    first.mkdir(mode=0o700)
    alias.mkdir(mode=0o700)
    first_identity = first.stat()
    real_stat = Path.stat

    def bind_aliased_stat(path: Path, *args: object, **kwargs: object) -> object:
        metadata = real_stat(path, *args, **kwargs)
        if path == alias:
            return SimpleNamespace(
                st_dev=first_identity.st_dev,
                st_ino=first_identity.st_ino,
                st_mode=metadata.st_mode,
            )
        return metadata

    monkeypatch.setattr(Path, "stat", bind_aliased_stat)
    with pytest.raises(ValueError, match="inode alias|distinct"):
        replay._require_distinct_directory_identities(
            (first, alias),
            label="protected roots",
        )
    with pytest.raises(RuntimeError, match="inode alias|distinct"):
        acceptance_controller._require_distinct_v3_protected_roots(
            (("capture", first), ("channel", alias)),
        )


def test_channel_mount_rejects_a_reviewed_bind_inode_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    channel = tmp_path / "channel-00000000000000000000000000000001"
    alias = tmp_path / "reviewed-bind-alias"
    channel.mkdir()
    alias.mkdir()
    channel_identity = channel.stat()
    real_stat = Path.stat

    def bind_aliased_stat(path: Path, *args: object, **kwargs: object) -> object:
        metadata = real_stat(path, *args, **kwargs)
        if path == alias:
            return SimpleNamespace(
                st_dev=channel_identity.st_dev,
                st_ino=channel_identity.st_ino,
            )
        return metadata

    monkeypatch.setattr(Path, "stat", bind_aliased_stat)
    environment = TargetRuntimeControllerEnvironmentV2(
        engine_path=Path("/usr/bin/docker"),
        nvidia_ctk_path=Path("/usr/bin/nvidia-ctk"),
        command=("runtime", "--acceptance-channel", "/run/acceptance"),
        reviewed_mount_argv=(
            "--mount",
            f"type=bind,src={channel},dst=/run/acceptance",
        ),
    )
    with pytest.raises(ValueError, match="inode alias"):
        _require_exact_channel_mount(
            environment,
            channel,
            reviewed_mount_sources=frozenset({alias}),
        )


def test_descriptor_relative_publish_removes_partial_leaf_and_fsyncs_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from protector.pilot import acceptance_capture_v3

    root = tmp_path / "capture"
    root.mkdir(mode=0o700)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    real_write = os.write
    writes = 0
    fsynced: list[int] = []

    def fail_second_write(descriptor: int, payload: bytes) -> int:
        nonlocal writes
        writes += 1
        if writes == 2:
            raise OSError("simulated crash cut")
        return real_write(descriptor, payload[:1])

    monkeypatch.setattr(acceptance_capture_v3.os, "write", fail_second_write)
    monkeypatch.setattr(
        acceptance_capture_v3.os,
        "fsync",
        lambda descriptor: fsynced.append(descriptor),
    )
    try:
        with pytest.raises(OSError, match="crash cut"):
            acceptance_capture_v3._publish_file_at(
                directory,
                "capture.json",
                b"payload",
            )
        assert not (root / "capture.json").exists()
        assert directory in fsynced
    finally:
        os.close(directory)


def test_channel_publication_never_exposes_a_partial_final_leaf(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from protector.pilot import acceptance_channel

    root = tmp_path / "channel"
    root.mkdir(mode=0o700)
    target = root / "grant.json"
    first_byte_written = threading.Event()
    release_writer = threading.Event()
    failures: list[BaseException] = []
    real_write = os.write
    writes = 0

    def interleaved_write(descriptor: int, payload: bytes) -> int:
        nonlocal writes
        writes += 1
        if writes == 1:
            written = real_write(descriptor, payload[:1])
            first_byte_written.set()
            if not release_writer.wait(timeout=2.0):
                raise RuntimeError("interleaving test did not release writer")
            return written
        return real_write(descriptor, payload)

    monkeypatch.setattr(acceptance_channel.os, "write", interleaved_write)

    def publish() -> None:
        try:
            acceptance_channel._publish_private(target, b"complete-payload")
        except BaseException as exc:
            failures.append(exc)

    worker = threading.Thread(target=publish)
    worker.start()
    assert first_byte_written.wait(timeout=2.0)
    assert not target.exists()
    assert tuple(root.glob(".grant.json.staged-*"))
    release_writer.set()
    worker.join(timeout=2.0)

    assert failures == []
    assert target.read_bytes() == b"complete-payload"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert tuple(root.glob(".grant.json.staged-*")) == ()


def test_existing_capture_leaf_requires_private_owner_device_metadata(
    tmp_path: Path,
) -> None:
    from protector.pilot import acceptance_capture_v3

    root = tmp_path / "capture"
    root.mkdir(mode=0o700)
    existing = root / "capture.json"
    existing.write_bytes(b"payload")
    existing.chmod(0o644)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError, match="unsafe|unbounded"):
            acceptance_capture_v3._publish_file_at(
                directory,
                existing.name,
                b"payload",
            )
    finally:
        os.close(directory)


def test_staged_mounts_preserve_original_and_child_visible_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"reviewed-mount-contract"
    image_digest = "1" * 64
    targets = (
        Path("/run/config/site.yaml"),
        Path("/run/config/runtime-manifest.yaml"),
        Path("/run/config/measured-capacity.yaml"),
        Path("/run/config/measured-capacity.sig"),
        Path("/run/config/capacity-authority.pem"),
    )
    original_sources = tuple(
        tmp_path / f"original-{index}" for index in range(len(targets))
    )
    staged_sources = tuple(
        tmp_path / f"staged-{index}" for index in range(len(targets))
    )
    contract = SimpleNamespace(
        image_id=f"sha256:{image_digest}",
        mounts=tuple(
            SimpleNamespace(target=target, source=source)
            for target, source in zip(
                targets,
                original_sources,
                strict=True,
            )
        ),
    )
    staged = SimpleNamespace(
        mounts=tuple(
            SimpleNamespace(target=target, source=source)
            for target, source in zip(
                targets,
                staged_sources,
                strict=True,
            )
        )
    )
    monkeypatch.setattr(
        replay,
        "read_regular_bounded",
        lambda *_args, **_kwargs: payload,
    )
    monkeypatch.setattr(
        replay,
        "_load_runtime_mount_contract",
        lambda _payload: contract,
    )
    monkeypatch.setattr(
        replay,
        "stage_runtime_mount_contract",
        lambda **_kwargs: staged,
    )
    monkeypatch.setattr(
        replay,
        "validate_runtime_mount_contract",
        lambda **_kwargs: ("--mount", "reviewed"),
    )
    arguments = SimpleNamespace(
        mount_contract=tmp_path / "mount-contract.yaml",
        mount_contract_sha256=hashlib.sha256(payload).hexdigest(),
        runtime_image_id_sha256=image_digest,
        site_config=original_sources[0],
        runtime_manifest=original_sources[1],
        measured_capacity_report=original_sources[2],
        measured_capacity_signature=original_sources[3],
    )
    reviewed = SimpleNamespace(
        site=object(),
        runtime=object(),
        snapshots=SimpleNamespace(
            site_config=object(),
            runtime_manifest=object(),
            capacity=SimpleNamespace(
                payload=object(),
                signature=object(),
                trust_key=object(),
            ),
        ),
    )

    mount_argv, sources = replay._stage_reviewed_runtime_mounts(
        arguments,
        reviewed=reviewed,
        work_root=tmp_path / "work",
    )

    assert mount_argv == ("--mount", "reviewed")
    assert sources == frozenset((*original_sources, *staged_sources))


def test_target_command_and_parser_require_all_child_acceptance_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parser = replay._parser()
    actions = {action.dest for action in parser._actions}
    assert {
        "acceptance_channel_dir",
        "acceptance_source_secrets_root",
        "acceptance_native_projection_dir",
        "acceptance_work_projection_dir",
    } <= actions

    names = (
        "site_config",
        "site_config_sha256",
        "runtime_manifest",
        "runtime_manifest_sha256",
        "measured_capacity_report",
        "measured_capacity_sha256",
        "measured_capacity_signature",
        "runtime_image_id_sha256",
        "runtime_image_config_sha256",
        "runtime_code_sha256",
        "mount_contract_sha256",
        "mount_contract",
        "container_engine",
        "nvidia_ctk",
        "control_network",
        "camera_network",
        "control_network_id",
        "control_network_config_sha256",
        "camera_network_id",
        "camera_network_config_sha256",
        "acceptance_adapter_sha256",
        "acceptance_adapter_executable",
        "acceptance_adapter_policy",
        "acceptance_adapter_policy_sha256",
        "acceptance_adapter_work_root",
        "acceptance_observer_sha256",
        "acceptance_observer_executable",
        "acceptance_observer_policy",
        "acceptance_observer_policy_sha256",
        "acceptance_observer_work_root",
        "collector_state",
        "control_plane_url",
        "machine_token_file",
        "acceptance_controller_token_file",
        "out_attestation",
        "out_signature",
        "out_journal_proof",
    )
    arguments = SimpleNamespace(**{name: "x" for name in names})
    command = replay.target_command(
        arguments,  # type: ignore[arg-type]
        launch_nonce="1" * 32,
        acceptance_channel="/run/acceptance/channel",
        acceptance_source_secrets="/run/acceptance/source-secrets",
        acceptance_native_projection="/run/acceptance/native.json",
        acceptance_work_projection="/run/acceptance/work.json",
    )
    for option in (
        "--acceptance-channel",
        "--acceptance-source-secrets-root",
        "--acceptance-native-projection",
        "--acceptance-work-projection",
    ):
        assert command.count(option) == 1

    from protector.pilot.runtime import deepstream

    parsed: list[argparse.Namespace] = []
    real_parse_args = argparse.ArgumentParser.parse_args

    class ParsedOnly(RuntimeError):
        pass

    def parse_without_runtime(
        parser: argparse.ArgumentParser,
        argv: list[str] | None = None,
    ) -> argparse.Namespace:
        arguments = real_parse_args(parser, argv)
        parsed.append(arguments)
        raise ParsedOnly

    monkeypatch.setattr(
        argparse.ArgumentParser,
        "parse_args",
        parse_without_runtime,
    )
    with pytest.raises(ParsedOnly):
        deepstream.main(list(command))
    assert len(parsed) == 1
    assert parsed[0].acceptance_channel == Path(
        "/run/acceptance/channel"
    )
    assert parsed[0].acceptance_source_secrets_root == Path(
        "/run/acceptance/source-secrets"
    )
    assert parsed[0].acceptance_native_projection == Path(
        "/run/acceptance/native.json"
    )
    assert parsed[0].acceptance_work_projection == Path(
        "/run/acceptance/work.json"
    )


def test_target_cli_selects_v3_production_orchestrator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called: list[argparse.Namespace] = []
    monkeypatch.setattr(
        replay,
        "run_production_target_v3",
        lambda arguments: called.append(arguments),
    )
    monkeypatch.setattr(
        replay,
        "_parser",
        lambda: SimpleNamespace(
            parse_args=lambda _argv: argparse.Namespace(mode="target")
        ),
    )

    assert replay.main([]) == 0
    assert len(called) == 1


def test_retained_v3_uses_fresh_three_epoch_continuation_authority() -> None:
    collector_source = inspect.getsource(
        replay.RetainedRuntimeTargetV3Collector._collect
    )
    preflight_source = inspect.getsource(
        replay._run_production_target_v3_locked
    )
    replay_source = inspect.getsource(replay.run_target_v3)
    binding_source = inspect.getsource(replay.bind_target_authority_v3)
    controller_source = inspect.getsource(
        acceptance_controller
        .CollectorBoundAcceptanceControllerV3
    )

    assert replay.RETAINED_V3_RUNTIME_RESTART_AUTHORIZING is False
    assert "_advance_target_runtime_restart_v3" in collector_source
    assert "runtime = self._continuation.active_runtime" not in collector_source
    assert "docker restart" not in collector_source.lower()
    assert "len(profile_paths) != 3" in preflight_source
    assert "len(signature_paths) != 3" in preflight_source
    assert "len(launch_nonces) != 3" in preflight_source
    assert "TargetRuntimeContinuationCoordinatorV3" in preflight_source
    assert "continuation_capability" in replay_source
    assert "_require_continuation_capability" in binding_source
    assert "require_target_authority_continuation_v3" in controller_source
    assert (
        "_require_target_runtime_restart_continuation_authority"
        not in controller_source
    )


def test_production_v3_holds_the_campaign_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "collector.sqlite3"
    active = False
    observed: list[Path] = []

    class Lock:
        def __init__(self, path: Path) -> None:
            observed.append(path)

        def __enter__(self) -> None:
            nonlocal active
            active = True

        def __exit__(self, *_args: object) -> None:
            nonlocal active
            active = False

    def run_locked(_arguments: argparse.Namespace) -> dict[str, object]:
        assert active is True
        return {"accepted": True}

    monkeypatch.setattr(replay, "TargetCampaignLock", Lock)
    monkeypatch.setattr(
        replay,
        "_run_production_target_v3_locked",
        run_locked,
        raising=False,
    )

    assert replay.run_production_target_v3(
        argparse.Namespace(collector_state=state)
    ) == {"accepted": True}
    assert observed == [state.with_name(f"{state.name}.campaign.lock")]
    assert active is False


def test_controller_token_capture_closes_its_descriptor_once(
    tmp_path: Path,
) -> None:
    token_path = tmp_path / "controller.token"
    token_path.write_text("controller-token-01", encoding="utf-8")

    assert (
        acceptance_controller._read_controller_token(token_path)
        == "controller-token-01"
    )


def test_controller_app_keeps_v2_collection_and_v3_finalization_separate() -> None:
    class LegacyAuthority:
        def readiness_probe(self) -> None:
            return None

    class V3Authority:
        def readiness_probe(self) -> None:
            return None

        def finalize_collector(self, _collector_id: str) -> dict[str, object]:
            return {}

    app = acceptance_controller.create_acceptance_controller_app(
        authority=LegacyAuthority(),
        v3_authority=V3Authority(),
        controller_token="controller-token-01",
    )
    routes = {route.path for route in app.routes}

    assert "/api/internal/acceptance/start" in routes
    assert "/api/internal/acceptance/sample" in routes
    assert "/api/internal/acceptance/finalize" in routes
    assert (
        "/api/internal/acceptance/v3/collectors/{collector_id}/finalize"
        in routes
    )


def test_production_v3_uses_a_capture_root_distinct_from_channel_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture_root = tmp_path / "capture"
    channel_root = tmp_path / "channel"
    snapshot_root = tmp_path / "snapshots"
    proof_root = tmp_path / "proofs"
    capture_root.mkdir(mode=0o700)
    channel_root.mkdir(mode=0o700)
    snapshot_root.mkdir(mode=0o700)
    proof_root.mkdir(mode=0o700)
    values = {
        "PILOT_ACCEPTANCE_JOURNAL_PATH": str(tmp_path / "authority.sqlite3"),
        "PILOT_ACCEPTANCE_SNAPSHOT_DIR": str(snapshot_root),
        "PILOT_ACCEPTANCE_PROOF_DIR": str(proof_root),
        "PILOT_ACCEPTANCE_CHANNEL_DIR": str(channel_root),
        "PILOT_ACCEPTANCE_CAPTURE_DIR": str(capture_root),
    }
    legacy = SimpleNamespace(signer=object(), trust_context=object())
    observed: dict[str, object] = {}
    provider = object()
    v3_controller = object()
    result_app = object()

    monkeypatch.setattr(
        acceptance_controller,
        "build_production_acceptance_authority",
        lambda: legacy,
    )
    monkeypatch.setattr(
        acceptance_controller,
        "_required_environment",
        values.__getitem__,
    )

    def capture_provider(root: Path, *, trust_context: object) -> object:
        observed["capture_root"] = root
        observed["trust_context"] = trust_context
        return provider

    monkeypatch.setattr(
        acceptance_controller,
        "ProtectedAcceptanceCaptureRepositoryV3",
        capture_provider,
    )
    monkeypatch.setattr(
        acceptance_controller,
        "AcceptanceAuthoritySnapshotStoreV3",
        lambda path: ("snapshot", path),
    )
    monkeypatch.setattr(
        acceptance_controller,
        "AcceptanceProofStoreV3",
        lambda path: ("proof", path),
    )
    monkeypatch.setattr(
        acceptance_controller,
        "AcceptanceAuthorityStateStoreV3",
        lambda path: ("state", path),
    )
    monkeypatch.setattr(
        acceptance_controller,
        "AcceptanceAuthorityV3",
        lambda **kwargs: ("authority", kwargs),
    )
    monkeypatch.setattr(
        acceptance_controller,
        "CollectorBoundAcceptanceControllerV3",
        lambda **_kwargs: v3_controller,
    )
    monkeypatch.setattr(
        acceptance_controller,
        "_read_controller_token",
        lambda: "controller-token-01",
    )

    def create_combined_app(**kwargs: object) -> object:
        observed["app_kwargs"] = kwargs
        return result_app

    monkeypatch.setattr(
        acceptance_controller,
        "create_acceptance_controller_app",
        create_combined_app,
    )

    assert (
        acceptance_controller.create_production_acceptance_controller_v3_app()
        is result_app
    )
    assert observed["capture_root"] == capture_root
    assert observed["capture_root"] != channel_root
    assert observed["app_kwargs"] == {
        "authority": legacy,
        "v3_authority": v3_controller,
        "controller_token": "controller-token-01",
        "runtime_lock_path": "/tmp/kuzet-acceptance-controller-v3.lock",
    }
