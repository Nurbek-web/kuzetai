from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from protector.pilot.acceptance import AcceptanceRunRecordV2
from protector.pilot.acceptance_c2 import (
    SignedTargetAuthorityBindingV3,
    TargetAuthorityBindingV3,
    TargetC2ContinuationEvidenceV3,
    TargetC2EvidenceV3,
    TargetEpochEvidenceV3,
    TargetExecutionTransitionEntryV3,
    TargetExecutionTransitionJournalV3,
    _aggregate,
    _sha,
)
from protector.pilot.acceptance_operational import (
    AcceptanceLimitsV1,
    AuthoritativeRepositoryBoundaryV1,
    OperationalAcceptanceEvidenceV1,
)
from protector.pilot.acceptance_snapshot import (
    MAX_ACCEPTANCE_SNAPSHOT_BYTES,
    AcceptanceAuthoritySnapshotStoreV3,
    AcceptanceAuthoritySnapshotV3,
    build_acceptance_authority_snapshot_v3,
    expected_evaluator_identities_v3,
)
from protector.pilot.acceptance_trust import canonical_json_bytes
from tests.pilot.test_acceptance_operational import (
    _evidence_payload,
    _json_bytes,
    _limits_payload,
    _repository_boundary_payload,
)
from tests.pilot.test_acceptance_report import _manifest, _run
from tests.pilot.test_acceptance_restart_continuation_contract import (
    _execution,
)
from tests.pilot.acceptance_trust_helpers import authority_trust_context


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _continuation(
    c2: TargetC2EvidenceV3,
) -> TargetC2ContinuationEvidenceV3:
    previous_execution = _execution(2)
    continuation_execution = _execution(3)
    previous = c2.epochs[-1]
    started = previous.measurement_completed_monotonic_ns + 1
    continuation_epoch = TargetEpochEvidenceV3(
        schema_version="target-epoch-evidence.v3",
        collector_id=c2.collector_id,
        site_id=c2.site_id,
        campaign_id=c2.campaign_id,
        gate=c2.gate,
        runtime_epoch=3,
        runtime_epoch_started_generation=3,
        launch_nonce=continuation_execution.launch_nonce,
        container_id=continuation_execution.container_id,
        launch_request_sha256=_digest("launch-3"),
        runtime_identity_sha256=_digest("runtime-3"),
        gpu_inventory_sha256=_digest("gpu-3"),
        source_profile_sha256=_digest("source-3"),
        native_prewarm_sha256=_digest("prewarm-3"),
        unique_work_plan_sha256=_digest("plan-3"),
        unique_work_sha256=_digest("work-3"),
        completion_sha256=_digest("completion-3"),
        runtime_epoch_started_monotonic_ns=started,
        identity_observed_monotonic_ns=started + 1,
        prewarm_ready_at_monotonic_ns=started + 60_000_000_000,
        measurement_started_monotonic_ns=started + 60_000_000_001,
        measurement_completed_monotonic_ns=started + 120_000_000_001,
        disposition="authorize",
        analytics_publication_enabled_during_gate=False,
    )
    common = {
        "schema_version": "target-execution-transition-entry.v3",
        "collector_id": c2.collector_id,
        "site_id": c2.site_id,
        "campaign_id": c2.campaign_id,
        "gate": c2.gate,
        "runtime_restart_fault_id": "fault-03-runtime-restart",
        "base_c2_evidence_sha256": c2.evidence_sha256,
        "previous_epoch_sha256": previous.epoch_sha256,
        "previous_execution_binding_sha256": (
            previous_execution.binding_sha256
        ),
        "previous_runtime_identity_sha256": (
            previous.runtime_identity_sha256
        ),
        "continuation_launch_request_sha256": (
            continuation_epoch.launch_request_sha256
        ),
        "continuation_launch_nonce": continuation_epoch.launch_nonce,
        "continuation_runtime_epoch": 3,
    }
    requested = TargetExecutionTransitionEntryV3(
        **common,
        sequence=1,
        phase="requested",
        previous_entry_sha256="0" * 64,
        recorded_monotonic_ns=1,
    )
    compatibility_boot = (
        f"{previous_execution.launch_nonce}.container-"
        f"{continuation_execution.container_id[:32]}"
    )
    runtime_fields = {
        "continuation_execution_binding_sha256": (
            continuation_execution.binding_sha256
        ),
        "continuation_runtime_identity_sha256": (
            continuation_epoch.runtime_identity_sha256
        ),
        "continuation_runtime_boot_id": (
            f"container:{continuation_execution.container_id}"
        ),
        "v2_compatibility_runtime_boot_id": compatibility_boot,
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
        unique_work_plan_sha256=continuation_epoch.unique_work_plan_sha256,
        unique_work_sha256=continuation_epoch.unique_work_sha256,
        completion_sha256=continuation_epoch.completion_sha256,
        previous_entry_sha256=observed.entry_sha256,
        recorded_monotonic_ns=3,
    )
    return TargetC2ContinuationEvidenceV3(
        schema_version="target-c2-continuation-evidence.v3",
        base_c2=c2,
        runtime_restart_fault_id="fault-03-runtime-restart",
        injected_monotonic_offset_seconds=40.0,
        recovered_monotonic_offset_seconds=43.0,
        previous_execution=previous_execution,
        continuation_execution=continuation_execution,
        continuation_epoch=continuation_epoch,
        continuation_runtime_boot_id=runtime_fields[
            "continuation_runtime_boot_id"
        ],
        v2_compatibility_runtime_boot_id=compatibility_boot,
        transition_journal=TargetExecutionTransitionJournalV3(
            schema_version="target-execution-transition-journal.v3",
            entries=(requested, observed, authorized),
        ),
    )


def _target_binding(run: AcceptanceRunRecordV2) -> TargetAuthorityBindingV3:
    epochs = tuple(
        TargetEpochEvidenceV3(
            schema_version="target-epoch-evidence.v3",
            collector_id=run.run_id,
            site_id=run.site_id,
            campaign_id="campaign-2026-07",
            gate="8h",
            runtime_epoch=index,
            runtime_epoch_started_generation=index,
            launch_nonce=f"{index:032x}",
            container_id=f"{index:x}" * 64,
            launch_request_sha256=_digest(f"launch-{index}"),
            runtime_identity_sha256=_digest(f"runtime-{index}"),
            gpu_inventory_sha256=_digest(f"gpu-{index}"),
            source_profile_sha256=_digest(f"source-{index}"),
            native_prewarm_sha256=_digest(f"prewarm-{index}"),
            unique_work_plan_sha256=_digest(f"plan-{index}"),
            unique_work_sha256=_digest(f"work-{index}"),
            completion_sha256=_digest(f"completion-{index}"),
            runtime_epoch_started_monotonic_ns=(index - 1) * 200_000_000_000
            + 1_000_000_000,
            identity_observed_monotonic_ns=(index - 1) * 200_000_000_000
            + 3_000_000_000,
            prewarm_ready_at_monotonic_ns=(index - 1) * 200_000_000_000
            + 61_000_000_000,
            measurement_started_monotonic_ns=(index - 1) * 200_000_000_000
            + 61_000_000_000,
            measurement_completed_monotonic_ns=(index - 1) * 200_000_000_000
            + 121_000_000_000,
            disposition="restart" if index == 1 else "authorize",
            analytics_publication_enabled_during_gate=False,
        )
        for index in (1, 2)
    )
    c2 = TargetC2EvidenceV3(
        schema_version="target-c2-evidence.v3",
        collector_id=run.run_id,
        site_id=run.site_id,
        campaign_id="campaign-2026-07",
        gate="8h",
        epochs=epochs,
    )
    continuation = _continuation(c2)
    run_sha256 = hashlib.sha256(canonical_json_bytes(run)).hexdigest()
    attestation_sha256 = _digest("v2-attestation")
    proof_sha256 = _digest("v2-proof")
    root_sha256 = _digest("v2-root")
    epoch_chain_sha256 = _sha(
        {
            "schema_version": "target-epoch-chain.v3",
            "epoch_sha256": [epoch.epoch_sha256 for epoch in epochs],
        }
    )
    receipt_sha256 = _sha(
        {
            "schema_version": "target-authority-receipt.v3",
            "c2_evidence_sha256": c2.evidence_sha256,
            "c2_continuation_sha256": continuation.evidence_sha256,
            "execution_transition_journal_root_sha256": (
                continuation.transition_journal.journal_root_sha256
            ),
            "v2_run_record_sha256": run_sha256,
            "v2_run_attestation_sha256": attestation_sha256,
            "v2_journal_proof_sha256": proof_sha256,
            "v2_journal_root_sha256": root_sha256,
        }
    )
    aggregates = {
        field: _aggregate(epochs, field)
        for field in (
            "runtime_identity_sha256",
            "gpu_inventory_sha256",
            "source_profile_sha256",
            "native_prewarm_sha256",
            "unique_work_sha256",
            "completion_sha256",
        )
    }
    return TargetAuthorityBindingV3(
        schema_version="target-authority-binding.v3",
        authorized=True,
        collector_id=run.run_id,
        site_id=run.site_id,
        campaign_id="campaign-2026-07",
        gate="8h",
        epochs=epochs,
        **aggregates,
        c2_evidence_sha256=c2.evidence_sha256,
        epoch_chain_sha256=epoch_chain_sha256,
        c2_continuation=continuation,
        c2_continuation_sha256=continuation.evidence_sha256,
        execution_transition_journal_root_sha256=(
            continuation.transition_journal.journal_root_sha256
        ),
        journal_proof_sha256=proof_sha256,
        v2_run_record_sha256=run_sha256,
        v2_run_attestation_sha256=attestation_sha256,
        v2_journal_root_sha256=root_sha256,
        authority_receipt_sha256=receipt_sha256,
        cross_artifact_root_sha256=_sha(
            {
                "schema_version": "target-v2-cross-artifact-root.v3",
                "c2_evidence_sha256": c2.evidence_sha256,
                "c2_continuation_sha256": continuation.evidence_sha256,
                "execution_transition_journal_root_sha256": (
                    continuation.transition_journal.journal_root_sha256
                ),
                "continuation_execution_binding_sha256": (
                    continuation.continuation_execution.binding_sha256
                ),
                "v2_compatibility_runtime_boot_id": (
                    continuation.v2_compatibility_runtime_boot_id
                ),
                "epoch_chain_sha256": epoch_chain_sha256,
                **aggregates,
                "v2_run_record_sha256": run_sha256,
                "v2_run_attestation_sha256": attestation_sha256,
                "v2_journal_proof_sha256": proof_sha256,
                "v2_journal_root_sha256": root_sha256,
                "authority_receipt_sha256": receipt_sha256,
            }
        ),
    )


def _snapshot(tmp_path: Path) -> AcceptanceAuthoritySnapshotV3:
    (tmp_path / "manifest").mkdir(parents=True)
    manifest = _manifest(tmp_path / "manifest")
    run_payload = _run(manifest, hours=8).model_dump(mode="python", round_trip=True)
    run_payload["gate"] = "8h"
    run = AcceptanceRunRecordV2.model_validate(run_payload)

    limits_payload = _limits_payload()
    evidence_payload = _evidence_payload()
    for payload in (limits_payload, evidence_payload):
        payload["site_id"] = manifest.site_id
        payload["manifest_sha256"] = manifest.manifest_sha256
    limits = AcceptanceLimitsV1.model_validate_json(_json_bytes(limits_payload))
    evidence = OperationalAcceptanceEvidenceV1.model_validate_json(_json_bytes(evidence_payload))
    boundary = AuthoritativeRepositoryBoundaryV1.model_validate_json(
        _json_bytes(_repository_boundary_payload(evidence_payload))
    )
    target = _target_binding(run)
    context = authority_trust_context(tmp_path / "manifest", manifest)
    payload_path = tmp_path / "manifest" / "signed-target.json"
    signature_path = tmp_path / "manifest" / "signed-target.sig"
    payload_path.write_bytes(canonical_json_bytes(target))
    subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(tmp_path / "manifest" / "target-run-private.pem"),
            "-in",
            str(payload_path),
            "-out",
            str(signature_path),
        ],
        check=True,
        capture_output=True,
    )
    signed_target = SignedTargetAuthorityBindingV3(
        schema_version="signed-target-authority-binding.v3",
        binding=target,
        public_key_spki_sha256=context.trust.policy.roles.run_spki_sha256,
        signature_hex=signature_path.read_bytes().hex(),
    )
    return build_acceptance_authority_snapshot_v3(
        collector_id=run.run_id,
        campaign_id="campaign-2026-07",
        offline_root_spki_sha256=context.trust.root_spki_sha256,
        policy_id=context.trust.policy.policy_id,
        policy_sha256=context.trust.policy_sha256,
        manifest_payload_sha256=context.trust.manifest_payload_sha256,
        controller_image_sha256="4" * 64,
        controller_code_sha256="5" * 64,
        signed_target_authority=signed_target,
        trust_context=context,
        manifest=manifest,
        run_record=run,
        operational_limits=limits,
        operational_evidence=evidence,
        repository_boundary=boundary,
        conditional_gate_decisions=(),
    )


def test_snapshot_reconstructs_every_nested_authority_input_and_binds_exact_identities(
    tmp_path: Path,
) -> None:
    snapshot = _snapshot(tmp_path)

    assert snapshot.run_record.run_id == snapshot.collector_id
    assert snapshot.run_record_sha256 == hashlib.sha256(snapshot.canonical_run_record).hexdigest()
    assert snapshot.manifest_sha256 == snapshot.manifest.manifest_sha256
    assert (
        snapshot.standard_evaluator,
        snapshot.operational_evaluator,
    ) == expected_evaluator_identities_v3()

    malformed = AcceptanceRunRecordV2.model_construct(
        **{
            **{
                field_name: getattr(snapshot.run_record, field_name)
                for field_name in AcceptanceRunRecordV2.model_fields
            },
            "environment": "test_only",
        }
    )
    with pytest.raises(
        (ValidationError, ValueError),
        match="target|execution|snapshot|reconstructed",
    ):
        build_acceptance_authority_snapshot_v3(
            collector_id=snapshot.collector_id,
            campaign_id=snapshot.campaign_id,
            offline_root_spki_sha256=snapshot.offline_root_spki_sha256,
            policy_id=snapshot.policy_id,
            policy_sha256=snapshot.policy_sha256,
            manifest_payload_sha256=snapshot.manifest_payload_sha256,
            controller_image_sha256=snapshot.controller_image_sha256,
            controller_code_sha256=snapshot.controller_code_sha256,
            signed_target_authority=snapshot.signed_target_authority,
            trust_context=authority_trust_context(
                tmp_path / "manifest",
                snapshot.manifest,
            ),
            manifest=snapshot.manifest,
            run_record=malformed,
            operational_limits=snapshot.operational_limits,
            operational_evidence=snapshot.operational_evidence,
            repository_boundary=snapshot.repository_boundary,
            conditional_gate_decisions=(),
        )


def test_snapshot_builder_rejects_caller_forged_signed_authority(
    tmp_path: Path,
) -> None:
    snapshot = _snapshot(tmp_path)
    with pytest.raises(ValueError, match="signature|target authority"):
        build_acceptance_authority_snapshot_v3(
            collector_id=snapshot.collector_id,
            campaign_id=snapshot.campaign_id,
            offline_root_spki_sha256=snapshot.offline_root_spki_sha256,
            policy_id=snapshot.policy_id,
            policy_sha256=snapshot.policy_sha256,
            manifest_payload_sha256=snapshot.manifest_payload_sha256,
            controller_image_sha256=snapshot.controller_image_sha256,
            controller_code_sha256=snapshot.controller_code_sha256,
            signed_target_authority=snapshot.signed_target_authority.model_copy(
                update={"signature_hex": "0" * 128}
            ),
            trust_context=authority_trust_context(
                tmp_path / "manifest",
                snapshot.manifest,
            ),
            manifest=snapshot.manifest,
            run_record=snapshot.run_record,
            operational_limits=snapshot.operational_limits,
            operational_evidence=snapshot.operational_evidence,
            repository_boundary=snapshot.repository_boundary,
            conditional_gate_decisions=(),
        )


def test_c2_process_online_deadline_is_distinct_from_native_prewarm() -> None:
    epoch = TargetEpochEvidenceV3(
        schema_version="target-epoch-evidence.v3",
        collector_id="collector-01",
        site_id="school-01",
        campaign_id="campaign-01",
        gate="8h",
        runtime_epoch=1,
        runtime_epoch_started_generation=1,
        launch_nonce="1" * 32,
        container_id=_digest("container"),
        launch_request_sha256=_digest("launch"),
        runtime_identity_sha256=_digest("runtime"),
        gpu_inventory_sha256=_digest("gpu"),
        source_profile_sha256=_digest("source"),
        native_prewarm_sha256=_digest("prewarm"),
        unique_work_plan_sha256=_digest("plan"),
        unique_work_sha256=_digest("work"),
        completion_sha256=_digest("completion"),
        runtime_epoch_started_monotonic_ns=0,
        identity_observed_monotonic_ns=3_000_000_000,
        prewarm_ready_at_monotonic_ns=60_000_000_000,
        measurement_started_monotonic_ns=60_000_000_000,
        measurement_completed_monotonic_ns=120_000_000_000,
        disposition="restart",
        analytics_publication_enabled_during_gate=False,
    )
    assert (
        epoch.prewarm_ready_at_monotonic_ns
        - epoch.runtime_epoch_started_monotonic_ns
        >= 60_000_000_000
    )
    invalid = epoch.model_dump(mode="python")
    invalid["identity_observed_monotonic_ns"] = 3_000_000_001
    with pytest.raises(ValidationError, match="ordering"):
        TargetEpochEvidenceV3.model_validate(invalid)


def test_snapshot_store_is_canonical_bounded_no_replace_and_crash_idempotent(
    tmp_path: Path,
) -> None:
    root = tmp_path / "snapshots"
    root.mkdir(mode=0o700)
    snapshot = _snapshot(tmp_path / "fixture")
    store = AcceptanceAuthoritySnapshotStoreV3(root)

    first = store.publish(snapshot)
    assert first.byte_size <= MAX_ACCEPTANCE_SNAPSHOT_BYTES
    assert first.path.read_bytes() == snapshot.canonical_bytes
    assert store.publish(snapshot) == first
    assert store.load_exact(snapshot.collector_id, snapshot.snapshot_sha256) == snapshot

    replacement = snapshot.model_copy(update={"controller_code_sha256": "f" * 64})
    with pytest.raises(RuntimeError, match="differs|replace"):
        store.publish(replacement)
    assert first.path.read_bytes() == snapshot.canonical_bytes

    pending_name = store.pending_name(snapshot.collector_id)
    first.path.unlink()
    os.link(first.path.parent / pending_name, first.path) if False else None
    (root / pending_name).write_bytes(snapshot.canonical_bytes)
    (root / pending_name).chmod(0o600)
    recovered = store.publish(snapshot)
    assert recovered.sha256 == snapshot.snapshot_sha256
    assert not (root / pending_name).exists()


def test_snapshot_store_rejects_symlink_noncanonical_secret_and_oversize(
    tmp_path: Path,
) -> None:
    root = tmp_path / "snapshots"
    root.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.mkdir()
    root.rmdir()
    root.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        AcceptanceAuthoritySnapshotStoreV3(root)

    snapshot = _snapshot(tmp_path / "fixture")
    payload = json.loads(snapshot.canonical_bytes)
    payload["password"] = "do-not-store"
    with pytest.raises(ValueError, match="secret|canonical|field"):
        AcceptanceAuthoritySnapshotV3.model_validate_json(
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            strict=True,
        )

    real_root = tmp_path / "real-snapshots"
    real_root.mkdir(mode=0o700)
    store = AcceptanceAuthoritySnapshotStoreV3(real_root)
    pending = real_root / store.pending_name(snapshot.collector_id)
    pending.write_bytes(b"x" * (MAX_ACCEPTANCE_SNAPSHOT_BYTES + 1))
    pending.chmod(0o600)
    with pytest.raises(RuntimeError, match="bounded|differs|oversize"):
        store.publish(snapshot)
