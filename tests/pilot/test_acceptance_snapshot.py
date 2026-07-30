from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from protector.pilot.acceptance import AcceptanceRunRecordV2
from protector.pilot.acceptance_operational import (
    AcceptanceLimitsV1,
    AuthoritativeRepositoryBoundaryV1,
    OperationalAcceptanceEvidenceV1,
)
from protector.pilot.acceptance_snapshot import (
    MAX_ACCEPTANCE_SNAPSHOT_BYTES,
    AcceptanceAuthoritySnapshotStoreV3,
    AcceptanceAuthoritySnapshotV3,
    TargetAuthorityBindingV3,
    build_acceptance_authority_snapshot_v3,
    expected_evaluator_identities_v3,
)
from tests.pilot.test_acceptance_operational import (
    _evidence_payload,
    _json_bytes,
    _limits_payload,
    _repository_boundary_payload,
)
from tests.pilot.test_acceptance_report import _manifest, _run


def _target_binding() -> TargetAuthorityBindingV3:
    digests = tuple(
        hashlib.sha256(f"target-binding-{index}".encode()).hexdigest() for index in range(8)
    )
    return TargetAuthorityBindingV3(
        schema_version="target-authority-binding.v3",
        authorized=True,
        runtime_identity_sha256=digests[0],
        gpu_inventory_sha256=digests[1],
        source_profile_sha256=digests[2],
        native_prewarm_sha256=digests[3],
        unique_work_sha256=digests[4],
        completion_sha256=digests[5],
        journal_proof_sha256=digests[6],
        authority_receipt_sha256=digests[7],
    )


def _snapshot(tmp_path: Path, *, c2_authorized: bool = True) -> AcceptanceAuthoritySnapshotV3:
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
    target = _target_binding().model_copy(update={"authorized": c2_authorized})
    return build_acceptance_authority_snapshot_v3(
        collector_id=run.run_id,
        campaign_id="campaign-2026-07",
        offline_root_spki_sha256="1" * 64,
        policy_id="policy-01",
        policy_sha256="2" * 64,
        manifest_payload_sha256="3" * 64,
        controller_image_sha256="4" * 64,
        controller_code_sha256="5" * 64,
        target_authority=target,
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
            target_authority=snapshot.target_authority,
            manifest=snapshot.manifest,
            run_record=malformed,
            operational_limits=snapshot.operational_limits,
            operational_evidence=snapshot.operational_evidence,
            repository_boundary=snapshot.repository_boundary,
            conditional_gate_decisions=(),
        )


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
