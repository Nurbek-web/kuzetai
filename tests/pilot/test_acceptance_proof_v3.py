from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from protector.pilot.acceptance_proof import AcceptanceFinalEnvelopeV2
from protector.pilot.acceptance_proof_v3 import (
    AcceptanceJournalProofV3,
    build_acceptance_journal_proof_v3,
    canonical_acceptance_proof_v3,
    verify_acceptance_journal_proof_v3,
)
from tests.pilot.acceptance_trust_helpers import authority_trust_context
from tests.pilot.test_acceptance_report import (
    _manifest,
    _run,
    _write_bound_journal_proof,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _bound_v2(
    tmp_path: Path,
    *,
    gate: str,
) -> tuple[Path, AcceptanceFinalEnvelopeV2]:
    manifest = _manifest(tmp_path)
    run = _run(manifest, hours=8 if gate == "8h" else 72)
    trust = authority_trust_context(tmp_path, manifest).trust
    proof_path = tmp_path / "v2-proof.jsonl"
    attestation = _write_bound_journal_proof(
        proof_path,
        run=run,
        trust=trust,
    )
    return proof_path, AcceptanceFinalEnvelopeV2(
        record=run,
        attestation=attestation,
        signature_hex="0" * 128,
    )


@pytest.mark.parametrize(
    ("gate", "entries", "lines"),
    (("8h", 534, 536), ("72h", 4_374, 4_376)),
)
def test_v3_proof_has_exact_inventory_order_and_line_count(
    tmp_path: Path,
    gate: str,
    entries: int,
    lines: int,
) -> None:
    proof_path, envelope = _bound_v2(tmp_path, gate=gate)
    proof = build_acceptance_journal_proof_v3(
        v2_journal_proof_path=proof_path,
        v2_final_envelope=envelope,
        snapshot_sha256=_digest("snapshot"),
        standard_evaluation_sha256=_digest("standard"),
        operational_evaluation_sha256=_digest("operational"),
        final_decision_sha256=_digest("decision"),
    )
    payload = canonical_acceptance_proof_v3(proof)
    verified = verify_acceptance_journal_proof_v3(
        payload,
        expected_snapshot_sha256=_digest("snapshot"),
        expected_standard_evaluation_sha256=_digest("standard"),
        expected_operational_evaluation_sha256=_digest("operational"),
        expected_final_decision_sha256=_digest("decision"),
        expected_v2_run_record_sha256=proof.header.v2_run_record_sha256,
        expected_v2_run_attestation_sha256=(
            proof.header.v2_run_attestation_sha256
        ),
        expected_v2_journal_proof_sha256=(
            proof.header.v2_journal_proof_sha256
        ),
        expected_v2_journal_root_sha256=proof.header.v2_journal_root_sha256,
    )

    assert len(verified.entries) == entries
    assert len(payload.splitlines()) == lines
    assert tuple(item.kind for item in verified.entries[-4:]) == (
        "authority_snapshot",
        "standard_evaluation",
        "operational_evaluation",
        "final_decision",
    )


def test_v3_proof_rejects_substitution_reorder_and_count_even_with_canonical_json(
    tmp_path: Path,
) -> None:
    proof_path, envelope = _bound_v2(tmp_path, gate="8h")
    proof = build_acceptance_journal_proof_v3(
        v2_journal_proof_path=proof_path,
        v2_final_envelope=envelope,
        snapshot_sha256=_digest("snapshot"),
        standard_evaluation_sha256=_digest("standard"),
        operational_evaluation_sha256=_digest("operational"),
        final_decision_sha256=_digest("decision"),
    )
    payload = canonical_acceptance_proof_v3(proof)
    lines = payload.splitlines()

    substituted = json.loads(lines[-5])
    substituted["payload_sha256"] = _digest("substitute")
    lines[-5] = json.dumps(
        substituted,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    with pytest.raises(ValueError, match="snapshot|chain|substitution|digest"):
        verify_acceptance_journal_proof_v3(
            b"\n".join(lines) + b"\n",
            expected_snapshot_sha256=_digest("snapshot"),
            expected_standard_evaluation_sha256=_digest("standard"),
            expected_operational_evaluation_sha256=_digest("operational"),
            expected_final_decision_sha256=_digest("decision"),
            expected_v2_run_record_sha256=proof.header.v2_run_record_sha256,
            expected_v2_run_attestation_sha256=(
                proof.header.v2_run_attestation_sha256
            ),
            expected_v2_journal_proof_sha256=(
                proof.header.v2_journal_proof_sha256
            ),
            expected_v2_journal_root_sha256=(
                proof.header.v2_journal_root_sha256
            ),
        )

    reordered = list(proof.entries)
    reordered[-3], reordered[-2] = reordered[-2], reordered[-3]
    with pytest.raises(ValueError, match="order|chain|inventory"):
        AcceptanceJournalProofV3(
            header=proof.header,
            entries=tuple(reordered),
            trailer=proof.trailer,
        )

    with pytest.raises(ValueError, match="count|inventory"):
        AcceptanceJournalProofV3(
            header=proof.header,
            entries=proof.entries[:-1],
            trailer=proof.trailer,
        )
