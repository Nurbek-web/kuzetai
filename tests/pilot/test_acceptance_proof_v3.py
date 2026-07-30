from __future__ import annotations

import hashlib
import json

import pytest

from protector.pilot.acceptance_proof_v3 import (
    AcceptanceJournalProofV3,
    build_acceptance_journal_proof_v3,
    canonical_acceptance_proof_v3,
    verify_acceptance_journal_proof_v3,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


@pytest.mark.parametrize(
    ("gate", "entries", "lines"),
    (("8h", 534, 536), ("72h", 4_374, 4_376)),
)
def test_v3_proof_has_exact_inventory_order_and_line_count(
    gate: str,
    entries: int,
    lines: int,
) -> None:
    proof = build_acceptance_journal_proof_v3(
        collector_id="collector-01",
        site_id="school-01",
        gate=gate,
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
    )

    assert len(verified.entries) == entries
    assert len(payload.splitlines()) == lines
    assert tuple(item.kind for item in verified.entries[-4:]) == (
        "authority_snapshot",
        "standard_evaluation",
        "operational_evaluation",
        "final_decision",
    )


def test_v3_proof_rejects_substitution_reorder_and_count_even_with_canonical_json() -> None:
    proof = build_acceptance_journal_proof_v3(
        collector_id="collector-01",
        site_id="school-01",
        gate="8h",
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
