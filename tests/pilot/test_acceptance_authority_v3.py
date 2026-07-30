from __future__ import annotations

import hashlib
import sqlite3
import threading
from pathlib import Path

import pytest

import protector.pilot.acceptance_authority_v3 as authority_module
from protector.pilot.acceptance_authority_v3 import (
    AcceptanceAuthorityStateStoreV3,
    AcceptanceAuthorityV3,
    AcceptanceDecisionV3,
    AcceptanceRunStateV3,
)
from tests.pilot.test_acceptance_snapshot import _snapshot


class _Signer:
    def __init__(self) -> None:
        self.payloads: list[bytes] = []

    def sign(self, payload: bytes) -> bytes:
        self.payloads.append(payload)
        return hashlib.sha512(payload).digest()


def test_state_store_enforces_durable_cas_order_and_idempotent_concurrent_retry(
    tmp_path: Path,
) -> None:
    path = tmp_path / "authority.sqlite3"
    store = AcceptanceAuthorityStateStoreV3(path)
    snapshot = _snapshot(tmp_path / "fixture")

    records = []

    def begin() -> None:
        records.append(store.begin(snapshot.collector_id))

    threads = [threading.Thread(target=begin) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(records) == 8
    assert {record.state for record in records} == {AcceptanceRunStateV3.RUNNING}
    committed = store.commit_snapshot(snapshot)
    assert committed.state is AcceptanceRunStateV3.SNAPSHOT_COMMITTED
    assert store.commit_snapshot(snapshot) == committed

    with pytest.raises(RuntimeError, match="state|CAS|transition"):
        store.mark_proof_published(snapshot.collector_id, "a" * 64)


def test_authority_recovers_evaluation_and_never_mints_pass_attestation_for_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _snapshot(tmp_path / "fixture")
    state = AcceptanceAuthorityStateStoreV3(tmp_path / "authority.sqlite3")
    evidence_signer = _Signer()
    pass_signer = _Signer()
    authority = AcceptanceAuthorityV3(
        state_store=state,
        run_evidence_signer=evidence_signer,
        acceptance_pass_signer=pass_signer,
    )
    calls = 0

    def failed(_snapshot: object):
        nonlocal calls
        calls += 1
        return authority_module.AcceptanceEvaluationBundleV3.model_validate(
            {
                "schema_version": "acceptance-evaluation-bundle.v3",
                "snapshot_sha256": snapshot.snapshot_sha256,
                "c2_authorized": True,
                "standard": {
                    "schema_version": "acceptance-evaluator-outcome.v3",
                    "evaluator": snapshot.standard_evaluator,
                    "status": "fail",
                    "passed": False,
                    "reasons": ("standard failed",),
                    "result_sha256": "1" * 64,
                },
                "operational": {
                    "schema_version": "acceptance-evaluator-outcome.v3",
                    "evaluator": snapshot.operational_evaluator,
                    "status": "pass",
                    "passed": True,
                    "reasons": (),
                    "result_sha256": "2" * 64,
                },
                "accepted": False,
            }
        )

    monkeypatch.setattr(authority_module, "run_dual_evaluation_v3", failed)
    first = authority.evaluate_and_finalize(snapshot)
    second = authority.evaluate_and_finalize(snapshot)

    assert first == second
    assert calls == 1
    assert first.decision.accepted is False
    assert len(evidence_signer.payloads) == 1
    assert pass_signer.payloads == []
    assert state.load(snapshot.collector_id).state is AcceptanceRunStateV3.FINALIZED

    authority.mark_proof_published(snapshot.collector_id, "3" * 64)
    assert authority.attest(snapshot.collector_id) is None
    assert pass_signer.payloads == []
    assert state.load(snapshot.collector_id).state is AcceptanceRunStateV3.ATTESTED


def test_decision_cannot_be_supplied_by_caller_and_corrupt_database_fails_closed(
    tmp_path: Path,
) -> None:
    snapshot = _snapshot(tmp_path / "fixture")
    evidence_signer = _Signer()
    pass_signer = _Signer()
    authority = AcceptanceAuthorityV3(
        state_store=AcceptanceAuthorityStateStoreV3(tmp_path / "authority.sqlite3"),
        run_evidence_signer=evidence_signer,
        acceptance_pass_signer=pass_signer,
    )
    with pytest.raises(TypeError):
        authority.evaluate_and_finalize(
            snapshot,
            candidate=AcceptanceDecisionV3.model_construct(accepted=True),  # type: ignore[call-arg]
        )

    corrupt = tmp_path / "corrupt.sqlite3"
    corrupt.write_bytes(b"not a sqlite database")
    with pytest.raises(RuntimeError, match="database|corrupt|invalid"):
        AcceptanceAuthorityStateStoreV3(corrupt)

    authority.state_store.begin(snapshot.collector_id)
    connection = sqlite3.connect(tmp_path / "authority.sqlite3")
    try:
        connection.execute(
            "UPDATE acceptance_authority_v3_runs SET state = 'ATTESTED', "
            "pass_attestation_json = NULL"
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(RuntimeError, match="invariant|state|invalid"):
        authority.state_store.load(snapshot.collector_id)
