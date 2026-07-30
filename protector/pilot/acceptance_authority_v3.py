"""Durable V3 acceptance finalization without caller-supplied decisions."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from protector.pilot.acceptance_evaluation import (
    AcceptanceEvaluationBundleV3,
    run_dual_evaluation_v3,
)
from protector.pilot.acceptance_snapshot import AcceptanceAuthoritySnapshotV3
from protector.pilot.acceptance_trust import canonical_json_bytes

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
BoundedId = Annotated[str, Field(min_length=1, max_length=160)]


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class AcceptanceRunStateV3(StrEnum):
    RUNNING = "RUNNING"
    SNAPSHOT_COMMITTED = "SNAPSHOT_COMMITTED"
    EVALUATED = "EVALUATED"
    FINALIZED = "FINALIZED"
    PROOF_PUBLISHED = "PROOF_PUBLISHED"
    ATTESTED = "ATTESTED"


_STATE_RANK = {
    state: index
    for index, state in enumerate(
        (
            AcceptanceRunStateV3.RUNNING,
            AcceptanceRunStateV3.SNAPSHOT_COMMITTED,
            AcceptanceRunStateV3.EVALUATED,
            AcceptanceRunStateV3.FINALIZED,
            AcceptanceRunStateV3.PROOF_PUBLISHED,
            AcceptanceRunStateV3.ATTESTED,
        )
    )
}


class AcceptanceDecisionV3(_StrictFrozenModel):
    schema_version: Literal["acceptance-final-decision.v3"]
    collector_id: BoundedId
    snapshot_sha256: Digest
    evaluation_sha256: Digest
    standard_outcome_sha256: Digest
    operational_outcome_sha256: Digest
    c2_authorized: bool
    accepted: bool

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self)

    @property
    def decision_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()


class RunEvidenceAttestationV3(_StrictFrozenModel):
    schema_version: Literal["run-evidence-attestation.v3"]
    collector_id: BoundedId
    snapshot_sha256: Digest
    evaluation_sha256: Digest
    final_decision_sha256: Digest
    accepted: bool


class SignedRunEvidenceAttestationV3(_StrictFrozenModel):
    schema_version: Literal["signed-run-evidence-attestation.v3"]
    payload: RunEvidenceAttestationV3
    signature_hex: Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]


class AcceptancePassAttestationV3(_StrictFrozenModel):
    schema_version: Literal["acceptance-pass-attestation.v3"]
    collector_id: BoundedId
    snapshot_sha256: Digest
    evaluation_sha256: Digest
    final_decision_sha256: Digest
    proof_sha256: Digest
    accepted: Literal[True]


class SignedAcceptancePassAttestationV3(_StrictFrozenModel):
    schema_version: Literal["signed-acceptance-pass-attestation.v3"]
    payload: AcceptancePassAttestationV3
    signature_hex: Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]


class AcceptanceFinalizationV3(_StrictFrozenModel):
    schema_version: Literal["acceptance-finalization.v3"]
    evaluation: AcceptanceEvaluationBundleV3
    decision: AcceptanceDecisionV3
    run_evidence_attestation: SignedRunEvidenceAttestationV3

    @model_validator(mode="after")
    def graph_is_exact(self) -> AcceptanceFinalizationV3:
        if (
            self.decision.snapshot_sha256 != self.evaluation.snapshot_sha256
            or self.decision.evaluation_sha256 != self.evaluation.evaluation_sha256
            or self.decision.standard_outcome_sha256 != self.evaluation.standard.outcome_sha256
            or self.decision.operational_outcome_sha256
            != self.evaluation.operational.outcome_sha256
            or self.decision.c2_authorized != self.evaluation.c2_authorized
            or self.decision.accepted != self.evaluation.accepted
            or self.run_evidence_attestation.payload.collector_id != self.decision.collector_id
            or self.run_evidence_attestation.payload.snapshot_sha256
            != self.decision.snapshot_sha256
            or self.run_evidence_attestation.payload.evaluation_sha256
            != self.decision.evaluation_sha256
            or self.run_evidence_attestation.payload.final_decision_sha256
            != self.decision.decision_sha256
            or self.run_evidence_attestation.payload.accepted != self.decision.accepted
        ):
            raise ValueError("acceptance finalization graph is inconsistent")
        return self


class AcceptanceSignerV3(Protocol):
    def sign(self, payload: bytes) -> bytes: ...


class AcceptanceAuthorityStateRecordV3(_StrictFrozenModel):
    collector_id: BoundedId
    state: AcceptanceRunStateV3
    revision: Annotated[int, Field(ge=0)]
    snapshot_sha256: Digest | None = None
    evaluation: AcceptanceEvaluationBundleV3 | None = None
    decision: AcceptanceDecisionV3 | None = None
    run_evidence_attestation: SignedRunEvidenceAttestationV3 | None = None
    proof_sha256: Digest | None = None
    pass_attestation: SignedAcceptancePassAttestationV3 | None = None
    accepted: bool | None = None

    @model_validator(mode="after")
    def state_invariants(self) -> AcceptanceAuthorityStateRecordV3:
        rank = _STATE_RANK[self.state]
        required = (
            (1, self.snapshot_sha256, "snapshot"),
            (2, self.evaluation, "evaluation"),
            (3, self.decision, "decision"),
            (3, self.run_evidence_attestation, "run evidence attestation"),
            (3, self.accepted, "accepted decision"),
            (4, self.proof_sha256, "proof"),
        )
        for threshold, value, label in required:
            if rank >= threshold and value is None:
                raise ValueError(f"{self.state} lacks required {label}")
            if rank < threshold and value is not None:
                raise ValueError(f"{self.state} contains premature {label}")
        if rank < 5 and self.pass_attestation is not None:
            raise ValueError("pass attestation precedes ATTESTED")
        if rank >= 5:
            if self.accepted is True and self.pass_attestation is None:
                raise ValueError("accepted run lacks a pass attestation")
            if self.accepted is False and self.pass_attestation is not None:
                raise ValueError("failed run cannot contain a pass attestation")
        if self.evaluation is not None and (
            self.snapshot_sha256 != self.evaluation.snapshot_sha256
            or (
                self.decision is not None
                and self.decision.evaluation_sha256 != self.evaluation.evaluation_sha256
            )
        ):
            raise ValueError("durable authority graph has mismatched bindings")
        if self.decision is not None and self.accepted != self.decision.accepted:
            raise ValueError("durable accepted state differs from final decision")
        return self


def _canonical_text(value: BaseModel) -> str:
    return canonical_json_bytes(value).decode("utf-8")


class AcceptanceAuthorityStateStoreV3:
    """SQLite CAS journal for one-way V3 authority state."""

    def __init__(self, path: Path) -> None:
        if not path.is_absolute() or path.is_symlink():
            raise ValueError("acceptance authority database must be an absolute non-symlink")
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.exists():
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("acceptance authority database must be a regular file")
        else:
            descriptor = os.open(
                path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.close(descriptor)
        path.chmod(0o600)
        self.path = path
        try:
            with self._connect() as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS acceptance_authority_v3_runs (
                        collector_id TEXT PRIMARY KEY,
                        state TEXT NOT NULL CHECK (
                            state IN (
                                'RUNNING',
                                'SNAPSHOT_COMMITTED',
                                'EVALUATED',
                                'FINALIZED',
                                'PROOF_PUBLISHED',
                                'ATTESTED'
                            )
                        ),
                        revision INTEGER NOT NULL CHECK (revision >= 0),
                        snapshot_sha256 TEXT,
                        evaluation_json TEXT,
                        decision_json TEXT,
                        run_evidence_attestation_json TEXT,
                        proof_sha256 TEXT,
                        pass_attestation_json TEXT,
                        accepted INTEGER CHECK (accepted IN (0, 1))
                    )
                    """
                )
        except sqlite3.DatabaseError as error:
            raise RuntimeError("acceptance authority database is invalid or corrupt") from error

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @staticmethod
    def _decode(
        row: sqlite3.Row | tuple[object, ...],
    ) -> AcceptanceAuthorityStateRecordV3:
        (
            collector_id,
            state_text,
            revision,
            snapshot_sha256,
            evaluation_json,
            decision_json,
            run_attestation_json,
            proof_sha256,
            pass_attestation_json,
            accepted,
        ) = row
        try:
            return AcceptanceAuthorityStateRecordV3(
                collector_id=collector_id,
                state=AcceptanceRunStateV3(state_text),
                revision=revision,
                snapshot_sha256=snapshot_sha256,
                evaluation=(
                    None
                    if evaluation_json is None
                    else AcceptanceEvaluationBundleV3.model_validate_json(
                        evaluation_json,
                        strict=True,
                    )
                ),
                decision=(
                    None
                    if decision_json is None
                    else AcceptanceDecisionV3.model_validate_json(
                        decision_json,
                        strict=True,
                    )
                ),
                run_evidence_attestation=(
                    None
                    if run_attestation_json is None
                    else SignedRunEvidenceAttestationV3.model_validate_json(
                        run_attestation_json,
                        strict=True,
                    )
                ),
                proof_sha256=proof_sha256,
                pass_attestation=(
                    None
                    if pass_attestation_json is None
                    else SignedAcceptancePassAttestationV3.model_validate_json(
                        pass_attestation_json,
                        strict=True,
                    )
                ),
                accepted=None if accepted is None else bool(accepted),
            )
        except (TypeError, ValueError):
            raise RuntimeError("acceptance authority durable state invariant is invalid") from None

    @staticmethod
    def _select(connection: sqlite3.Connection, collector_id: str) -> tuple[object, ...] | None:
        return connection.execute(
            """
            SELECT collector_id, state, revision, snapshot_sha256,
                   evaluation_json, decision_json,
                   run_evidence_attestation_json, proof_sha256,
                   pass_attestation_json, accepted
            FROM acceptance_authority_v3_runs
            WHERE collector_id = ?
            """,
            (collector_id,),
        ).fetchone()

    def load(self, collector_id: str) -> AcceptanceAuthorityStateRecordV3:
        try:
            with self._connect() as connection:
                row = self._select(connection, collector_id)
        except sqlite3.DatabaseError as error:
            raise RuntimeError("acceptance authority database is invalid or corrupt") from error
        if row is None:
            raise KeyError(collector_id)
        return self._decode(row)

    def begin(self, collector_id: str) -> AcceptanceAuthorityStateRecordV3:
        if type(collector_id) is not str or not 1 <= len(collector_id) <= 160:
            raise ValueError("collector identity is invalid")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT INTO acceptance_authority_v3_runs
                        (collector_id, state, revision)
                    VALUES (?, 'RUNNING', 0)
                    ON CONFLICT(collector_id) DO NOTHING
                    """,
                    (collector_id,),
                )
                row = self._select(connection, collector_id)
                connection.commit()
        except sqlite3.DatabaseError as error:
            raise RuntimeError("acceptance authority begin CAS failed") from error
        assert row is not None
        return self._decode(row)

    def _transition(
        self,
        *,
        collector_id: str,
        from_state: AcceptanceRunStateV3,
        to_state: AcceptanceRunStateV3,
        assignments: dict[str, object],
    ) -> AcceptanceAuthorityStateRecordV3:
        allowed_columns = {
            "snapshot_sha256",
            "evaluation_json",
            "decision_json",
            "run_evidence_attestation_json",
            "proof_sha256",
            "pass_attestation_json",
            "accepted",
        }
        if not assignments or not set(assignments).issubset(allowed_columns):
            raise ValueError("acceptance authority transition assignments are invalid")
        with self._connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = self._select(connection, collector_id)
                if row is None:
                    raise RuntimeError("acceptance authority run is not RUNNING")
                current = self._decode(row)
                if current.state is not from_state:
                    connection.rollback()
                    return current
                columns = ", ".join(f"{name} = ?" for name in assignments)
                values = tuple(assignments.values())
                cursor = connection.execute(
                    f"""
                    UPDATE acceptance_authority_v3_runs
                    SET state = ?, revision = revision + 1, {columns}
                    WHERE collector_id = ? AND state = ? AND revision = ?
                    """,
                    (
                        to_state.value,
                        *values,
                        collector_id,
                        from_state.value,
                        current.revision,
                    ),
                )
                if cursor.rowcount != 1:
                    connection.rollback()
                    raise RuntimeError("acceptance authority CAS transition lost")
                result_row = self._select(connection, collector_id)
                connection.commit()
            except BaseException:
                if connection.in_transaction:
                    connection.rollback()
                raise
        assert result_row is not None
        return self._decode(result_row)

    def commit_snapshot(
        self,
        snapshot: AcceptanceAuthoritySnapshotV3,
    ) -> AcceptanceAuthorityStateRecordV3:
        current = self.load(snapshot.collector_id)
        if _STATE_RANK[current.state] >= _STATE_RANK[AcceptanceRunStateV3.SNAPSHOT_COMMITTED]:
            if current.snapshot_sha256 != snapshot.snapshot_sha256:
                raise RuntimeError("acceptance snapshot retry changed")
            return current
        result = self._transition(
            collector_id=snapshot.collector_id,
            from_state=AcceptanceRunStateV3.RUNNING,
            to_state=AcceptanceRunStateV3.SNAPSHOT_COMMITTED,
            assignments={"snapshot_sha256": snapshot.snapshot_sha256},
        )
        if result.snapshot_sha256 != snapshot.snapshot_sha256:
            raise RuntimeError("acceptance snapshot CAS transition changed")
        return result

    def store_evaluations(
        self,
        collector_id: str,
        evaluation: AcceptanceEvaluationBundleV3,
    ) -> AcceptanceAuthorityStateRecordV3:
        current = self.load(collector_id)
        if current.snapshot_sha256 != evaluation.snapshot_sha256:
            raise RuntimeError("evaluation differs from committed snapshot")
        if _STATE_RANK[current.state] >= _STATE_RANK[AcceptanceRunStateV3.EVALUATED]:
            if current.evaluation != evaluation:
                raise RuntimeError("acceptance evaluation retry changed")
            return current
        result = self._transition(
            collector_id=collector_id,
            from_state=AcceptanceRunStateV3.SNAPSHOT_COMMITTED,
            to_state=AcceptanceRunStateV3.EVALUATED,
            assignments={"evaluation_json": _canonical_text(evaluation)},
        )
        if result.evaluation != evaluation:
            raise RuntimeError("acceptance evaluation CAS transition changed")
        return result

    def finalize(
        self,
        decision: AcceptanceDecisionV3,
        attestation: SignedRunEvidenceAttestationV3,
    ) -> AcceptanceAuthorityStateRecordV3:
        current = self.load(decision.collector_id)
        if _STATE_RANK[current.state] >= _STATE_RANK[AcceptanceRunStateV3.FINALIZED]:
            if current.decision != decision or current.run_evidence_attestation != attestation:
                raise RuntimeError("acceptance finalization retry changed")
            return current
        if current.evaluation is None or (
            decision.evaluation_sha256 != current.evaluation.evaluation_sha256
            or decision.snapshot_sha256 != current.snapshot_sha256
        ):
            raise RuntimeError("final decision differs from stored evaluation")
        result = self._transition(
            collector_id=decision.collector_id,
            from_state=AcceptanceRunStateV3.EVALUATED,
            to_state=AcceptanceRunStateV3.FINALIZED,
            assignments={
                "decision_json": _canonical_text(decision),
                "run_evidence_attestation_json": _canonical_text(attestation),
                "accepted": int(decision.accepted),
            },
        )
        if result.decision != decision or result.run_evidence_attestation != attestation:
            raise RuntimeError("acceptance finalization CAS transition changed")
        return result

    def mark_proof_published(
        self,
        collector_id: str,
        proof_sha256: str,
    ) -> AcceptanceAuthorityStateRecordV3:
        if (
            type(proof_sha256) is not str
            or len(proof_sha256) != 64
            or any(character not in "0123456789abcdef" for character in proof_sha256)
        ):
            raise ValueError("proof digest is invalid")
        current = self.load(collector_id)
        if _STATE_RANK[current.state] >= _STATE_RANK[AcceptanceRunStateV3.PROOF_PUBLISHED]:
            if current.proof_sha256 != proof_sha256:
                raise RuntimeError("acceptance proof retry changed")
            return current
        if current.state is not AcceptanceRunStateV3.FINALIZED:
            raise RuntimeError("acceptance proof publication violates state transition")
        return self._transition(
            collector_id=collector_id,
            from_state=AcceptanceRunStateV3.FINALIZED,
            to_state=AcceptanceRunStateV3.PROOF_PUBLISHED,
            assignments={"proof_sha256": proof_sha256},
        )

    def mark_attested(
        self,
        collector_id: str,
        pass_attestation: SignedAcceptancePassAttestationV3 | None,
    ) -> AcceptanceAuthorityStateRecordV3:
        current = self.load(collector_id)
        if current.state is AcceptanceRunStateV3.ATTESTED:
            if current.pass_attestation != pass_attestation:
                raise RuntimeError("acceptance pass attestation retry changed")
            return current
        if current.state is not AcceptanceRunStateV3.PROOF_PUBLISHED:
            raise RuntimeError("acceptance attestation violates state transition")
        if current.accepted is True and pass_attestation is None:
            raise RuntimeError("accepted run requires pass attestation")
        if current.accepted is False and pass_attestation is not None:
            raise RuntimeError("failed run cannot receive pass attestation")
        # SQLite cannot update zero columns; repeat the proof binding as a CAS value.
        assignments: dict[str, object] = {"proof_sha256": current.proof_sha256}
        if pass_attestation is not None:
            assignments["pass_attestation_json"] = _canonical_text(pass_attestation)
        return self._transition(
            collector_id=collector_id,
            from_state=AcceptanceRunStateV3.PROOF_PUBLISHED,
            to_state=AcceptanceRunStateV3.ATTESTED,
            assignments=assignments,
        )


def _signature_hex(signer: AcceptanceSignerV3, payload: bytes) -> str:
    signature = signer.sign(payload)
    if type(signature) is not bytes or len(signature) != 64:
        raise RuntimeError("acceptance signer returned an invalid signature")
    return signature.hex()


class AcceptanceAuthorityV3:
    def __init__(
        self,
        *,
        state_store: AcceptanceAuthorityStateStoreV3,
        run_evidence_signer: AcceptanceSignerV3,
        acceptance_pass_signer: AcceptanceSignerV3,
    ) -> None:
        self.state_store = state_store
        self._run_evidence_signer = run_evidence_signer
        self._acceptance_pass_signer = acceptance_pass_signer

    def evaluate_and_finalize(
        self,
        snapshot: AcceptanceAuthoritySnapshotV3,
    ) -> AcceptanceFinalizationV3:
        current = self.state_store.begin(snapshot.collector_id)
        if current.snapshot_sha256 is not None and (
            current.snapshot_sha256 != snapshot.snapshot_sha256
        ):
            raise RuntimeError("acceptance authority retry changed its snapshot")
        current = self.state_store.commit_snapshot(snapshot)
        if current.evaluation is None:
            evaluation = run_dual_evaluation_v3(snapshot)
            current = self.state_store.store_evaluations(
                snapshot.collector_id,
                evaluation,
            )
        assert current.evaluation is not None
        evaluation = current.evaluation
        if current.decision is None:
            decision = AcceptanceDecisionV3(
                schema_version="acceptance-final-decision.v3",
                collector_id=snapshot.collector_id,
                snapshot_sha256=snapshot.snapshot_sha256,
                evaluation_sha256=evaluation.evaluation_sha256,
                standard_outcome_sha256=evaluation.standard.outcome_sha256,
                operational_outcome_sha256=evaluation.operational.outcome_sha256,
                c2_authorized=evaluation.c2_authorized,
                accepted=evaluation.accepted,
            )
            evidence_payload = RunEvidenceAttestationV3(
                schema_version="run-evidence-attestation.v3",
                collector_id=snapshot.collector_id,
                snapshot_sha256=snapshot.snapshot_sha256,
                evaluation_sha256=evaluation.evaluation_sha256,
                final_decision_sha256=decision.decision_sha256,
                accepted=decision.accepted,
            )
            signed_evidence = SignedRunEvidenceAttestationV3(
                schema_version="signed-run-evidence-attestation.v3",
                payload=evidence_payload,
                signature_hex=_signature_hex(
                    self._run_evidence_signer,
                    canonical_json_bytes(evidence_payload),
                ),
            )
            current = self.state_store.finalize(decision, signed_evidence)
        assert current.decision is not None
        assert current.run_evidence_attestation is not None
        return AcceptanceFinalizationV3(
            schema_version="acceptance-finalization.v3",
            evaluation=evaluation,
            decision=current.decision,
            run_evidence_attestation=current.run_evidence_attestation,
        )

    def mark_proof_published(
        self,
        collector_id: str,
        proof_sha256: str,
    ) -> AcceptanceAuthorityStateRecordV3:
        return self.state_store.mark_proof_published(collector_id, proof_sha256)

    def attest(
        self,
        collector_id: str,
    ) -> SignedAcceptancePassAttestationV3 | None:
        current = self.state_store.load(collector_id)
        if current.state is AcceptanceRunStateV3.ATTESTED:
            return current.pass_attestation
        if current.state is not AcceptanceRunStateV3.PROOF_PUBLISHED:
            raise RuntimeError("acceptance proof must be published before attestation")
        assert current.decision is not None
        assert current.proof_sha256 is not None
        if not current.decision.accepted:
            self.state_store.mark_attested(collector_id, None)
            return None
        payload = AcceptancePassAttestationV3(
            schema_version="acceptance-pass-attestation.v3",
            collector_id=collector_id,
            snapshot_sha256=current.decision.snapshot_sha256,
            evaluation_sha256=current.decision.evaluation_sha256,
            final_decision_sha256=current.decision.decision_sha256,
            proof_sha256=current.proof_sha256,
            accepted=True,
        )
        signed = SignedAcceptancePassAttestationV3(
            schema_version="signed-acceptance-pass-attestation.v3",
            payload=payload,
            signature_hex=_signature_hex(
                self._acceptance_pass_signer,
                canonical_json_bytes(payload),
            ),
        )
        self.state_store.mark_attested(collector_id, signed)
        return signed
