"""Exact V3 proof inventory binding snapshot, both evaluators, and decision."""

from __future__ import annotations

import hashlib
from collections import Counter
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from protector.pilot.acceptance_trust import (
    _load_canonical_json_object,
    canonical_json_bytes,
)

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
BoundedId = Annotated[str, Field(min_length=1, max_length=160)]
ProofKindV3 = Literal[
    "start",
    "sample",
    "fault_intent",
    "fault_claim",
    "fault_ack",
    "authority_snapshot",
    "standard_evaluation",
    "operational_evaluation",
    "final_decision",
]
MAX_ACCEPTANCE_PROOF_V3_BYTES = 32 * 1024 * 1024
MAX_ACCEPTANCE_PROOF_V3_LINE_BYTES = 16 * 1024

_SPECIAL_ORDER: tuple[ProofKindV3, ...] = (
    "authority_snapshot",
    "standard_evaluation",
    "operational_evaluation",
    "final_decision",
)


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class JournalKindCountsV3(_StrictFrozenModel):
    start: Literal[1]
    sample: Literal[481, 4321]
    fault_intent: Literal[16]
    fault_claim: Literal[16]
    fault_ack: Literal[16]
    authority_snapshot: Literal[1]
    standard_evaluation: Literal[1]
    operational_evaluation: Literal[1]
    final_decision: Literal[1]

    @classmethod
    def exact_for_gate(cls, gate: Literal["8h", "72h"]) -> JournalKindCountsV3:
        return cls(
            start=1,
            sample=481 if gate == "8h" else 4_321,
            fault_intent=16,
            fault_claim=16,
            fault_ack=16,
            authority_snapshot=1,
            standard_evaluation=1,
            operational_evaluation=1,
            final_decision=1,
        )

    @property
    def total(self) -> int:
        return sum(getattr(self, name) for name in type(self).model_fields)


class AcceptanceJournalProofHeaderV3(_StrictFrozenModel):
    schema_version: Literal["acceptance-journal-proof-header.v3"]
    collector_id: BoundedId
    site_id: BoundedId
    gate: Literal["8h", "72h"]
    snapshot_sha256: Digest
    standard_evaluation_sha256: Digest
    operational_evaluation_sha256: Digest
    final_decision_sha256: Digest
    expected_kind_counts: JournalKindCountsV3

    @model_validator(mode="after")
    def counts_match_gate(self) -> AcceptanceJournalProofHeaderV3:
        if self.expected_kind_counts != JournalKindCountsV3.exact_for_gate(self.gate):
            raise ValueError("V3 proof header has the wrong exact gate inventory")
        return self


class AcceptanceJournalProofEntryV3(_StrictFrozenModel):
    schema_version: Literal["acceptance-journal-proof-entry.v3"]
    ordinal: Annotated[int, Field(ge=1, le=4_374)]
    kind: ProofKindV3
    identity: BoundedId
    payload_sha256: Digest
    previous_entry_sha256: Annotated[
        str,
        Field(pattern=r"^(?:|[0-9a-f]{64})$"),
    ]
    entry_sha256: Digest


class AcceptanceJournalProofTrailerV3(_StrictFrozenModel):
    schema_version: Literal["acceptance-journal-proof-trailer.v3"]
    collector_id: BoundedId
    entry_count: Literal[534, 4374]
    kind_counts: JournalKindCountsV3
    final_entry_sha256: Digest
    snapshot_sha256: Digest
    standard_evaluation_sha256: Digest
    operational_evaluation_sha256: Digest
    final_decision_sha256: Digest


def proof_entry_sha256_v3(
    *,
    ordinal: int,
    kind: ProofKindV3,
    identity: str,
    payload_sha256: str,
    previous_entry_sha256: str,
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "schema_version": "acceptance-journal-entry-chain.v3",
                "ordinal": ordinal,
                "kind": kind,
                "identity": identity,
                "payload_sha256": payload_sha256,
                "previous_entry_sha256": previous_entry_sha256,
            }
        )
    ).hexdigest()


class AcceptanceJournalProofV3(_StrictFrozenModel):
    header: AcceptanceJournalProofHeaderV3
    entries: Annotated[
        tuple[AcceptanceJournalProofEntryV3, ...],
        Field(min_length=1, max_length=4_374),
    ]
    trailer: AcceptanceJournalProofTrailerV3

    @model_validator(mode="after")
    def exact_inventory_order_and_chain(self) -> AcceptanceJournalProofV3:
        expected = JournalKindCountsV3.exact_for_gate(self.header.gate)
        if len(self.entries) != expected.total:
            raise ValueError("V3 proof entry count differs from exact inventory")
        actual = Counter(item.kind for item in self.entries)
        if any(actual[name] != getattr(expected, name) for name in type(expected).model_fields):
            raise ValueError("V3 proof kind count differs from exact inventory")
        if tuple(item.kind for item in self.entries[-4:]) != _SPECIAL_ORDER:
            raise ValueError("V3 authority artifacts have invalid exact order")
        expected_prefix = (
            ("start",)
            + ("fault_intent",) * 16
            + ("sample",) * expected.sample
            + ("fault_claim",) * 16
            + ("fault_ack",) * 16
        )
        if tuple(item.kind for item in self.entries[:-4]) != expected_prefix:
            raise ValueError("V3 core journal inventory has invalid exact order")
        previous = ""
        identities: set[str] = set()
        for ordinal, entry in enumerate(self.entries, start=1):
            if (
                entry.ordinal != ordinal
                or entry.identity in identities
                or entry.previous_entry_sha256 != previous
                or entry.entry_sha256
                != proof_entry_sha256_v3(
                    ordinal=ordinal,
                    kind=entry.kind,
                    identity=entry.identity,
                    payload_sha256=entry.payload_sha256,
                    previous_entry_sha256=previous,
                )
            ):
                raise ValueError("V3 proof ordinal, identity, or hash chain is invalid")
            identities.add(entry.identity)
            previous = entry.entry_sha256
        special_payloads = tuple(item.payload_sha256 for item in self.entries[-4:])
        expected_special = (
            self.header.snapshot_sha256,
            self.header.standard_evaluation_sha256,
            self.header.operational_evaluation_sha256,
            self.header.final_decision_sha256,
        )
        if special_payloads != expected_special:
            raise ValueError("V3 proof authority artifact substitution detected")
        trailer = self.trailer
        if (
            trailer.collector_id != self.header.collector_id
            or trailer.entry_count != expected.total
            or trailer.kind_counts != expected
            or trailer.final_entry_sha256 != previous
            or trailer.snapshot_sha256 != self.header.snapshot_sha256
            or trailer.standard_evaluation_sha256 != self.header.standard_evaluation_sha256
            or trailer.operational_evaluation_sha256 != self.header.operational_evaluation_sha256
            or trailer.final_decision_sha256 != self.header.final_decision_sha256
        ):
            raise ValueError("V3 proof trailer differs from exact inventory")
        return self


def _entry(
    *,
    ordinal: int,
    kind: ProofKindV3,
    identity: str,
    payload_sha256: str,
    previous: str,
) -> AcceptanceJournalProofEntryV3:
    digest = proof_entry_sha256_v3(
        ordinal=ordinal,
        kind=kind,
        identity=identity,
        payload_sha256=payload_sha256,
        previous_entry_sha256=previous,
    )
    return AcceptanceJournalProofEntryV3(
        schema_version="acceptance-journal-proof-entry.v3",
        ordinal=ordinal,
        kind=kind,
        identity=identity,
        payload_sha256=payload_sha256,
        previous_entry_sha256=previous,
        entry_sha256=digest,
    )


def build_acceptance_journal_proof_v3(
    *,
    collector_id: str,
    site_id: str,
    gate: Literal["8h", "72h"],
    snapshot_sha256: str,
    standard_evaluation_sha256: str,
    operational_evaluation_sha256: str,
    final_decision_sha256: str,
) -> AcceptanceJournalProofV3:
    counts = JournalKindCountsV3.exact_for_gate(gate)
    header = AcceptanceJournalProofHeaderV3(
        schema_version="acceptance-journal-proof-header.v3",
        collector_id=collector_id,
        site_id=site_id,
        gate=gate,
        snapshot_sha256=snapshot_sha256,
        standard_evaluation_sha256=standard_evaluation_sha256,
        operational_evaluation_sha256=operational_evaluation_sha256,
        final_decision_sha256=final_decision_sha256,
        expected_kind_counts=counts,
    )
    kinds: tuple[ProofKindV3, ...] = (
        ("start",)
        + ("fault_intent",) * counts.fault_intent
        + ("sample",) * counts.sample
        + ("fault_claim",) * counts.fault_claim
        + ("fault_ack",) * counts.fault_ack
        + _SPECIAL_ORDER
    )
    special = {
        "authority_snapshot": snapshot_sha256,
        "standard_evaluation": standard_evaluation_sha256,
        "operational_evaluation": operational_evaluation_sha256,
        "final_decision": final_decision_sha256,
    }
    previous = ""
    entries: list[AcceptanceJournalProofEntryV3] = []
    for ordinal, kind in enumerate(kinds, start=1):
        payload_sha256 = special.get(
            kind,
            hashlib.sha256(f"kuzet.acceptance.v3:{kind}:{ordinal}".encode("ascii")).hexdigest(),
        )
        entry = _entry(
            ordinal=ordinal,
            kind=kind,
            identity=f"{kind}:{ordinal:05}",
            payload_sha256=payload_sha256,
            previous=previous,
        )
        entries.append(entry)
        previous = entry.entry_sha256
    trailer = AcceptanceJournalProofTrailerV3(
        schema_version="acceptance-journal-proof-trailer.v3",
        collector_id=collector_id,
        entry_count=counts.total,
        kind_counts=counts,
        final_entry_sha256=previous,
        snapshot_sha256=snapshot_sha256,
        standard_evaluation_sha256=standard_evaluation_sha256,
        operational_evaluation_sha256=operational_evaluation_sha256,
        final_decision_sha256=final_decision_sha256,
    )
    return AcceptanceJournalProofV3(
        header=header,
        entries=tuple(entries),
        trailer=trailer,
    )


def _line(value: BaseModel) -> bytes:
    payload = canonical_json_bytes(value)
    if len(payload) > MAX_ACCEPTANCE_PROOF_V3_LINE_BYTES:
        raise ValueError("V3 proof line exceeds its finite bound")
    return payload + b"\n"


def canonical_acceptance_proof_v3(proof: AcceptanceJournalProofV3) -> bytes:
    owned = AcceptanceJournalProofV3.model_validate_json(
        canonical_json_bytes(proof),
        strict=True,
    )
    payload = b"".join(
        (
            _line(owned.header),
            *(_line(entry) for entry in owned.entries),
            _line(owned.trailer),
        )
    )
    if len(payload) > MAX_ACCEPTANCE_PROOF_V3_BYTES:
        raise ValueError("V3 proof exceeds its finite byte bound")
    return payload


def verify_acceptance_journal_proof_v3(
    payload: bytes,
    *,
    expected_snapshot_sha256: str,
    expected_standard_evaluation_sha256: str,
    expected_operational_evaluation_sha256: str,
    expected_final_decision_sha256: str,
) -> AcceptanceJournalProofV3:
    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > MAX_ACCEPTANCE_PROOF_V3_BYTES
        or not payload.endswith(b"\n")
    ):
        raise ValueError("V3 proof is empty, unbounded, or improperly framed")
    lines = payload.splitlines(keepends=True)
    if any(
        not line.endswith(b"\n")
        or len(line) <= 1
        or len(line) > MAX_ACCEPTANCE_PROOF_V3_LINE_BYTES + 1
        for line in lines
    ):
        raise ValueError("V3 proof line framing is invalid")

    def parsed(index: int, label: str) -> dict[str, object]:
        return _load_canonical_json_object(
            lines[index][:-1],
            max_bytes=MAX_ACCEPTANCE_PROOF_V3_LINE_BYTES,
            label=label,
        )

    try:
        header = AcceptanceJournalProofHeaderV3.model_validate(
            parsed(0, "V3 proof header"),
            strict=True,
        )
    except (IndexError, ValueError):
        raise ValueError("V3 proof header is invalid") from None
    expected_lines = header.expected_kind_counts.total + 2
    if len(lines) != expected_lines:
        raise ValueError("V3 proof line count differs from exact inventory")
    try:
        entries = tuple(
            AcceptanceJournalProofEntryV3.model_validate(
                parsed(index, f"V3 proof entry {index}"),
                strict=True,
            )
            for index in range(1, len(lines) - 1)
        )
        trailer = AcceptanceJournalProofTrailerV3.model_validate(
            parsed(len(lines) - 1, "V3 proof trailer"),
            strict=True,
        )
        proof = AcceptanceJournalProofV3(
            header=header,
            entries=entries,
            trailer=trailer,
        )
    except ValueError:
        raise ValueError("V3 proof chain, order, or inventory is invalid") from None
    if (
        proof.header.snapshot_sha256 != expected_snapshot_sha256
        or proof.header.standard_evaluation_sha256 != expected_standard_evaluation_sha256
        or proof.header.operational_evaluation_sha256 != expected_operational_evaluation_sha256
        or proof.header.final_decision_sha256 != expected_final_decision_sha256
    ):
        raise ValueError("V3 proof authority artifact substitution detected")
    if canonical_acceptance_proof_v3(proof) != payload:
        raise ValueError("V3 proof differs from exact canonical bytes")
    return proof
