"""Exact V3 proof inventory binding snapshot, both evaluators, and decision."""

from __future__ import annotations

import hashlib
import os
import stat
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from protector.pilot.acceptance_proof import (
    MAX_ACCEPTANCE_JOURNAL_PROOF_BYTES,
    MAX_ACCEPTANCE_JOURNAL_PROOF_LINE_BYTES,
    AcceptanceFinalEnvelopeV2,
    AcceptanceJournalProofEntryV2,
    verify_acceptance_journal_proof,
)
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
    v2_run_record_sha256: Digest
    v2_run_attestation_sha256: Digest
    v2_journal_proof_sha256: Digest
    v2_journal_root_sha256: Digest
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
    source_v2_entry_sha256: Digest | None = None
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
    v2_run_record_sha256: Digest
    v2_run_attestation_sha256: Digest
    v2_journal_proof_sha256: Digest
    v2_journal_root_sha256: Digest


def proof_entry_sha256_v3(
    *,
    ordinal: int,
    kind: ProofKindV3,
    identity: str,
    payload_sha256: str,
    source_v2_entry_sha256: str | None,
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
                "source_v2_entry_sha256": source_v2_entry_sha256,
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
        ordinary = self.entries[:-4]
        if (
            not ordinary
            or ordinary[0].kind != "start"
            or any(item.source_v2_entry_sha256 is None for item in ordinary)
            or any(item.source_v2_entry_sha256 is not None for item in self.entries[-4:])
        ):
            raise ValueError("V3 core journal does not bind actual ordered V2 entries")
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
                    source_v2_entry_sha256=entry.source_v2_entry_sha256,
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
            or trailer.v2_run_record_sha256 != self.header.v2_run_record_sha256
            or trailer.v2_run_attestation_sha256
            != self.header.v2_run_attestation_sha256
            or trailer.v2_journal_proof_sha256
            != self.header.v2_journal_proof_sha256
            or trailer.v2_journal_root_sha256
            != self.header.v2_journal_root_sha256
        ):
            raise ValueError("V3 proof trailer differs from exact inventory")
        return self


def _entry(
    *,
    ordinal: int,
    kind: ProofKindV3,
    identity: str,
    payload_sha256: str,
    source_v2_entry_sha256: str | None,
    previous: str,
) -> AcceptanceJournalProofEntryV3:
    digest = proof_entry_sha256_v3(
        ordinal=ordinal,
        kind=kind,
        identity=identity,
        payload_sha256=payload_sha256,
        source_v2_entry_sha256=source_v2_entry_sha256,
        previous_entry_sha256=previous,
    )
    return AcceptanceJournalProofEntryV3(
        schema_version="acceptance-journal-proof-entry.v3",
        ordinal=ordinal,
        kind=kind,
        identity=identity,
        payload_sha256=payload_sha256,
        source_v2_entry_sha256=source_v2_entry_sha256,
        previous_entry_sha256=previous,
        entry_sha256=digest,
    )


def _capture_v2_entries(
    path: Path,
    *,
    expected_proof_sha256: str,
) -> tuple[AcceptanceJournalProofEntryV2, ...]:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= MAX_ACCEPTANCE_JOURNAL_PROOF_BYTES
        ):
            raise ValueError("V2 journal proof is not one bounded regular file")
        digest = hashlib.sha256()
        entries: list[AcceptanceJournalProofEntryV2] = []
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            for line_number, line in enumerate(handle, start=1):
                if (
                    not line.endswith(b"\n")
                    or len(line) <= 1
                    or len(line) > MAX_ACCEPTANCE_JOURNAL_PROOF_LINE_BYTES + 1
                ):
                    raise ValueError("V2 journal proof framing changed")
                digest.update(line)
                if line_number == 1:
                    continue
                parsed = _load_canonical_json_object(
                    line[:-1],
                    max_bytes=MAX_ACCEPTANCE_JOURNAL_PROOF_LINE_BYTES,
                    label="V2 journal proof entry",
                )
                schema = parsed.get("schema_version")
                if schema == "acceptance-journal-proof-trailer.v2":
                    break
                entry = AcceptanceJournalProofEntryV2.model_validate(parsed)
                if entry.kind != "finalize":
                    entries.append(entry)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValueError("V2 journal proof changed while V3 captured it")
        if digest.hexdigest() != expected_proof_sha256:
            raise ValueError("V2 journal proof digest changed during V3 capture")
        return tuple(entries)
    finally:
        os.close(descriptor)


def build_acceptance_journal_proof_v3(
    *,
    v2_journal_proof_path: Path,
    v2_final_envelope: AcceptanceFinalEnvelopeV2,
    snapshot_sha256: str,
    standard_evaluation_sha256: str,
    operational_evaluation_sha256: str,
    final_decision_sha256: str,
) -> AcceptanceJournalProofV3:
    if type(v2_final_envelope) is not AcceptanceFinalEnvelopeV2:
        raise TypeError("V3 proof requires the exact V2 final envelope")
    envelope = AcceptanceFinalEnvelopeV2.model_validate(
        v2_final_envelope.model_dump(mode="python")
    )
    verified = verify_acceptance_journal_proof(
        v2_journal_proof_path,
        expected_attestation=envelope.attestation,
        expected_run_record=envelope.record,
    )
    collector_id = envelope.record.run_id
    site_id = envelope.record.site_id
    gate = envelope.record.gate
    counts = JournalKindCountsV3.exact_for_gate(gate)
    run_record_sha256 = hashlib.sha256(
        canonical_json_bytes(envelope.record)
    ).hexdigest()
    run_attestation_sha256 = hashlib.sha256(
        canonical_json_bytes(envelope.attestation)
    ).hexdigest()
    header = AcceptanceJournalProofHeaderV3(
        schema_version="acceptance-journal-proof-header.v3",
        collector_id=collector_id,
        site_id=site_id,
        gate=gate,
        snapshot_sha256=snapshot_sha256,
        standard_evaluation_sha256=standard_evaluation_sha256,
        operational_evaluation_sha256=operational_evaluation_sha256,
        final_decision_sha256=final_decision_sha256,
        v2_run_record_sha256=run_record_sha256,
        v2_run_attestation_sha256=run_attestation_sha256,
        v2_journal_proof_sha256=verified.proof_sha256,
        v2_journal_root_sha256=verified.trailer.journal_final_root_sha256,
        expected_kind_counts=counts,
    )
    v2_entries = _capture_v2_entries(
        v2_journal_proof_path,
        expected_proof_sha256=verified.proof_sha256,
    )
    if len(v2_entries) != counts.total - len(_SPECIAL_ORDER):
        raise ValueError("V2 journal proof has the wrong ordinary evidence inventory")
    special = {
        "authority_snapshot": snapshot_sha256,
        "standard_evaluation": standard_evaluation_sha256,
        "operational_evaluation": operational_evaluation_sha256,
        "final_decision": final_decision_sha256,
    }
    previous = ""
    entries: list[AcceptanceJournalProofEntryV3] = []
    for ordinal, source in enumerate(v2_entries, start=1):
        payload_sha256 = hashlib.sha256(canonical_json_bytes(source)).hexdigest()
        entry = _entry(
            ordinal=ordinal,
            kind=source.kind,
            identity=f"v2:{source.ordinal}:{source.entry_sha256[:32]}",
            payload_sha256=payload_sha256,
            source_v2_entry_sha256=source.entry_sha256,
            previous=previous,
        )
        entries.append(entry)
        previous = entry.entry_sha256
    for kind in _SPECIAL_ORDER:
        ordinal = len(entries) + 1
        entry = _entry(
            ordinal=ordinal,
            kind=kind,
            identity=f"{kind}:{ordinal:05}",
            payload_sha256=special[kind],
            source_v2_entry_sha256=None,
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
        v2_run_record_sha256=run_record_sha256,
        v2_run_attestation_sha256=run_attestation_sha256,
        v2_journal_proof_sha256=verified.proof_sha256,
        v2_journal_root_sha256=verified.trailer.journal_final_root_sha256,
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
    expected_v2_run_record_sha256: str,
    expected_v2_run_attestation_sha256: str,
    expected_v2_journal_proof_sha256: str,
    expected_v2_journal_root_sha256: str,
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
        or proof.header.v2_run_record_sha256 != expected_v2_run_record_sha256
        or proof.header.v2_run_attestation_sha256
        != expected_v2_run_attestation_sha256
        or proof.header.v2_journal_proof_sha256
        != expected_v2_journal_proof_sha256
        or proof.header.v2_journal_root_sha256
        != expected_v2_journal_root_sha256
    ):
        raise ValueError("V3 proof authority artifact substitution detected")
    if canonical_acceptance_proof_v3(proof) != payload:
        raise ValueError("V3 proof differs from exact canonical bytes")
    return proof


@dataclass(frozen=True)
class PublishedAcceptanceProofV3:
    path: Path
    sha256: str
    byte_size: int


class AcceptanceProofStoreV3:
    """Private O_EXCL/no-replace publication with digest re-observation."""

    def __init__(self, root: Path) -> None:
        if not root.is_absolute() or root.is_symlink():
            raise ValueError("V3 proof root must be an absolute non-symlink")
        metadata = root.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ValueError("V3 proof root must be private and owner controlled")
        self.root = root
        self._descriptor = os.open(
            root,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(self._descriptor)
        self._identity = (opened.st_dev, opened.st_ino)
        if self._identity != (metadata.st_dev, metadata.st_ino):
            os.close(self._descriptor)
            raise ValueError("V3 proof root changed while opening")

    def __del__(self) -> None:
        descriptor = getattr(self, "_descriptor", -1)
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
            self._descriptor = -1

    @staticmethod
    def _stem(collector_id: str) -> str:
        if type(collector_id) is not str or not 1 <= len(collector_id) <= 160:
            raise ValueError("V3 proof collector identity is invalid")
        return hashlib.sha256(collector_id.encode()).hexdigest()

    def _read(self, name: str) -> bytes:
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=self._descriptor,
        )
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600
                or not 1 <= before.st_size <= MAX_ACCEPTANCE_PROOF_V3_BYTES
                or before.st_dev != self._identity[0]
            ):
                raise RuntimeError("V3 proof artifact is unsafe or unbounded")
            chunks: list[bytes] = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    raise RuntimeError("V3 proof artifact changed while reading")
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise RuntimeError("V3 proof artifact changed while reading")
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    def publish(
        self,
        *,
        collector_id: str,
        proof: AcceptanceJournalProofV3,
    ) -> PublishedAcceptanceProofV3:
        payload = canonical_acceptance_proof_v3(proof)
        digest = hashlib.sha256(payload).hexdigest()
        stem = self._stem(collector_id)
        final_name = f"proof-{stem}.jsonl"
        pending_name = f".proof-{stem}.pending"
        try:
            existing_payload = self._read(final_name)
        except FileNotFoundError:
            existing_payload = None
        if existing_payload is not None:
            if existing_payload != payload:
                raise RuntimeError("existing V3 proof differs; replace is forbidden")
            return PublishedAcceptanceProofV3(
                path=self.root / final_name,
                sha256=hashlib.sha256(existing_payload).hexdigest(),
                byte_size=len(existing_payload),
            )
        try:
            descriptor = os.open(
                pending_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=self._descriptor,
            )
        except FileExistsError:
            if self._read(pending_name) != payload:
                raise RuntimeError("pending V3 proof differs from exact recovery")
        else:
            try:
                offset = 0
                while offset < len(payload):
                    written = os.write(descriptor, payload[offset:])
                    if written <= 0:
                        raise OSError("V3 proof write made no progress")
                    offset += written
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        try:
            os.link(
                pending_name,
                final_name,
                src_dir_fd=self._descriptor,
                dst_dir_fd=self._descriptor,
                follow_symlinks=False,
            )
        except FileExistsError:
            pass
        try:
            os.unlink(pending_name, dir_fd=self._descriptor)
        except FileNotFoundError:
            pass
        os.fsync(self._descriptor)
        observed = self._read(final_name)
        observed_digest = hashlib.sha256(observed).hexdigest()
        if observed != payload or observed_digest != digest:
            raise RuntimeError("published V3 proof differs from exact observed bytes")
        return PublishedAcceptanceProofV3(
            path=self.root / final_name,
            sha256=observed_digest,
            byte_size=len(observed),
        )
