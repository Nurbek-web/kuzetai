"""Streaming, independently replayable target acceptance journal proofs."""

from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from protector.pilot.acceptance import (
    AcceptanceRunRecordV2,
    ExecutionBindingV2,
    LaunchAttestationV2,
    ScheduledFaultV2,
    build_canonical_fault_schedule,
    canonical_fault_schedule_sha256,
)
from protector.pilot.acceptance_trust import (
    MAX_ACCEPTANCE_RUN_RECORD_BYTES,
    _load_canonical_json_object,
    canonical_json_bytes,
    load_canonical_json_bytes,
)
from protector.pilot.config import FrozenModel

MAX_ACCEPTANCE_JOURNAL_PROOF_BYTES = 272 * 1024 * 1024
MAX_ACCEPTANCE_JOURNAL_PROOF_LINE_BYTES = MAX_ACCEPTANCE_RUN_RECORD_BYTES + 1024 * 1024
_MAX_HEADER_BYTES = 4 * 1024 * 1024
_MAX_TRAILER_BYTES = 64 * 1024

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
SafeIdentifier = Annotated[
    str,
    Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$"),
]
JournalKind = Literal[
    "start",
    "sample",
    "fault_intent",
    "fault_claim",
    "fault_ack",
    "finalize",
]
_JOURNAL_PAYLOAD_SCHEMAS = {
    "start": "acceptance-collector-start.v2",
    "sample": "acceptance-sample-observation.v2",
    "fault_intent": "acceptance-fault-intent.v2",
    "fault_claim": "acceptance-fault-claim.v2",
    "fault_ack": "acceptance-fault-acknowledgement.v2",
    "finalize": "acceptance-run-record.v2",
}


class JournalKindCountsV2(FrozenModel):
    start: Annotated[int, Field(ge=0, le=1)]
    sample: Annotated[int, Field(ge=0, le=4_321)]
    fault_intent: Annotated[int, Field(ge=0, le=16)]
    fault_claim: Annotated[int, Field(ge=0, le=16)]
    fault_ack: Annotated[int, Field(ge=0, le=16)]
    finalize: Annotated[int, Field(ge=0, le=1)]

    @property
    def total(self) -> int:
        return sum(getattr(self, name) for name in type(self).model_fields)

    @classmethod
    def exact_for_gate(cls, gate: Literal["8h", "72h"]) -> JournalKindCountsV2:
        return cls(
            start=1,
            sample=481 if gate == "8h" else 4_321,
            fault_intent=16,
            fault_claim=16,
            fault_ack=16,
            finalize=1,
        )


class AcceptanceJournalProofHeaderV2(FrozenModel):
    schema_version: Literal["acceptance-journal-proof-header.v2"]
    collector_id: SafeIdentifier
    site_id: Annotated[str, Field(min_length=1, max_length=128)]
    manifest_sha256: Digest
    gate: Literal["8h", "72h"]
    journal_namespace_mode: Literal["protected"]
    offline_root_spki_sha256: Digest
    policy_id: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"),
    ]
    policy_sha256: Digest
    campaign_id: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"),
    ]
    manifest_payload_sha256: Digest
    launch_attestation_sha256: Digest
    execution_binding_sha256: Digest
    fault_schedule_sha256: Digest
    public_run_authority_spki_sha256: Digest
    sample_interval_seconds: Literal[60]
    camera_ids: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=128)], ...],
        Field(min_length=20, max_length=20),
    ]
    launch: LaunchAttestationV2
    execution: ExecutionBindingV2
    fault_schedule: Annotated[
        tuple[ScheduledFaultV2, ...],
        Field(min_length=8, max_length=8),
    ]

    @model_validator(mode="after")
    def embedded_contracts_are_exact(
        self,
    ) -> AcceptanceJournalProofHeaderV2:
        if (
            len(set(self.camera_ids)) != 20
            or self.fault_schedule != build_canonical_fault_schedule(self.camera_ids)
            or self.launch.site_id != self.site_id
            or self.launch.attestation_sha256 != self.launch_attestation_sha256
            or self.execution.binding_sha256 != self.execution_binding_sha256
            or self.execution.launch_attestation_sha256 != self.launch_attestation_sha256
            or canonical_fault_schedule_sha256(self.fault_schedule) != self.fault_schedule_sha256
            or self.launch.run_authority_public_key_spki_sha256 != self.public_run_authority_spki_sha256
            or self.execution.runtime_image_id_sha256 != self.launch.runtime_image_id_sha256
            or self.execution.acceptance_adapter_sha256 != self.launch.acceptance_adapter_sha256
            or self.execution.acceptance_adapter_policy_sha256
            != self.launch.acceptance_adapter_policy_sha256
            or self.execution.acceptance_observer_sha256 != self.launch.acceptance_observer_sha256
            or self.execution.acceptance_observer_policy_sha256
            != self.launch.acceptance_observer_policy_sha256
            or self.execution.control_network_id != self.launch.expected_control_network_id
            or self.execution.control_network_config_sha256
            != self.launch.expected_control_network_config_sha256
            or self.execution.camera_network_id != self.launch.expected_camera_network_id
            or self.execution.camera_network_config_sha256
            != self.launch.expected_camera_network_config_sha256
            or self.execution.observed_gpu_inventory_sha256 != self.launch.gpu_inventory_sha256
        ):
            raise ValueError(
                "acceptance journal proof embedded launch, execution, or fault contract differs"
            )
        return self


class AcceptanceJournalProofEntryV2(FrozenModel):
    schema_version: Literal["acceptance-journal-proof-entry.v2"]
    ordinal: Annotated[int, Field(ge=1, le=4_371)]
    collector_id: SafeIdentifier
    kind: JournalKind
    identity: SafeIdentifier
    payload: Annotated[dict[str, object], Field(max_length=256)]
    created_at: Annotated[str, Field(min_length=20, max_length=64)]
    previous_entry_sha256: Annotated[str, Field(pattern=r"^(?:|[0-9a-f]{64})$")]
    entry_sha256: Digest

    @model_validator(mode="after")
    def payload_schema_matches_operation(self) -> AcceptanceJournalProofEntryV2:
        if self.payload.get("schema_version") != _JOURNAL_PAYLOAD_SCHEMAS[self.kind]:
            raise ValueError("proof entry payload schema differs from operation")
        return self

    @field_validator("created_at")
    @classmethod
    def created_at_is_exact_utc(cls, value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            raise ValueError("proof entry timestamp must be ISO UTC") from None
        if (
            parsed.tzinfo is None
            or parsed.utcoffset() is None
            or parsed.utcoffset() != timedelta(0)
        ):
            raise ValueError("proof entry timestamp must be ISO UTC")
        return value


class AcceptanceJournalProofTrailerV2(FrozenModel):
    schema_version: Literal["acceptance-journal-proof-trailer.v2"]
    collector_id: SafeIdentifier
    entry_count: Annotated[int, Field(ge=1, le=4_371)]
    kind_counts: JournalKindCountsV2
    journal_final_root_sha256: Digest
    run_record_sha256: Digest

    @model_validator(mode="after")
    def entry_count_matches_kinds(self) -> AcceptanceJournalProofTrailerV2:
        if self.entry_count != self.kind_counts.total:
            raise ValueError("proof trailer count differs from kind inventory")
        return self


class TargetRunAttestationV2(FrozenModel):
    schema_version: Literal["target-run-attestation.v2"]
    journal_namespace_mode: Literal["protected"]
    collector_id: SafeIdentifier
    site_id: Annotated[str, Field(min_length=1, max_length=128)]
    manifest_sha256: Digest
    gate: Literal["8h", "72h"]
    offline_root_spki_sha256: Digest
    policy_id: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"),
    ]
    policy_sha256: Digest
    campaign_id: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"),
    ]
    manifest_payload_sha256: Digest
    launch_attestation_sha256: Digest
    execution_binding_sha256: Digest
    fault_schedule_sha256: Digest
    run_record_sha256: Digest
    journal_root_sha256: Digest
    journal_entry_count: Annotated[int, Field(ge=1, le=4_371)]
    public_key_spki_sha256: Digest
    journal_proof_sha256: Digest
    journal_proof_bytes: Annotated[
        int,
        Field(ge=1, le=MAX_ACCEPTANCE_JOURNAL_PROOF_BYTES),
    ]
    journal_proof_lines: Annotated[int, Field(ge=3, le=4_373)]
    journal_kind_counts: JournalKindCountsV2

    @model_validator(mode="after")
    def exact_gate_inventory(self) -> TargetRunAttestationV2:
        expected = JournalKindCountsV2.exact_for_gate(self.gate)
        if (
            self.journal_kind_counts != expected
            or self.journal_entry_count != expected.total
            or self.journal_proof_lines != expected.total + 2
        ):
            raise ValueError("target attestation does not bind the exact gate inventory")
        return self


class AcceptanceFinalEnvelopeV2(FrozenModel):
    """Signed, proof-bound final response accepted by protected target flows."""

    schema_version: Literal["acceptance-final-envelope.v2"]
    record: AcceptanceRunRecordV2
    attestation: TargetRunAttestationV2
    signature_hex: Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]


@dataclass(frozen=True)
class VerifiedAcceptanceJournalProofV2:
    header: AcceptanceJournalProofHeaderV2
    trailer: AcceptanceJournalProofTrailerV2
    proof_sha256: str
    proof_bytes: int
    line_count: int
    entry_count: int
    kind_counts: JournalKindCountsV2


@dataclass(frozen=True)
class PublishedAcceptanceProofV2:
    path: Path
    sha256: str
    byte_size: int


@dataclass(frozen=True)
class ExportedAcceptanceJournalProofV2:
    published: PublishedAcceptanceProofV2
    header: AcceptanceJournalProofHeaderV2
    trailer: AcceptanceJournalProofTrailerV2
    line_count: int


class AcceptanceProofStore:
    """Descriptor-relative, private, atomic no-replace proof publication."""

    def __init__(self, root: Path) -> None:
        if not root.is_absolute() or root.is_symlink():
            raise ValueError("acceptance proof root must be an absolute non-symlink")
        try:
            metadata = root.lstat()
        except OSError:
            raise ValueError("acceptance proof root is unavailable") from None
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_nlink < 1
        ):
            raise ValueError("acceptance proof root ownership or mode is unsafe")
        for ancestor in root.parents:
            ancestor_metadata = ancestor.lstat()
            if (
                stat.S_ISLNK(ancestor_metadata.st_mode)
                or not stat.S_ISDIR(ancestor_metadata.st_mode)
                or ancestor_metadata.st_uid not in {0, os.geteuid()}
                or (
                    ancestor_metadata.st_mode & 0o022
                    and not (
                        ancestor_metadata.st_uid == 0 and ancestor_metadata.st_mode & stat.S_ISVTX
                    )
                )
            ):
                raise ValueError("acceptance proof root ancestor is unsafe")
        self.root = root
        self._descriptor = os.open(
            root,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(self._descriptor)
        self._root_identity = (opened.st_dev, opened.st_ino)
        if self._root_identity != (metadata.st_dev, metadata.st_ino):
            os.close(self._descriptor)
            raise ValueError("acceptance proof root changed while opening")

    def __del__(self) -> None:
        descriptor = getattr(self, "_descriptor", -1)
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
            self._descriptor = -1

    @staticmethod
    def _filename(collector_id: str) -> str:
        if (
            not isinstance(collector_id, str)
            or not 1 <= len(collector_id) <= 160
            or any(ord(character) < 32 for character in collector_id)
        ):
            raise ValueError("acceptance proof collector identity is invalid")
        return f"journal-{hashlib.sha256(collector_id.encode()).hexdigest()}.jsonl"

    def _validate_root(self) -> None:
        try:
            path_metadata = self.root.lstat()
            opened = os.fstat(self._descriptor)
        except OSError:
            raise RuntimeError("acceptance proof root identity changed") from None
        if (
            stat.S_ISLNK(path_metadata.st_mode)
            or not stat.S_ISDIR(path_metadata.st_mode)
            or path_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(path_metadata.st_mode) != 0o700
            or (path_metadata.st_dev, path_metadata.st_ino) != self._root_identity
            or (opened.st_dev, opened.st_ino) != self._root_identity
        ):
            raise RuntimeError("acceptance proof root identity changed")
        for ancestor in self.root.parents:
            try:
                ancestor_metadata = ancestor.lstat()
            except OSError:
                raise RuntimeError("acceptance proof root ancestor changed") from None
            if (
                stat.S_ISLNK(ancestor_metadata.st_mode)
                or not stat.S_ISDIR(ancestor_metadata.st_mode)
                or ancestor_metadata.st_uid not in {0, os.geteuid()}
                or (
                    ancestor_metadata.st_mode & 0o022
                    and not (
                        ancestor_metadata.st_uid == 0 and ancestor_metadata.st_mode & stat.S_ISVTX
                    )
                )
            ):
                raise RuntimeError("acceptance proof root ancestor changed")

    def _open_name(self, name: str) -> int:
        self._validate_root()
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=self._descriptor,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= MAX_ACCEPTANCE_JOURNAL_PROOF_BYTES
            or metadata.st_dev != self._root_identity[0]
        ):
            os.close(descriptor)
            raise RuntimeError("acceptance proof artifact is unsafe")
        return descriptor

    @staticmethod
    def _digest_descriptor(descriptor: int) -> tuple[str, int]:
        before = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        consumed = 0
        while chunk := os.read(
            descriptor,
            min(1024 * 1024, MAX_ACCEPTANCE_JOURNAL_PROOF_BYTES + 1 - consumed),
        ):
            digest.update(chunk)
            consumed += len(chunk)
            if consumed > MAX_ACCEPTANCE_JOURNAL_PROOF_BYTES:
                raise RuntimeError("acceptance proof artifact exceeds its finite bound")
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
            raise RuntimeError("acceptance proof artifact changed while hashing")
        return digest.hexdigest(), consumed

    def publish_bytes(
        self,
        collector_id: str,
        payload: bytes,
    ) -> PublishedAcceptanceProofV2:
        if (
            not isinstance(payload, bytes)
            or not 0 < len(payload) <= MAX_ACCEPTANCE_JOURNAL_PROOF_BYTES
        ):
            raise ValueError("acceptance proof payload is empty or unbounded")
        return self.publish_chunks(collector_id, (payload,))

    def publish_chunks(
        self,
        collector_id: str,
        chunks: object,
    ) -> PublishedAcceptanceProofV2:
        name = self._filename(collector_id)
        temporary = f".{name}.tmp-{secrets.token_hex(16)}"
        self._validate_root()
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=self._descriptor,
        )
        digest = hashlib.sha256()
        consumed = 0
        try:
            for chunk in chunks:  # type: ignore[union-attr]
                if not isinstance(chunk, bytes) or not chunk:
                    raise ValueError("acceptance proof publisher requires nonempty byte chunks")
                consumed += len(chunk)
                if consumed > MAX_ACCEPTANCE_JOURNAL_PROOF_BYTES:
                    raise ValueError("acceptance proof exceeds its finite bound")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("short acceptance proof write")
                    view = view[written:]
            if consumed == 0:
                raise ValueError("acceptance proof is empty")
            os.fsync(descriptor)
        except BaseException:
            os.close(descriptor)
            os.unlink(temporary, dir_fd=self._descriptor)
            raise
        os.close(descriptor)
        expected = (digest.hexdigest(), consumed)
        try:
            os.link(
                temporary,
                name,
                src_dir_fd=self._descriptor,
                dst_dir_fd=self._descriptor,
                follow_symlinks=False,
            )
            os.unlink(temporary, dir_fd=self._descriptor)
            os.fsync(self._descriptor)
        except FileExistsError:
            os.unlink(temporary, dir_fd=self._descriptor)
            existing = self.open_verified(collector_id)
            if (existing.sha256, existing.byte_size) != expected:
                raise RuntimeError("existing acceptance proof differs from finalized journal")
            return existing
        except BaseException:
            try:
                os.unlink(temporary, dir_fd=self._descriptor)
            except OSError:
                pass
            raise
        published = self.open_verified(collector_id)
        if (published.sha256, published.byte_size) != expected:
            raise RuntimeError("published acceptance proof differs from streamed bytes")
        return published

    def open_verified(self, collector_id: str) -> PublishedAcceptanceProofV2:
        name = self._filename(collector_id)
        descriptor = self._open_name(name)
        try:
            digest, consumed = self._digest_descriptor(descriptor)
        finally:
            os.close(descriptor)
        return PublishedAcceptanceProofV2(
            path=self.root / name,
            sha256=digest,
            byte_size=consumed,
        )

    def iter_bytes(
        self,
        collector_id: str,
        *,
        chunk_size: int = 1024 * 1024,
    ) -> object:
        if not 1 <= chunk_size <= 1024 * 1024:
            raise ValueError("acceptance proof stream chunk size is invalid")
        name = self._filename(collector_id)

        def stream() -> object:
            descriptor = self._open_name(name)
            try:
                while chunk := os.read(descriptor, chunk_size):
                    yield chunk
            finally:
                os.close(descriptor)

        return stream()


def canonical_proof_line(value: FrozenModel) -> bytes:
    payload = canonical_json_bytes(value)
    if len(payload) > MAX_ACCEPTANCE_JOURNAL_PROOF_LINE_BYTES:
        raise ValueError("acceptance proof line exceeds its finite bound")
    return payload + b"\n"


def journal_entry_sha256(
    *,
    collector_id: str,
    kind: str,
    identity: str,
    payload_json: str,
    created_at: str,
    previous_entry_sha256: str,
) -> str:
    """Reproduce the exact durable SQLite journal entry digest."""
    return hashlib.sha256(
        json.dumps(
            {
                "collector_id": collector_id,
                "kind": kind,
                "identity": identity,
                "payload_json": payload_json,
                "created_at": created_at,
                "previous_entry_sha256": previous_entry_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _read_proof_line(
    handle: object,
    *,
    digest: object,
    consumed: int,
    line_number: int,
) -> tuple[bytes, int]:
    line = handle.readline(MAX_ACCEPTANCE_JOURNAL_PROOF_LINE_BYTES + 2)  # type: ignore[attr-defined]
    if not line:
        return b"", consumed
    if len(line) > MAX_ACCEPTANCE_JOURNAL_PROOF_LINE_BYTES + 1 or not line.endswith(b"\n"):
        raise ValueError("acceptance journal proof has invalid newline framing")
    consumed += len(line)
    if consumed > MAX_ACCEPTANCE_JOURNAL_PROOF_BYTES:
        raise ValueError("acceptance journal proof exceeds its finite byte bound")
    if line == b"\n":
        raise ValueError("acceptance journal proof contains an empty line")
    digest.update(line)  # type: ignore[attr-defined]
    if line_number > 4_373:
        raise ValueError("acceptance journal proof exceeds its line bound")
    return line[:-1], consumed


def verify_acceptance_journal_proof(
    path: Path,
    *,
    expected_attestation: TargetRunAttestationV2,
    expected_run_record: AcceptanceRunRecordV2 | None = None,
) -> VerifiedAcceptanceJournalProofV2:
    """Stream and replay one canonical proof without retaining journal history."""
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= MAX_ACCEPTANCE_JOURNAL_PROOF_BYTES
        ):
            raise ValueError("acceptance journal proof is not one bounded regular file")
        digest = hashlib.sha256()
        consumed = 0
        line_number = 1
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw_header, consumed = _read_proof_line(
                handle,
                digest=digest,
                consumed=consumed,
                line_number=line_number,
            )
            if not raw_header:
                raise ValueError("acceptance journal proof is empty")
            header = load_canonical_json_bytes(
                raw_header,
                AcceptanceJournalProofHeaderV2,
                max_bytes=_MAX_HEADER_BYTES,
                label="acceptance journal proof header",
            )
            previous = ""
            ordinal = 0
            identities: set[tuple[str, str]] = set()
            counts: dict[str, int] = {name: 0 for name in JournalKindCountsV2.model_fields}
            finalize_payload_sha256: str | None = None
            trailer: AcceptanceJournalProofTrailerV2 | None = None
            while True:
                line_number += 1
                raw, consumed = _read_proof_line(
                    handle,
                    digest=digest,
                    consumed=consumed,
                    line_number=line_number,
                )
                if not raw:
                    break
                parsed = _load_canonical_json_object(
                    raw,
                    max_bytes=MAX_ACCEPTANCE_JOURNAL_PROOF_LINE_BYTES,
                    label="acceptance journal proof line",
                )
                schema_version = parsed.get("schema_version")
                if schema_version == "acceptance-journal-proof-trailer.v2":
                    trailer = load_canonical_json_bytes(
                        raw,
                        AcceptanceJournalProofTrailerV2,
                        max_bytes=_MAX_TRAILER_BYTES,
                        label="acceptance journal proof trailer",
                    )
                    extra, consumed = _read_proof_line(
                        handle,
                        digest=digest,
                        consumed=consumed,
                        line_number=line_number + 1,
                    )
                    if extra:
                        raise ValueError("acceptance journal proof contains trailing content")
                    break
                entry = load_canonical_json_bytes(
                    raw,
                    AcceptanceJournalProofEntryV2,
                    max_bytes=MAX_ACCEPTANCE_JOURNAL_PROOF_LINE_BYTES,
                    label="acceptance journal proof entry",
                )
                ordinal += 1
                identity = (entry.kind, entry.identity)
                payload_json = canonical_json_bytes(entry.payload).decode()
                expected_hash = journal_entry_sha256(
                    collector_id=entry.collector_id,
                    kind=entry.kind,
                    identity=entry.identity,
                    payload_json=payload_json,
                    created_at=entry.created_at,
                    previous_entry_sha256=previous,
                )
                if (
                    entry.ordinal != ordinal
                    or entry.collector_id != header.collector_id
                    or entry.previous_entry_sha256 != previous
                    or entry.entry_sha256 != expected_hash
                    or identity in identities
                    or (ordinal == 1 and entry.kind != "start")
                    or (counts["finalize"] and entry.kind != "finalize")
                ):
                    raise ValueError("acceptance journal proof chain is invalid")
                identities.add(identity)
                counts[entry.kind] += 1
                if counts["finalize"] > 1:
                    raise ValueError("acceptance journal proof has multiple final records")
                if entry.kind == "finalize":
                    finalize_payload_sha256 = hashlib.sha256(
                        canonical_json_bytes(entry.payload)
                    ).hexdigest()
                previous = entry.entry_sha256
            if trailer is None:
                raise ValueError("acceptance journal proof trailer is missing")
        after = os.fstat(descriptor)
        if consumed != metadata.st_size or (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValueError("acceptance journal proof changed while streaming")
    finally:
        os.close(descriptor)
    kind_counts = JournalKindCountsV2.model_validate(counts)
    proof_sha256 = digest.hexdigest()
    launch_sha256 = header.launch.attestation_sha256
    execution_sha256 = header.execution.binding_sha256
    fault_schedule_sha256 = canonical_fault_schedule_sha256(header.fault_schedule)
    if (
        header.collector_id != expected_attestation.collector_id
        or header.site_id != expected_attestation.site_id
        or header.manifest_sha256 != expected_attestation.manifest_sha256
        or header.gate != expected_attestation.gate
        or header.offline_root_spki_sha256 != expected_attestation.offline_root_spki_sha256
        or header.policy_id != expected_attestation.policy_id
        or header.policy_sha256 != expected_attestation.policy_sha256
        or header.campaign_id != expected_attestation.campaign_id
        or header.manifest_payload_sha256 != expected_attestation.manifest_payload_sha256
        or header.launch_attestation_sha256 != expected_attestation.launch_attestation_sha256
        or header.execution_binding_sha256 != expected_attestation.execution_binding_sha256
        or header.fault_schedule_sha256 != expected_attestation.fault_schedule_sha256
        or header.public_run_authority_spki_sha256 != expected_attestation.public_key_spki_sha256
        or launch_sha256 != header.launch_attestation_sha256
        or execution_sha256 != header.execution_binding_sha256
        or fault_schedule_sha256 != header.fault_schedule_sha256
        or trailer.collector_id != header.collector_id
        or trailer.entry_count != ordinal
        or trailer.kind_counts != kind_counts
        or trailer.journal_final_root_sha256 != previous
        or finalize_payload_sha256 != trailer.run_record_sha256
        or trailer.run_record_sha256 != expected_attestation.run_record_sha256
        or expected_attestation.journal_root_sha256 != previous
        or expected_attestation.journal_entry_count != ordinal
        or expected_attestation.journal_kind_counts != kind_counts
        or expected_attestation.journal_proof_sha256 != proof_sha256
        or expected_attestation.journal_proof_bytes != consumed
        or expected_attestation.journal_proof_lines != line_number
        or kind_counts != JournalKindCountsV2.exact_for_gate(header.gate)
        or not math.isfinite(float(consumed))
    ):
        raise ValueError("acceptance journal proof differs from its V2 attestation")
    if expected_run_record is not None and (
        finalize_payload_sha256
        != hashlib.sha256(canonical_json_bytes(expected_run_record)).hexdigest()
        or header.site_id != expected_run_record.site_id
        or header.manifest_sha256 != expected_run_record.manifest_sha256
        or header.gate != expected_run_record.gate
        or header.camera_ids != tuple(camera.camera_id for camera in expected_run_record.cameras)
        or canonical_json_bytes(header.launch) != canonical_json_bytes(expected_run_record.launch)
        or expected_run_record.execution is None
        or canonical_json_bytes(header.execution)
        != canonical_json_bytes(expected_run_record.execution)
        or tuple(
            (
                fault.fault_id,
                fault.kind,
                fault.target,
                fault.monotonic_offset_seconds,
                fault.duration_seconds,
                fault.expected_degraded,
                fault.expected_recovery,
            )
            for fault in expected_run_record.faults
        )
        != tuple(
            (
                fault.fault_id,
                fault.kind,
                fault.target,
                fault.offset_seconds,
                fault.duration_seconds,
                fault.expected_degraded,
                fault.expected_recovery,
            )
            for fault in header.fault_schedule
        )
    ):
        raise ValueError("acceptance journal proof final record differs from supplied evidence")
    return VerifiedAcceptanceJournalProofV2(
        header=header,
        trailer=trailer,
        proof_sha256=proof_sha256,
        proof_bytes=consumed,
        line_count=line_number,
        entry_count=ordinal,
        kind_counts=kind_counts,
    )
