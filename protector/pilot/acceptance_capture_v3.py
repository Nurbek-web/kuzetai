"""Protected durable provider capture for collector-bound V3 finalization."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from protector.pilot.acceptance import (
    AcceptanceManifestV2,
    AcceptanceRunRecordV2,
    ConditionalGateAttestationV2,
)
from protector.pilot.acceptance_authority import (
    AcceptanceAuthorityTrustContextV2,
    _require_authority_trust_context,
)
from protector.pilot.acceptance_c2 import (
    SignedTargetAuthorityBindingV3,
    TargetAuthorityBindingV3,
    require_target_authority_continuation_v3,
    verify_signed_target_authority_v3,
)
from protector.pilot.acceptance_controller_v3 import (
    AcceptanceEvidenceCaptureV3,
    DurableV2EvidenceV3,
)
from protector.pilot.acceptance_operational import (
    AcceptanceLimitsV1,
    AuthoritativeRepositoryBoundaryV1,
    OperationalAcceptanceEvidenceV1,
)
from protector.pilot.acceptance_proof import (
    MAX_ACCEPTANCE_JOURNAL_PROOF_BYTES,
    AcceptanceFinalEnvelopeV2,
    verify_acceptance_journal_proof,
)
from protector.pilot.acceptance_trust import (
    canonical_json_bytes,
    load_canonical_json_bytes,
)
from protector.pilot.config import FrozenModel

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
SafeId = Annotated[
    str,
    Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$"),
]
MAX_ACCEPTANCE_CAPTURE_BYTES = 64 * 1024 * 1024


class AcceptanceCaptureRecordV3(FrozenModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    schema_version: Literal["acceptance-provider-capture.v3"]
    collector_id: SafeId
    campaign_id: SafeId
    offline_root_spki_sha256: Digest
    policy_id: SafeId
    policy_sha256: Digest
    manifest_payload_sha256: Digest
    controller_image_sha256: Digest
    controller_code_sha256: Digest
    signed_target_authority: SignedTargetAuthorityBindingV3
    target_authority: TargetAuthorityBindingV3
    manifest: AcceptanceManifestV2
    run_record: AcceptanceRunRecordV2
    operational_limits: AcceptanceLimitsV1
    operational_evidence: OperationalAcceptanceEvidenceV1
    repository_boundary: AuthoritativeRepositoryBoundaryV1
    conditional_gate_decisions: tuple[ConditionalGateAttestationV2, ...]
    final_envelope_v2: AcceptanceFinalEnvelopeV2
    journal_proof_v2_sha256: Digest

    @field_validator("conditional_gate_decisions", mode="before")
    @classmethod
    def decisions_are_finite(cls, value: object) -> object:
        if type(value) not in {tuple, list}:
            raise TypeError("conditional gate decisions must be one finite sequence")
        return tuple(ConditionalGateAttestationV2.model_validate(item) for item in value)

    @model_validator(mode="after")
    def exact_graph(self) -> AcceptanceCaptureRecordV3:
        if (
            self.collector_id != self.run_record.run_id
            or self.collector_id != self.final_envelope_v2.record.run_id
            or self.final_envelope_v2.record != self.run_record
            or self.target_authority.collector_id != self.collector_id
            or self.signed_target_authority.binding != self.target_authority
            or self.target_authority.site_id != self.run_record.site_id
            or self.target_authority.campaign_id != self.campaign_id
            or self.target_authority.gate != self.run_record.gate
            or self.target_authority.journal_proof_sha256
            != self.journal_proof_v2_sha256
            or self.target_authority.v2_run_record_sha256
            != hashlib.sha256(canonical_json_bytes(self.run_record)).hexdigest()
            or self.target_authority.v2_run_attestation_sha256
            != hashlib.sha256(
                canonical_json_bytes(self.final_envelope_v2.attestation)
            ).hexdigest()
            or self.target_authority.v2_journal_root_sha256
            != self.final_envelope_v2.attestation.journal_root_sha256
            or self.target_authority.journal_proof_sha256
            != self.final_envelope_v2.attestation.journal_proof_sha256
            or self.manifest.site_id != self.run_record.site_id
            or self.manifest.manifest_sha256 != self.run_record.manifest_sha256
            or self.repository_boundary.site_id != self.run_record.site_id
            or self.repository_boundary.manifest_sha256
            != self.run_record.manifest_sha256
        ):
            raise ValueError("acceptance provider capture graph differs")
        return self


def _read_file(path: Path, *, max_bytes: int) -> bytes:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError("acceptance capture artifact path must be absolute")
    directory = os.open(
        path.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        return _read_file_at(
            directory,
            path.name,
            max_bytes=max_bytes,
        )
    finally:
        os.close(directory)


def _read_file_at(
    directory: int,
    name: str,
    *,
    max_bytes: int,
) -> bytes:
    parent = os.fstat(directory)
    if (
        type(name) is not str
        or not name
        or "/" in name
        or name in {".", ".."}
        or not stat.S_ISDIR(parent.st_mode)
    ):
        raise ValueError("acceptance capture artifact name is invalid")
    descriptor = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=directory,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 1 <= before.st_size <= max_bytes
            or before.st_dev != parent.st_dev
        ):
            raise ValueError("acceptance capture artifact is unsafe or unbounded")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise ValueError("acceptance capture artifact changed while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError(
                "acceptance capture artifact exceeds its captured size"
            )
        after = os.fstat(descriptor)
        leaf = os.stat(name, dir_fd=directory, follow_symlinks=False)
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
        ) or (leaf.st_dev, leaf.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("acceptance capture artifact changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _publish_file_at(directory: int, name: str, payload: bytes) -> bool:
    """No-replace publication relative to one pinned private directory."""

    if (
        type(name) is not str
        or not name
        or "/" in name
        or name in {".", ".."}
        or type(payload) is not bytes
        or not payload
    ):
        raise ValueError("acceptance capture publication input is invalid")
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=directory,
        )
    except FileExistsError:
        if _read_file_at(directory, name, max_bytes=len(payload)) != payload:
            raise RuntimeError("acceptance capture replacement is forbidden")
        return False
    created = True
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("acceptance capture write made no progress")
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        leaf = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != len(payload)
            or metadata.st_dev != os.fstat(directory).st_dev
            or (metadata.st_dev, metadata.st_ino)
            != (leaf.st_dev, leaf.st_ino)
        ):
            raise RuntimeError("acceptance capture publication identity changed")
    except BaseException as primary:
        failures: list[BaseException] = [primary]
        try:
            os.close(descriptor)
        except BaseException as cleanup:
            failures.append(cleanup)
        if created:
            try:
                os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                pass
            except BaseException as cleanup:
                failures.append(cleanup)
        try:
            os.fsync(directory)
        except BaseException as cleanup:
            failures.append(cleanup)
        if len(failures) == 1:
            raise
        raise BaseExceptionGroup(
            "acceptance capture publication and rollback failed",
            failures,
        ) from primary
    try:
        os.close(descriptor)
        os.fsync(directory)
    except BaseException as cleanup:
        if created:
            try:
                os.unlink(name, dir_fd=directory)
                os.fsync(directory)
            except BaseException as rollback:
                raise BaseExceptionGroup(
                    "acceptance capture durability and rollback failed",
                    [cleanup, rollback],
                ) from cleanup
        raise
    return True


class ProtectedAcceptanceCaptureRepositoryV3:
    """No-replace repository linking target authority to one contiguous DB capture."""

    def __init__(
        self,
        root: Path,
        *,
        trust_context: AcceptanceAuthorityTrustContextV2,
    ) -> None:
        if not root.is_absolute() or root.is_symlink():
            raise ValueError("acceptance capture root must be an absolute non-symlink")
        metadata = root.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ValueError("acceptance capture root must be private and owner controlled")
        self.root = root
        self._identity = (metadata.st_dev, metadata.st_ino)
        self._trust_context = _require_authority_trust_context(trust_context)

    @staticmethod
    def _stem(collector_id: str) -> str:
        if type(collector_id) is not str or not 1 <= len(collector_id) <= 160:
            raise ValueError("acceptance capture collector identity is invalid")
        return hashlib.sha256(collector_id.encode()).hexdigest()

    def _paths(self, collector_id: str) -> tuple[Path, Path]:
        stem = self._stem(collector_id)
        return (
            self.root / f"capture-{stem}.json",
            self.root / f"v2-proof-{stem}.jsonl",
        )

    def readiness_probe(self) -> None:
        metadata = self.root.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != os.geteuid()
            or (metadata.st_dev, metadata.st_ino) != self._identity
        ):
            raise RuntimeError("acceptance capture root identity changed")

    def publish(self, capture: AcceptanceEvidenceCaptureV3) -> None:
        if type(capture) is not AcceptanceEvidenceCaptureV3:
            raise TypeError("exact controller provider capture is required")
        target = require_target_authority_continuation_v3(
            verify_signed_target_authority_v3(
                capture.signed_target_authority,
                trust_context=self._trust_context,
            )
        )
        trust = self._trust_context.trust
        if (
            capture.campaign_id != self._trust_context.configured_campaign_id
            or capture.offline_root_spki_sha256 != trust.root_spki_sha256
            or capture.policy_id != trust.policy.policy_id
            or capture.policy_sha256 != trust.policy_sha256
            or capture.manifest_payload_sha256
            != trust.manifest_payload_sha256
            or capture.manifest != trust.manifest
        ):
            raise ValueError("provider capture differs from pinned acceptance trust")
        source_proof = _read_file(
            capture.journal_proof_v2_path,
            max_bytes=MAX_ACCEPTANCE_JOURNAL_PROOF_BYTES,
        )
        proof = verify_acceptance_journal_proof(
            capture.journal_proof_v2_path,
            expected_attestation=capture.final_envelope_v2.attestation,
            expected_run_record=capture.run_record,
        )
        if (
            proof.proof_sha256 != target.journal_proof_sha256
            or proof.trailer.journal_final_root_sha256
            != target.v2_journal_root_sha256
            or proof.trailer.run_record_sha256
            != target.v2_run_record_sha256
        ):
            raise ValueError("provider V2 proof differs from target authority")
        record = AcceptanceCaptureRecordV3(
            schema_version="acceptance-provider-capture.v3",
            collector_id=capture.collector_id,
            campaign_id=capture.campaign_id,
            offline_root_spki_sha256=capture.offline_root_spki_sha256,
            policy_id=capture.policy_id,
            policy_sha256=capture.policy_sha256,
            manifest_payload_sha256=capture.manifest_payload_sha256,
            controller_image_sha256=capture.controller_image_sha256,
            controller_code_sha256=capture.controller_code_sha256,
            signed_target_authority=capture.signed_target_authority,
            target_authority=target,
            manifest=capture.manifest,
            run_record=capture.run_record,
            operational_limits=capture.operational_limits,
            operational_evidence=capture.operational_evidence,
            repository_boundary=capture.repository_boundary,
            conditional_gate_decisions=capture.conditional_gate_decisions,
            final_envelope_v2=capture.final_envelope_v2,
            journal_proof_v2_sha256=proof.proof_sha256,
        )
        record_payload = canonical_json_bytes(record)
        if not 1 <= len(record_payload) <= MAX_ACCEPTANCE_CAPTURE_BYTES:
            raise ValueError("acceptance provider capture exceeds its finite bound")
        if hashlib.sha256(source_proof).hexdigest() != proof.proof_sha256:
            raise ValueError("provider V2 proof changed during capture")
        record_path, proof_path = self._paths(capture.collector_id)
        # The record is the commit marker, so publish proof bytes first.
        directory = os.open(
            self.root,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        proof_created = False
        try:
            opened = os.fstat(directory)
            if (opened.st_dev, opened.st_ino) != self._identity:
                raise RuntimeError("acceptance capture root identity changed")
            proof_created = _publish_file_at(
                directory,
                proof_path.name,
                source_proof,
            )
            _publish_file_at(
                directory,
                record_path.name,
                record_payload,
            )
        except BaseException as primary:
            failures: list[BaseException] = [primary]
            if proof_created:
                try:
                    os.unlink(proof_path.name, dir_fd=directory)
                    os.fsync(directory)
                except FileNotFoundError:
                    pass
                except BaseException as cleanup:
                    failures.append(cleanup)
            try:
                os.close(directory)
            except BaseException as cleanup:
                failures.append(cleanup)
            if len(failures) == 1:
                raise
            raise BaseExceptionGroup(
                "acceptance capture transaction and rollback failed",
                failures,
            ) from primary
        os.close(directory)
        self.readiness_probe()

    def _record(self, collector_id: str) -> tuple[AcceptanceCaptureRecordV3, Path]:
        self.readiness_probe()
        record_path, proof_path = self._paths(collector_id)
        directory = os.open(
            self.root,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            opened = os.fstat(directory)
            if (opened.st_dev, opened.st_ino) != self._identity:
                raise RuntimeError(
                    "acceptance capture root identity changed"
                )
            record_payload = _read_file_at(
                directory,
                record_path.name,
                max_bytes=MAX_ACCEPTANCE_CAPTURE_BYTES,
            )
            proof_payload = _read_file_at(
                directory,
                proof_path.name,
                max_bytes=MAX_ACCEPTANCE_JOURNAL_PROOF_BYTES,
            )
        finally:
            os.close(directory)
        record = load_canonical_json_bytes(
            record_payload,
            AcceptanceCaptureRecordV3,
            max_bytes=MAX_ACCEPTANCE_CAPTURE_BYTES,
            label="acceptance provider capture",
        )
        target = require_target_authority_continuation_v3(
            verify_signed_target_authority_v3(
                record.signed_target_authority,
                trust_context=self._trust_context,
            )
        )
        trust = self._trust_context.trust
        if (
            record.collector_id != collector_id
            or target != record.target_authority
            or record.campaign_id != self._trust_context.configured_campaign_id
            or record.offline_root_spki_sha256 != trust.root_spki_sha256
            or record.policy_id != trust.policy.policy_id
            or record.policy_sha256 != trust.policy_sha256
            or record.manifest_payload_sha256
            != trust.manifest_payload_sha256
            or record.manifest != trust.manifest
        ):
            raise ValueError("acceptance provider collector identity differs")
        proof = verify_acceptance_journal_proof(
            proof_path,
            expected_attestation=record.final_envelope_v2.attestation,
            expected_run_record=record.run_record,
        )
        if (
            hashlib.sha256(proof_payload).hexdigest()
            != record.journal_proof_v2_sha256
            or
            proof.proof_sha256 != record.journal_proof_v2_sha256
            or proof.trailer.journal_final_root_sha256
            != record.target_authority.v2_journal_root_sha256
        ):
            raise ValueError("acceptance provider proof digest differs")
        return record, proof_path

    def capture_for_snapshot(self, collector_id: str) -> AcceptanceEvidenceCaptureV3:
        record, proof_path = self._record(collector_id)
        return AcceptanceEvidenceCaptureV3(
            collector_id=record.collector_id,
            campaign_id=record.campaign_id,
            offline_root_spki_sha256=record.offline_root_spki_sha256,
            policy_id=record.policy_id,
            policy_sha256=record.policy_sha256,
            manifest_payload_sha256=record.manifest_payload_sha256,
            controller_image_sha256=record.controller_image_sha256,
            controller_code_sha256=record.controller_code_sha256,
            signed_target_authority=record.signed_target_authority,
            manifest=record.manifest,
            run_record=record.run_record,
            operational_limits=record.operational_limits,
            operational_evidence=record.operational_evidence,
            repository_boundary=record.repository_boundary,
            conditional_gate_decisions=record.conditional_gate_decisions,
            final_envelope_v2=record.final_envelope_v2,
            journal_proof_v2_path=proof_path,
        )

    def load_durable_v2_evidence(self, collector_id: str) -> DurableV2EvidenceV3:
        record, proof_path = self._record(collector_id)
        return DurableV2EvidenceV3(
            final_envelope=record.final_envelope_v2,
            journal_proof_path=proof_path,
        )


class ReviewedAcceptanceCaptureProducerV3:
    """Build one provider capture from reviewed non-secret controller values."""

    def __init__(
        self,
        *,
        trust_context: AcceptanceAuthorityTrustContextV2,
        controller_image_sha256: str,
        controller_code_sha256: str,
        operational_limits: AcceptanceLimitsV1,
        operational_evidence: OperationalAcceptanceEvidenceV1,
        repository_boundary: AuthoritativeRepositoryBoundaryV1,
        conditional_gate_decisions: tuple[
            ConditionalGateAttestationV2,
            ...,
        ],
    ) -> None:
        context = _require_authority_trust_context(trust_context)
        values = (controller_image_sha256, controller_code_sha256)
        if any(
            type(value) is not str
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in values
        ):
            raise ValueError("acceptance capture controller identity is invalid")
        if (
            type(operational_limits) is not AcceptanceLimitsV1
            or type(operational_evidence)
            is not OperationalAcceptanceEvidenceV1
            or type(repository_boundary)
            is not AuthoritativeRepositoryBoundaryV1
            or type(conditional_gate_decisions) is not tuple
            or any(
                type(decision) is not ConditionalGateAttestationV2
                for decision in conditional_gate_decisions
            )
        ):
            raise TypeError(
                "acceptance capture requires exact typed operational inputs"
            )
        self._trust_context = context
        self._controller_image_sha256 = controller_image_sha256
        self._controller_code_sha256 = controller_code_sha256
        self._operational_limits = AcceptanceLimitsV1.model_validate(
            operational_limits.model_dump(mode="python")
        )
        self._operational_evidence = OperationalAcceptanceEvidenceV1.model_validate(
            operational_evidence.model_dump(mode="python")
        )
        self._repository_boundary = AuthoritativeRepositoryBoundaryV1.model_validate(
            repository_boundary.model_dump(mode="python")
        )
        self._conditional_gate_decisions = tuple(
            ConditionalGateAttestationV2.model_validate(
                decision.model_dump(mode="python")
            )
            for decision in conditional_gate_decisions
        )

    def capture(
        self,
        *,
        signed_target_authority: SignedTargetAuthorityBindingV3,
        final_envelope_v2: AcceptanceFinalEnvelopeV2,
        journal_proof_v2_path: Path,
    ) -> AcceptanceEvidenceCaptureV3:
        if (
            type(final_envelope_v2) is not AcceptanceFinalEnvelopeV2
            or not isinstance(journal_proof_v2_path, Path)
        ):
            raise TypeError(
                "acceptance capture requires exact final evidence inputs"
            )
        target = require_target_authority_continuation_v3(
            verify_signed_target_authority_v3(
                signed_target_authority,
                trust_context=self._trust_context,
            )
        )
        envelope = AcceptanceFinalEnvelopeV2.model_validate(
            final_envelope_v2.model_dump(mode="python")
        )
        if (
            target.collector_id != envelope.record.run_id
            or target.site_id != envelope.record.site_id
            or target.gate != envelope.record.gate
            or target.campaign_id
            != self._trust_context.configured_campaign_id
            or not journal_proof_v2_path.is_absolute()
        ):
            raise ValueError("acceptance capture producer graph differs")
        trust = self._trust_context.trust
        return AcceptanceEvidenceCaptureV3(
            collector_id=target.collector_id,
            campaign_id=target.campaign_id,
            offline_root_spki_sha256=trust.root_spki_sha256,
            policy_id=trust.policy.policy_id,
            policy_sha256=trust.policy_sha256,
            manifest_payload_sha256=trust.manifest_payload_sha256,
            controller_image_sha256=self._controller_image_sha256,
            controller_code_sha256=self._controller_code_sha256,
            signed_target_authority=signed_target_authority,
            manifest=trust.manifest,
            run_record=envelope.record,
            operational_limits=self._operational_limits,
            operational_evidence=self._operational_evidence,
            repository_boundary=self._repository_boundary,
            conditional_gate_decisions=self._conditional_gate_decisions,
            final_envelope_v2=envelope,
            journal_proof_v2_path=journal_proof_v2_path,
        )


__all__ = (
    "AcceptanceCaptureRecordV3",
    "ProtectedAcceptanceCaptureRepositoryV3",
    "ReviewedAcceptanceCaptureProducerV3",
)
