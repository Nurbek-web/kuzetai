"""Transactional repositories enforcing pilot lifecycle and notification invariants."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, Literal
from uuid import UUID, uuid4

from sqlalchemy import Select, and_, delete, func, or_, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, object_session

from protector.pilot.api.auth import prepare_username
from protector.pilot.domain import (
    CameraEpochActivationReceiptV1,
    CandidateEventProvenanceV1,
    CandidateEventV1,
    ConfigurationActivationReceiptV1,
    LegacyCandidateImportV1,
    NotificationOutboxRecordV1,
    ObservationV1,
    PersistedCandidateEventV2,
    ProvenancedCandidateEventV2,
    ReviewStatus,
    RuntimeWriterReceiptV1,
    _issue_runtime_writer_receipt,
)
from protector.pilot.gates import ModelArtifactV1
from protector.pilot.operational_retention import (
    OperationalMetadataPruneCounts,
)
from protector.pilot.rules import (
    VerifiedCameraRulesetRevision,
    VerifiedModelGateDecision,
    VerifiedSiteConfigRevision,
    compile_verified_camera_rules,
)
from protector.pilot.storage.db import SessionFactory
from protector.pilot.storage.journal import validate_journal_work
from protector.pilot.storage.models import (
    ActivePilotConfigurationModel,
    AuditEntryModel,
    CameraHealthSampleModel,
    CameraEpochAuthorityModel,
    CameraEpochHistoryModel,
    CameraModel,
    CameraRuleRevisionModel,
    CameraRulesetRevisionModel,
    CandidateEventModel,
    CandidateEventProvenanceModel,
    ConfigurationActivationModel,
    DeliveryAttemptModel,
    EvidenceModel,
    LegacyCandidateImportModel,
    ModelArtifactModel,
    NotificationOutboxModel,
    ObservationModel,
    PreviewAccessReceiptModel,
    PreviewPublicationModel,
    ReviewModel,
    RuntimeWriterAuthorityModel,
    RuntimeWriterSessionModel,
    SiteConfigRevisionModel,
    SiteModel,
    TelemetryPublisherEpochModel,
    UserModel,
)
from protector.pilot.totp_envelope import TOTP_ROTATION_INSTRUCTION, TotpEnvelopeProtector

if TYPE_CHECKING:
    from protector.pilot.storage.preview import (
        PreviewAccessReceipt,
        PreviewObjectContext,
        PreviewObjectReceiptV1,
        PreviewPublicationIntentV1,
    )


_PREVIEW_MAX_BYTES = 16 * 1024 * 1024


class IdempotencyConflictError(ValueError):
    """An idempotency key was reused for different work."""


class StaleStateError(ValueError):
    """The caller's expected event state no longer matches persisted state."""

    def __init__(self, *, expected: str, actual: str) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(f"expected {expected}, found {actual}")


class SoleSiteRequiredError(RuntimeError):
    """Auth lifecycle writes require exactly one authoritative site."""


class BootstrapAlreadyCompletedError(RuntimeError):
    """The one-shot first-admin bootstrap has already been consumed."""


class LastActiveAdminError(ValueError):
    """A mutation would leave the pilot without an active administrator."""


class UsernameConflictError(ValueError):
    """A canonical username identity is already assigned."""


class StaleAuthGenerationError(ValueError):
    """An auth mutation targeted an outdated durable generation."""

    def __init__(self, *, expected: int, actual: int) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(f"expected auth generation {expected}, found {actual}")


class StaleActivationGenerationError(ValueError):
    """A configuration activation CAS targeted an outdated generation."""

    def __init__(self, *, expected: int, actual: int) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"expected activation generation {expected}, found {actual}"
        )


class StaleRuntimeWriterGenerationError(ValueError):
    """A writer-session claim targeted an outdated generation."""

    def __init__(self, *, expected: int, actual: int) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(f"expected writer generation {expected}, found {actual}")


class StaleCameraEpochError(ValueError):
    """A camera epoch CAS targeted a different current source epoch."""


class RetiredRuntimeWriterError(ValueError):
    """A queued candidate came from a no-longer-authoritative runtime generation."""


class ReviewedConfigurationConflictError(ValueError):
    """An immutable reviewed revision identity was reused with different bytes."""


def _audit_site_id(session: Session, entity_type: str, entity_id: str) -> str | None:
    if entity_type == "site":
        return session.scalar(
            select(SiteModel.site_id).where(SiteModel.site_id == entity_id)
        )
    if entity_type == "camera":
        return session.scalar(
            select(CameraModel.site_id).where(CameraModel.camera_id == entity_id)
        )
    if entity_type == "candidate_event":
        return session.scalar(
            select(CameraModel.site_id)
            .join(
                CandidateEventModel,
                CandidateEventModel.camera_id == CameraModel.camera_id,
            )
            .where(CandidateEventModel.event_id == entity_id)
        )
    if entity_type == "evidence":
        return session.scalar(
            select(CameraModel.site_id)
            .join(
                CandidateEventModel,
                CandidateEventModel.camera_id == CameraModel.camera_id,
            )
            .join(EvidenceModel, EvidenceModel.event_id == CandidateEventModel.event_id)
            .where(EvidenceModel.evidence_id == entity_id)
        )
    if entity_type == "review":
        return session.scalar(
            select(CameraModel.site_id)
            .join(
                CandidateEventModel,
                CandidateEventModel.camera_id == CameraModel.camera_id,
            )
            .join(ReviewModel, ReviewModel.event_id == CandidateEventModel.event_id)
            .where(ReviewModel.review_id == entity_id)
        )
    if entity_type == "notification_outbox":
        return session.scalar(
            select(CameraModel.site_id)
            .join(
                CandidateEventModel,
                CandidateEventModel.camera_id == CameraModel.camera_id,
            )
            .join(
                NotificationOutboxModel,
                NotificationOutboxModel.event_id == CandidateEventModel.event_id,
            )
            .where(NotificationOutboxModel.outbox_id == entity_id)
        )
    if entity_type == "delivery_attempt":
        return session.scalar(
            select(CameraModel.site_id)
            .join(
                CandidateEventModel,
                CandidateEventModel.camera_id == CameraModel.camera_id,
            )
            .join(
                NotificationOutboxModel,
                NotificationOutboxModel.event_id == CandidateEventModel.event_id,
            )
            .join(
                DeliveryAttemptModel,
                DeliveryAttemptModel.outbox_id == NotificationOutboxModel.outbox_id,
            )
            .where(DeliveryAttemptModel.delivery_attempt_id == entity_id)
        )
    return None


@dataclass(frozen=True)
class AuditEntryInput:
    actor_user_id: str | None
    action: str
    entity_type: str
    entity_id: str
    payload: dict[str, Any]
    idempotency_key: str | None
    occurred_at: datetime


@dataclass(frozen=True)
class EvidenceInput:
    evidence_id: UUID
    event_id: UUID
    object_key: str
    sha256: str
    codec: Literal["h264", "h265"]
    start_at: datetime
    end_at: datetime
    source_reference: str
    status: Literal["pending", "ready", "failed", "unavailable"]

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> EvidenceInput:
        return cls(
            evidence_id=UUID(payload["evidence_id"]),
            event_id=UUID(payload["event_id"]),
            object_key=payload["object_key"],
            sha256=payload["sha256"],
            codec=payload["codec"],
            start_at=datetime.fromisoformat(payload["start_at"]),
            end_at=datetime.fromisoformat(payload["end_at"]),
            source_reference=payload["source_reference"],
            status=payload["status"],
        )


@dataclass(frozen=True)
class EvidenceIntent:
    """Durable pre-material evidence identity; deliberately has no byte digest."""

    schema_version: Literal["evidence-intent.v1"]
    evidence_id: UUID
    event_id: UUID
    object_key: str
    codec: Literal["h264", "h265"]
    start_at: datetime
    end_at: datetime
    source_reference: str
    status: Literal["pending", "failed"] = "pending"

    def __post_init__(self) -> None:
        if self.start_at.tzinfo is None or self.end_at.tzinfo is None:
            raise ValueError("evidence intent timestamps must be timezone-aware")
        if self.end_at <= self.start_at:
            raise ValueError("evidence intent end_at must follow start_at")
        if not self.object_key or not self.source_reference:
            raise ValueError("evidence intent references must be non-empty")

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> EvidenceIntent:
        return cls(
            schema_version=payload["schema_version"],
            evidence_id=UUID(payload["evidence_id"]),
            event_id=UUID(payload["event_id"]),
            object_key=payload["object_key"],
            codec=payload["codec"],
            start_at=datetime.fromisoformat(payload["start_at"]),
            end_at=datetime.fromisoformat(payload["end_at"]),
            source_reference=payload["source_reference"],
            status=payload["status"],
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "evidence_id": str(self.evidence_id),
            "event_id": str(self.event_id),
            "object_key": self.object_key,
            "codec": self.codec,
            "start_at": self.start_at.isoformat(),
            "end_at": self.end_at.isoformat(),
            "source_reference": self.source_reference,
            "status": self.status,
        }

    def materialize(
        self,
        *,
        sha256: str,
        status: Literal["pending", "ready", "failed"] = "pending",
        codec: Literal["h264", "h265"] | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
    ) -> EvidenceInput:
        return EvidenceInput(
            evidence_id=self.evidence_id,
            event_id=self.event_id,
            object_key=self.object_key,
            sha256=sha256,
            codec=codec or self.codec,
            start_at=start_at or self.start_at,
            end_at=end_at or self.end_at,
            source_reference=self.source_reference,
            status=status,
        )


@dataclass(frozen=True)
class ReviewNotificationResult:
    review: ReviewModel
    outbox: NotificationOutboxModel | None


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _review_audit_key(event_id: UUID, review_idempotency_key: str) -> str:
    material = f"{event_id}:{review_idempotency_key}".encode()
    return f"review-audit:{hashlib.sha256(material).hexdigest()}"


def _review_audit_payload(
    *,
    from_status: ReviewStatus,
    to_status: ReviewStatus,
    notes: str | None,
) -> dict[str, Any]:
    return {
        "from_status": from_status,
        "to_status": to_status,
        "notes_present": notes is not None,
        "notes_sha256": (
            hashlib.sha256(notes.encode("utf-8")).hexdigest() if notes is not None else None
        ),
    }


def _event_from_row(row: CandidateEventModel) -> CandidateEventV1:
    return CandidateEventV1(
        schema_version=row.schema_version,
        event_id=row.event_id,
        camera_id=row.camera_id,
        module=row.module,
        opened_at=_as_utc(row.opened_at),
        last_seen_at=_as_utc(row.last_seen_at),
        peak_confidence=row.peak_confidence,
        reason=row.reason,
        model_artifact_id=row.model_artifact_id,
        gate_mode=row.gate_mode,
        evidence_status=row.evidence_status,
        review_status=row.review_status,
        transition_history=tuple(row.transition_history.split(">")),
    )


def _provenance_from_row(
    row: CandidateEventProvenanceModel,
) -> CandidateEventProvenanceV1:
    return CandidateEventProvenanceV1(
        schema_version=row.schema_version,
        site_id=row.site_id,
        runtime_session_id=row.runtime_session_id,
        runtime_writer_generation=row.runtime_writer_generation,
        configuration_activation_generation=(
            row.configuration_activation_generation
        ),
        source_epoch=UUID(row.source_epoch),
        rule_id=row.rule_id,
        rule_revision=row.rule_revision,
        rule_revision_sha256=row.rule_revision_sha256,
        ruleset_sha256=row.ruleset_sha256,
        site_config_sha256=row.site_config_sha256,
        model_gate_decision_sha256=row.model_gate_decision_sha256,
        gate_mode=row.gate_mode,
    )


def _preview_intent_from_row(
    row: PreviewPublicationModel,
) -> PreviewPublicationIntentV1:
    from protector.pilot.storage.preview import PreviewPublicationIntentV1

    return PreviewPublicationIntentV1(
        schema_version=row.intent_schema_version,
        site_id=row.site_id,
        event_id=UUID(row.event_id),
        evidence_id=UUID(row.evidence_id),
        object_key=row.object_key,
        sha256=row.sha256,
        configuration_sha256=row.configuration_sha256,
        runtime_session_id=row.runtime_session_id,
        runtime_writer_generation=row.runtime_writer_generation,
        configuration_activation_generation=(
            row.configuration_activation_generation
        ),
        source_epoch=UUID(row.source_epoch),
        rule_revision_sha256=row.rule_revision_sha256,
        candidate_body_sha256=row.candidate_body_sha256,
        created_at=_as_utc(row.intent_created_at),
        expires_at=_as_utc(row.intent_expires_at),
    )


def _preview_receipt_from_row(
    row: PreviewPublicationModel,
) -> PreviewObjectReceiptV1:
    from protector.pilot.storage.preview import PreviewObjectReceiptV1

    required = (
        row.receipt_schema_version,
        row.checksum_sha256,
        row.size_bytes,
        row.media_type,
        row.etag,
        row.version_id,
        row.server_side_encryption,
        row.receipt_sha256,
        row.receipt_created_at,
    )
    if any(value is None for value in required):
        raise ReviewedConfigurationConflictError(
            "ready preview omitted immutable receipt material"
        )
    receipt = PreviewObjectReceiptV1(
        schema_version=row.receipt_schema_version,
        site_id=row.site_id,
        event_id=UUID(row.event_id),
        evidence_id=UUID(row.evidence_id),
        object_key=row.object_key,
        sha256=row.sha256,
        checksum_sha256=row.checksum_sha256,
        size_bytes=row.size_bytes,
        media_type=row.media_type,
        etag=row.etag,
        version_id=row.version_id,
        server_side_encryption=row.server_side_encryption,
        kms_key_id=row.kms_key_id,
        configuration_sha256=row.configuration_sha256,
        runtime_session_id=row.runtime_session_id,
        runtime_writer_generation=row.runtime_writer_generation,
        configuration_activation_generation=(
            row.configuration_activation_generation
        ),
        source_epoch=UUID(row.source_epoch),
        rule_revision_sha256=row.rule_revision_sha256,
        candidate_body_sha256=row.candidate_body_sha256,
        created_at=_as_utc(row.receipt_created_at),
    )
    if receipt.receipt_sha256 != row.receipt_sha256:
        raise ReviewedConfigurationConflictError(
            "preview receipt digest does not match immutable material"
        )
    return receipt


def _preview_intent_payload(intent: PreviewPublicationIntentV1) -> dict[str, Any]:
    return {
        "schema_version": intent.schema_version,
        "site_id": intent.site_id,
        "event_id": str(intent.event_id),
        "evidence_id": str(intent.evidence_id),
        "object_key": intent.object_key,
        "sha256": intent.sha256,
        "configuration_sha256": intent.configuration_sha256,
        "runtime_session_id": intent.runtime_session_id,
        "runtime_writer_generation": intent.runtime_writer_generation,
        "configuration_activation_generation": (
            intent.configuration_activation_generation
        ),
        "source_epoch": str(intent.source_epoch),
        "rule_revision_sha256": intent.rule_revision_sha256,
        "candidate_body_sha256": intent.candidate_body_sha256,
        "created_at": intent.created_at.isoformat(),
        "expires_at": intent.expires_at.isoformat(),
    }


def _preview_receipt_payload(receipt: PreviewObjectReceiptV1) -> dict[str, Any]:
    return {
        "schema_version": receipt.schema_version,
        "site_id": receipt.site_id,
        "event_id": str(receipt.event_id),
        "evidence_id": str(receipt.evidence_id),
        "object_key": receipt.object_key,
        "sha256": receipt.sha256,
        "checksum_sha256": receipt.checksum_sha256,
        "size_bytes": receipt.size_bytes,
        "media_type": receipt.media_type,
        "etag": receipt.etag,
        "version_id": receipt.version_id,
        "server_side_encryption": receipt.server_side_encryption,
        "kms_key_id": receipt.kms_key_id,
        "configuration_sha256": receipt.configuration_sha256,
        "runtime_session_id": receipt.runtime_session_id,
        "runtime_writer_generation": receipt.runtime_writer_generation,
        "configuration_activation_generation": (
            receipt.configuration_activation_generation
        ),
        "source_epoch": str(receipt.source_epoch),
        "rule_revision_sha256": receipt.rule_revision_sha256,
        "candidate_body_sha256": receipt.candidate_body_sha256,
        "created_at": receipt.created_at.isoformat(),
        "receipt_sha256": receipt.receipt_sha256,
        "receipt_canonical_json": receipt.canonical_bytes().decode("utf-8"),
    }


def _preview_intent_from_payload(payload: object) -> PreviewPublicationIntentV1:
    from protector.pilot.storage.preview import PreviewPublicationIntentV1

    if isinstance(payload, str):
        payload = json.loads(payload)
    if not isinstance(payload, dict):
        raise ReviewedConfigurationConflictError(
            "preview intent function returned an invalid payload"
        )
    return PreviewPublicationIntentV1(
        schema_version=payload["schema_version"],
        site_id=payload["site_id"],
        event_id=UUID(payload["event_id"]),
        evidence_id=UUID(payload["evidence_id"]),
        object_key=payload["object_key"],
        sha256=payload["sha256"],
        configuration_sha256=payload["configuration_sha256"],
        runtime_session_id=payload["runtime_session_id"],
        runtime_writer_generation=payload["runtime_writer_generation"],
        configuration_activation_generation=(
            payload["configuration_activation_generation"]
        ),
        source_epoch=UUID(payload["source_epoch"]),
        rule_revision_sha256=payload["rule_revision_sha256"],
        candidate_body_sha256=payload["candidate_body_sha256"],
        created_at=datetime.fromisoformat(payload["created_at"]),
        expires_at=datetime.fromisoformat(payload["expires_at"]),
    )


def _preview_context_from_payload(payload: object) -> PreviewObjectContext:
    from protector.pilot.storage.preview import PreviewObjectContext

    if isinstance(payload, str):
        payload = json.loads(payload)
    if not isinstance(payload, dict):
        raise ReviewedConfigurationConflictError(
            "preview context function returned an invalid payload"
        )
    return PreviewObjectContext(
        site_id=payload["site_id"],
        event_id=UUID(payload["event_id"]),
        evidence_id=UUID(payload["evidence_id"]),
        configuration_sha256=payload["configuration_sha256"],
        runtime_session_id=payload["runtime_session_id"],
        runtime_writer_generation=payload["runtime_writer_generation"],
        configuration_activation_generation=(
            payload["configuration_activation_generation"]
        ),
        source_epoch=UUID(payload["source_epoch"]),
        rule_revision_sha256=payload["rule_revision_sha256"],
        candidate_body_sha256=payload["candidate_body_sha256"],
    )


def _preview_receipt_from_payload(payload: object) -> PreviewObjectReceiptV1:
    from protector.pilot.storage.preview import PreviewObjectReceiptV1

    if isinstance(payload, str):
        payload = json.loads(payload)
    if not isinstance(payload, dict):
        raise ReviewedConfigurationConflictError(
            "preview receipt function returned an invalid payload"
        )
    payload = dict(payload)
    expected_digest = payload.pop("receipt_sha256", None)
    receipt = PreviewObjectReceiptV1(
        schema_version=payload["schema_version"],
        site_id=payload["site_id"],
        event_id=UUID(payload["event_id"]),
        evidence_id=UUID(payload["evidence_id"]),
        object_key=payload["object_key"],
        sha256=payload["sha256"],
        checksum_sha256=payload["checksum_sha256"],
        size_bytes=payload["size_bytes"],
        media_type=payload["media_type"],
        etag=payload["etag"],
        version_id=payload["version_id"],
        server_side_encryption=payload["server_side_encryption"],
        kms_key_id=payload["kms_key_id"],
        configuration_sha256=payload["configuration_sha256"],
        runtime_session_id=payload["runtime_session_id"],
        runtime_writer_generation=payload["runtime_writer_generation"],
        configuration_activation_generation=(
            payload["configuration_activation_generation"]
        ),
        source_epoch=UUID(payload["source_epoch"]),
        rule_revision_sha256=payload["rule_revision_sha256"],
        candidate_body_sha256=payload["candidate_body_sha256"],
        created_at=datetime.fromisoformat(payload["created_at"]),
    )
    if expected_digest is not None and receipt.receipt_sha256 != expected_digest:
        raise ReviewedConfigurationConflictError(
            "preview receipt function returned a mismatched digest"
        )
    return receipt


class PilotRepository:
    """Small transactional boundary shared by the API and journal replay worker."""

    def __init__(
        self,
        session_factory: SessionFactory,
        *,
        totp_encryption_key: str | None = None,
    ) -> None:
        self.session_factory = session_factory
        self._totp_envelopes = (
            TotpEnvelopeProtector(totp_encryption_key)
            if totp_encryption_key is not None
            else None
        )

    def add_site(self, *, site_id: str, name: str, timezone_name: str = "Asia/Almaty") -> SiteModel:
        with self.session_factory.begin() as session:
            row = SiteModel(site_id=site_id, name=name, timezone_name=timezone_name)
            session.add(row)
            session.flush()
            return row

    def add_camera(
        self,
        *,
        camera_id: str,
        site_id: str,
        name: str,
        source_reference: str,
        codec: Literal["h264", "h265"],
        state: str = "starting",
        enabled: bool = True,
    ) -> CameraModel:
        with self.session_factory.begin() as session:
            row = CameraModel(
                camera_id=camera_id,
                site_id=site_id,
                name=name,
                source_reference=source_reference,
                codec=codec,
                state=state,
                enabled=enabled,
            )
            session.add(row)
            session.flush()
            return row

    def get_active_site_config_sha256(self, *, site_id: str) -> str:
        """Return the exact digest of one site's currently active review."""

        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", site_id) is None:
            raise ValueError("preview site identity is invalid")
        with self.session_factory() as session:
            if session.get_bind().dialect.name == "postgresql":
                digest = session.scalar(
                    text(
                        "SELECT public.pilot_get_active_site_config_sha256(:site_id)"
                    ),
                    {"site_id": site_id},
                )
            else:
                digest = session.scalar(
                    select(SiteConfigRevisionModel.config_sha256)
                    .join(
                        ActivePilotConfigurationModel,
                        and_(
                            ActivePilotConfigurationModel.site_id
                            == SiteConfigRevisionModel.site_id,
                            ActivePilotConfigurationModel.config_revision_id
                            == SiteConfigRevisionModel.config_revision_id,
                        ),
                    )
                    .where(ActivePilotConfigurationModel.site_id == site_id)
                )
        if not isinstance(digest, str) or re.fullmatch(r"[a-f0-9]{64}", digest) is None:
            raise KeyError(f"active reviewed configuration unavailable: {site_id}")
        return digest

    def get_preview_object_context(
        self,
        *,
        site_id: str,
        event_id: UUID,
        evidence_id: UUID,
        source_epoch: UUID,
    ) -> PreviewObjectContext:
        """Derive preview authority exclusively from current durable state."""

        from protector.pilot.storage.preview import PreviewObjectContext

        if (
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", site_id) is None
            or type(event_id) is not UUID
            or type(evidence_id) is not UUID
            or type(source_epoch) is not UUID
        ):
            raise ValueError("preview context identity is invalid")
        with self.session_factory() as session:
            if session.get_bind().dialect.name == "postgresql":
                payload = session.scalar(
                    text(
                        """
                        SELECT public.pilot_get_preview_object_context(
                            :site_id,
                            CAST(:event_id AS uuid),
                            CAST(:evidence_id AS uuid),
                            CAST(:source_epoch AS uuid)
                        )
                        """
                    ),
                    {
                        "site_id": site_id,
                        "event_id": str(event_id),
                        "evidence_id": str(evidence_id),
                        "source_epoch": str(source_epoch),
                    },
                )
                return _preview_context_from_payload(payload)
            event_row = session.get(CandidateEventModel, str(event_id))
            provenance = session.get(
                CandidateEventProvenanceModel,
                str(event_id),
            )
            camera = (
                session.get(CameraModel, event_row.camera_id)
                if event_row is not None
                else None
            )
            active = session.get(ActivePilotConfigurationModel, site_id)
            writer = session.get(RuntimeWriterAuthorityModel, site_id)
            epoch = (
                session.get(CameraEpochAuthorityModel, event_row.camera_id)
                if event_row is not None
                else None
            )
            config = (
                session.get(SiteConfigRevisionModel, active.config_revision_id)
                if active is not None
                else None
            )
            rule = (
                session.get(
                    CameraRuleRevisionModel,
                    (provenance.ruleset_revision_id, provenance.rule_id),
                )
                if provenance is not None
                else None
            )
            evidence = session.get(EvidenceModel, str(evidence_id))
            if (
                event_row is None
                or provenance is None
                or camera is None
                or active is None
                or writer is None
                or epoch is None
                or config is None
                or rule is None
                or camera.site_id != site_id
                or event_row.evidence_status != "pending"
                or event_row.review_status != "candidate"
                or event_row.transition_history != "observation>candidate"
                or provenance.site_id != site_id
                or active.activation_generation
                != provenance.configuration_activation_generation
                or active.ruleset_revision_id
                != provenance.ruleset_revision_id
                or config.site_id != site_id
                or config.config_sha256 != provenance.site_config_sha256
                or writer.runtime_session_id
                != provenance.runtime_session_id
                or writer.writer_generation
                != provenance.runtime_writer_generation
                or writer.configuration_activation_generation
                != provenance.configuration_activation_generation
                or epoch.site_id != site_id
                or epoch.source_epoch != str(source_epoch)
                or provenance.source_epoch != str(source_epoch)
                or epoch.runtime_session_id
                != provenance.runtime_session_id
                or epoch.writer_generation
                != provenance.runtime_writer_generation
                or epoch.configuration_activation_generation
                != provenance.configuration_activation_generation
                or rule.site_id != site_id
                or rule.camera_id != event_row.camera_id
                or not rule.enabled
                or rule.revision != provenance.rule_revision
                or rule.rule_revision_sha256
                != provenance.rule_revision_sha256
                or rule.model_decision_sha256
                != provenance.model_gate_decision_sha256
                or rule.module != event_row.module
                or rule.model_artifact_id != event_row.model_artifact_id
                or rule.gate_mode != event_row.gate_mode
                or rule.gate_mode != provenance.gate_mode
                or (
                    evidence is not None
                    and evidence.event_id != str(event_id)
                )
            ):
                raise RetiredRuntimeWriterError(
                    "preview context lacks exact current candidate authority"
                )
            return PreviewObjectContext(
                site_id=site_id,
                event_id=event_id,
                evidence_id=evidence_id,
                configuration_sha256=provenance.site_config_sha256,
                runtime_session_id=provenance.runtime_session_id,
                runtime_writer_generation=(
                    provenance.runtime_writer_generation
                ),
                configuration_activation_generation=(
                    provenance.configuration_activation_generation
                ),
                source_epoch=source_epoch,
                rule_revision_sha256=provenance.rule_revision_sha256,
                candidate_body_sha256=provenance.body_sha256,
            )

    def prepare_preview_publication(
        self,
        *,
        context: PreviewObjectContext,
        object_key: str,
        sha256: str,
        requested_at: datetime,
        expires_at: datetime,
    ) -> PreviewPublicationIntentV1:
        """Reserve one immutable preview identity under current runtime authority."""

        from protector.pilot.storage.preview import (
            PreviewObjectContext,
            PreviewPublicationIntentV1,
        )

        if type(context) is not PreviewObjectContext:
            raise TypeError("preview preparation requires an exact object context")
        proposed = PreviewPublicationIntentV1(
            schema_version="preview-publication-intent.v1",
            site_id=context.site_id,
            event_id=context.event_id,
            evidence_id=context.evidence_id,
            object_key=object_key,
            sha256=sha256,
            configuration_sha256=context.configuration_sha256,
            runtime_session_id=context.runtime_session_id,
            runtime_writer_generation=context.runtime_writer_generation,
            configuration_activation_generation=(
                context.configuration_activation_generation
            ),
            source_epoch=context.source_epoch,
            rule_revision_sha256=context.rule_revision_sha256,
            candidate_body_sha256=context.candidate_body_sha256,
            created_at=requested_at,
            expires_at=expires_at,
        )
        expected_key = (
            f"{context.site_id}/{context.event_id}/{context.evidence_id}/"
            f"{sha256}.mp4"
        )
        if object_key != expected_key:
            raise ValueError("preview object key does not match its exact context")
        if proposed.expires_at <= datetime.now(timezone.utc):
            raise ValueError("preview publication intent has already expired")

        with self.session_factory() as session:
            if session.get_bind().dialect.name == "postgresql":
                result = session.scalar(
                    text(
                        """
                        SELECT public.pilot_prepare_preview_publication(
                            CAST(:intent AS jsonb)
                        )
                        """
                    ),
                    {
                        "intent": json.dumps(
                            _preview_intent_payload(proposed),
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                    },
                )
                session.commit()
                return _preview_intent_from_payload(result)
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            try:
                event_row = session.scalar(
                    select(CandidateEventModel)
                    .where(CandidateEventModel.event_id == str(context.event_id))
                    .with_for_update()
                )
                if event_row is None:
                    raise ValueError("preview candidate event is unavailable")
                camera = session.scalar(
                    select(CameraModel)
                    .where(CameraModel.camera_id == event_row.camera_id)
                    .with_for_update()
                )
                provenance = session.get(
                    CandidateEventProvenanceModel,
                    str(context.event_id),
                    with_for_update=True,
                )
                if provenance is None:
                    raise ValueError(
                        "preview publication requires nonlegacy candidate provenance"
                    )
                if (
                    camera is None
                    or camera.site_id != context.site_id
                    or event_row.evidence_status != "pending"
                    or event_row.review_status != "candidate"
                    or event_row.transition_history != "observation>candidate"
                ):
                    raise ValueError(
                        "preview publication requires an initial pending candidate"
                    )
                if (
                    provenance.site_id,
                    provenance.runtime_session_id,
                    provenance.runtime_writer_generation,
                    provenance.configuration_activation_generation,
                    provenance.source_epoch,
                    provenance.site_config_sha256,
                    provenance.rule_revision_sha256,
                    provenance.body_sha256,
                ) != (
                    context.site_id,
                    context.runtime_session_id,
                    context.runtime_writer_generation,
                    context.configuration_activation_generation,
                    str(context.source_epoch),
                    context.configuration_sha256,
                    context.rule_revision_sha256,
                    context.candidate_body_sha256,
                ):
                    raise ValueError(
                        "preview context does not match exact candidate provenance"
                    )
                active = session.get(
                    ActivePilotConfigurationModel,
                    context.site_id,
                    with_for_update=True,
                )
                writer = session.get(
                    RuntimeWriterAuthorityModel,
                    context.site_id,
                    with_for_update=True,
                )
                epoch = session.get(
                    CameraEpochAuthorityModel,
                    event_row.camera_id,
                    with_for_update=True,
                )
                config = (
                    session.get(
                        SiteConfigRevisionModel,
                        active.config_revision_id,
                        with_for_update=True,
                    )
                    if active is not None
                    else None
                )
                rule = session.get(
                    CameraRuleRevisionModel,
                    (provenance.ruleset_revision_id, provenance.rule_id),
                    with_for_update=True,
                )
                if (
                    active is None
                    or writer is None
                    or epoch is None
                    or config is None
                    or rule is None
                    or active.activation_generation
                    != context.configuration_activation_generation
                    or active.ruleset_revision_id
                    != provenance.ruleset_revision_id
                    or config.site_id != context.site_id
                    or config.config_sha256 != context.configuration_sha256
                    or writer.runtime_session_id != context.runtime_session_id
                    or writer.writer_generation
                    != context.runtime_writer_generation
                    or writer.configuration_activation_generation
                    != context.configuration_activation_generation
                    or epoch.site_id != context.site_id
                    or epoch.source_epoch != str(context.source_epoch)
                    or epoch.runtime_session_id != context.runtime_session_id
                    or epoch.writer_generation
                    != context.runtime_writer_generation
                    or epoch.configuration_activation_generation
                    != context.configuration_activation_generation
                    or rule.site_id != context.site_id
                    or rule.camera_id != event_row.camera_id
                    or not rule.enabled
                    or rule.revision != provenance.rule_revision
                    or rule.rule_revision_sha256
                    != context.rule_revision_sha256
                    or rule.model_decision_sha256
                    != provenance.model_gate_decision_sha256
                    or rule.module != event_row.module
                    or rule.model_artifact_id != event_row.model_artifact_id
                    or rule.gate_mode != event_row.gate_mode
                    or rule.gate_mode != provenance.gate_mode
                ):
                    raise RetiredRuntimeWriterError(
                        "retired runtime authority cannot reserve a preview"
                    )
                evidence = session.get(
                    EvidenceModel,
                    str(context.evidence_id),
                    with_for_update=True,
                )
                if evidence is not None and evidence.event_id != str(
                    context.event_id
                ):
                    raise IdempotencyConflictError(
                        "preview evidence identity belongs to another event"
                    )
                identities = list(
                    session.scalars(
                        select(PreviewPublicationModel)
                        .where(
                            or_(
                                PreviewPublicationModel.event_id
                                == str(context.event_id),
                                PreviewPublicationModel.evidence_id
                                == str(context.evidence_id),
                                PreviewPublicationModel.object_key == object_key,
                            )
                        )
                        .with_for_update()
                    )
                )
                if identities:
                    if len(identities) != 1:
                        raise IdempotencyConflictError(
                            "preview identities resolve to conflicting publications"
                        )
                    existing = identities[0]
                    persisted = _preview_intent_from_row(existing)
                    if (
                        persisted.context != context
                        or persisted.object_key != object_key
                        or persisted.sha256 != sha256
                    ):
                        raise IdempotencyConflictError(
                            "preview identity was reused with different material"
                        )
                    if existing.publication_state in {"retiring", "retired"}:
                        raise IdempotencyConflictError(
                            "terminal preview publication cannot be resurrected"
                        )
                    if (
                        existing.publication_state == "reserved"
                        and proposed.created_at >= persisted.expires_at
                    ):
                        raise ValueError("preview publication intent has expired")
                    session.commit()
                    return persisted
                row = PreviewPublicationModel(
                    event_id=str(context.event_id),
                    site_id=context.site_id,
                    camera_id=event_row.camera_id,
                    evidence_id=str(context.evidence_id),
                    intent_schema_version=proposed.schema_version,
                    publication_state="reserved",
                    object_key=object_key,
                    sha256=sha256,
                    configuration_sha256=context.configuration_sha256,
                    runtime_session_id=context.runtime_session_id,
                    runtime_writer_generation=(
                        context.runtime_writer_generation
                    ),
                    configuration_activation_generation=(
                        context.configuration_activation_generation
                    ),
                    source_epoch=str(context.source_epoch),
                    rule_revision_sha256=context.rule_revision_sha256,
                    candidate_body_sha256=context.candidate_body_sha256,
                    intent_created_at=proposed.created_at,
                    intent_expires_at=proposed.expires_at,
                )
                session.add(row)
                session.flush()
                session.commit()
                return proposed
            except BaseException:
                session.rollback()
                raise

    def finalize_preview_receipt(
        self,
        *,
        intent: PreviewPublicationIntentV1,
        receipt: PreviewObjectReceiptV1,
    ) -> None:
        """Bind an exact remote version to a live reserved publication."""

        from protector.pilot.storage.preview import (
            PreviewObjectContext,
            PreviewObjectReceiptV1,
            PreviewPublicationIntentV1,
        )

        if (
            type(intent) is not PreviewPublicationIntentV1
            or type(receipt) is not PreviewObjectReceiptV1
        ):
            raise TypeError("preview finalization requires exact validated contracts")
        if (
            PreviewObjectContext(
                site_id=receipt.site_id,
                event_id=receipt.event_id,
                evidence_id=receipt.evidence_id,
                configuration_sha256=receipt.configuration_sha256,
                runtime_session_id=receipt.runtime_session_id,
                runtime_writer_generation=receipt.runtime_writer_generation,
                configuration_activation_generation=(
                    receipt.configuration_activation_generation
                ),
                source_epoch=receipt.source_epoch,
                rule_revision_sha256=receipt.rule_revision_sha256,
                candidate_body_sha256=receipt.candidate_body_sha256,
            )
            != intent.context
            or receipt.object_key != intent.object_key
            or receipt.sha256 != intent.sha256
            or receipt.created_at != intent.created_at
        ):
            raise IdempotencyConflictError(
                "preview receipt does not match its publication intent"
            )
        if receipt.size_bytes > _PREVIEW_MAX_BYTES:
            raise ValueError("preview receipt exceeds the 16 MiB bound")
        with self.session_factory() as session:
            if session.get_bind().dialect.name == "postgresql":
                session.scalar(
                    text(
                        """
                        SELECT public.pilot_finalize_preview_receipt(
                            CAST(:intent AS jsonb),
                            CAST(:receipt AS jsonb)
                        )
                        """
                    ),
                    {
                        "intent": json.dumps(
                            _preview_intent_payload(intent),
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        "receipt": json.dumps(
                            _preview_receipt_payload(receipt),
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                    },
                )
                session.commit()
                return
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            try:
                row = session.get(
                    PreviewPublicationModel,
                    str(intent.event_id),
                    with_for_update=True,
                )
                if row is None:
                    raise KeyError(f"unknown preview intent: {intent.event_id}")
                persisted = _preview_intent_from_row(row)
                if persisted != intent:
                    raise IdempotencyConflictError(
                        "preview intent replay changed immutable material"
                    )
                if row.publication_state == "ready":
                    if _preview_receipt_from_row(row) != receipt:
                        raise IdempotencyConflictError(
                            "preview receipt replay changed remote identity"
                        )
                    session.commit()
                    return
                if row.publication_state in {"retiring", "retired"}:
                    raise IdempotencyConflictError(
                        "retired preview publication cannot be finalized"
                    )
                if datetime.now(timezone.utc) >= persisted.expires_at:
                    raise ValueError("preview publication intent has expired")
                conflicts = list(
                    session.scalars(
                        select(PreviewPublicationModel)
                        .where(
                            PreviewPublicationModel.event_id
                            != str(intent.event_id),
                            PreviewPublicationModel.receipt_sha256
                            == receipt.receipt_sha256,
                        )
                        .with_for_update()
                    )
                )
                if conflicts:
                    raise IdempotencyConflictError(
                        "preview remote identity is already registered"
                    )
                row.receipt_schema_version = receipt.schema_version
                row.checksum_sha256 = receipt.checksum_sha256
                row.size_bytes = receipt.size_bytes
                row.media_type = receipt.media_type
                row.etag = receipt.etag
                row.version_id = receipt.version_id
                row.server_side_encryption = receipt.server_side_encryption
                row.kms_key_id = receipt.kms_key_id
                row.receipt_sha256 = receipt.receipt_sha256
                row.receipt_created_at = receipt.created_at
                row.publication_state = "ready"
                session.flush()
                session.commit()
            except BaseException:
                session.rollback()
                raise

    def get_preview_receipt(
        self,
        *,
        site_id: str,
        event_id: UUID,
    ) -> PreviewObjectReceiptV1 | None:
        """Return only an exact receipt whose evidence is atomically eligible."""

        if (
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", site_id) is None
            or type(event_id) is not UUID
        ):
            raise ValueError("preview lookup identity is invalid")
        with self.session_factory() as session:
            if session.get_bind().dialect.name == "postgresql":
                payload = session.scalar(
                    text(
                        """
                        SELECT public.pilot_get_preview_receipt(
                            :site_id,
                            CAST(:event_id AS uuid)
                        )
                        """
                    ),
                    {"site_id": site_id, "event_id": str(event_id)},
                )
                return (
                    _preview_receipt_from_payload(payload)
                    if payload is not None
                    else None
                )
            row = session.scalar(
                select(PreviewPublicationModel)
                .join(
                    CandidateEventModel,
                    CandidateEventModel.event_id
                    == PreviewPublicationModel.event_id,
                )
                .join(
                    CameraModel,
                    CameraModel.camera_id == CandidateEventModel.camera_id,
                )
                .join(
                    EvidenceModel,
                    and_(
                        EvidenceModel.evidence_id
                        == PreviewPublicationModel.evidence_id,
                        EvidenceModel.event_id
                        == PreviewPublicationModel.event_id,
                    ),
                )
                .where(
                    PreviewPublicationModel.site_id == site_id,
                    PreviewPublicationModel.event_id == str(event_id),
                    PreviewPublicationModel.publication_state == "ready",
                    CameraModel.site_id == site_id,
                    CandidateEventModel.evidence_status == "ready",
                    EvidenceModel.status == "ready",
                )
            )
            return _preview_receipt_from_row(row) if row is not None else None

    def commit_preview_access(self, access: PreviewAccessReceipt) -> bool:
        """Atomically recheck eligibility and append redacted access plus audit."""

        from protector.pilot.storage.preview import PreviewAccessReceipt

        if type(access) is not PreviewAccessReceipt:
            raise TypeError("preview access requires an exact validated receipt")
        access_time = datetime.now(timezone.utc)
        if abs((access.occurred_at - access_time).total_seconds()) > 300:
            raise ValueError(
                "preview access time must match current server time"
            )
        access_payload = {
            "schema_version": access.schema_version,
            "access_id": str(access.access_id),
            "site_id": access.site_id,
            "event_id": str(access.event_id),
            "actor_id": access.actor_id,
            "receipt_sha256": access.receipt_sha256,
            "occurred_at": access.occurred_at.isoformat(),
        }
        with self.session_factory() as session:
            if session.get_bind().dialect.name == "postgresql":
                committed = bool(
                    session.scalar(
                        text(
                            """
                            SELECT public.pilot_commit_preview_access(
                                CAST(:access AS jsonb)
                            )
                            """
                        ),
                        {
                            "access": json.dumps(
                                access_payload,
                                sort_keys=True,
                                separators=(",", ":"),
                            )
                        },
                    )
                )
                session.commit()
                return committed
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            try:
                actor = session.scalar(
                    select(UserModel)
                    .where(UserModel.user_id == access.actor_id)
                    .with_for_update()
                )
                publication = session.scalar(
                    select(PreviewPublicationModel)
                    .where(
                        PreviewPublicationModel.site_id == access.site_id,
                        PreviewPublicationModel.event_id
                        == str(access.event_id),
                    )
                    .with_for_update()
                )
                if (
                    actor is None
                    or not actor.is_active
                    or publication is None
                    or publication.publication_state != "ready"
                    or publication.receipt_sha256 != access.receipt_sha256
                ):
                    session.rollback()
                    return False
                event_row = session.scalar(
                    select(CandidateEventModel)
                    .where(
                        CandidateEventModel.event_id == str(access.event_id)
                    )
                    .with_for_update()
                )
                evidence = session.scalar(
                    select(EvidenceModel)
                    .where(
                        EvidenceModel.evidence_id
                        == publication.evidence_id
                    )
                    .with_for_update()
                )
                if (
                    event_row is None
                    or event_row.evidence_status != "ready"
                    or evidence is None
                    or evidence.event_id != publication.event_id
                    or evidence.status != "ready"
                ):
                    session.rollback()
                    return False
                audit_key = f"preview-access:{access.access_id}"
                audit_payload = {
                    "schema_version": access.schema_version,
                    "access_id": str(access.access_id),
                    "receipt_sha256": access.receipt_sha256,
                    "requested_at": access.occurred_at.isoformat(),
                }
                existing_access = session.get(
                    PreviewAccessReceiptModel,
                    str(access.access_id),
                    with_for_update=True,
                )
                existing_audit = session.scalar(
                    select(AuditEntryModel)
                    .where(AuditEntryModel.idempotency_key == audit_key)
                    .with_for_update()
                )
                if existing_access is not None or existing_audit is not None:
                    if (
                        existing_access is None
                        or existing_audit is None
                        or (
                            existing_access.schema_version,
                            existing_access.site_id,
                            existing_access.event_id,
                            existing_access.actor_id,
                            existing_access.receipt_sha256,
                        )
                        != (
                            access.schema_version,
                            access.site_id,
                            str(access.event_id),
                            access.actor_id,
                            access.receipt_sha256,
                        )
                        or existing_audit.site_id != access.site_id
                        or existing_audit.actor_user_id != access.actor_id
                        or existing_audit.action != "preview.accessed"
                        or existing_audit.entity_type != "candidate_event"
                        or existing_audit.entity_id != str(access.event_id)
                        or existing_audit.payload != audit_payload
                        or _as_utc(existing_audit.occurred_at)
                        != _as_utc(existing_access.occurred_at)
                    ):
                        raise IdempotencyConflictError(
                            "preview access identity was reused with different data"
                        )
                    session.commit()
                    return True
                session.add(
                    PreviewAccessReceiptModel(
                        access_id=str(access.access_id),
                        schema_version=access.schema_version,
                        site_id=access.site_id,
                        event_id=str(access.event_id),
                        actor_id=access.actor_id,
                        receipt_sha256=access.receipt_sha256,
                        occurred_at=access_time,
                    )
                )
                session.add(
                    AuditEntryModel(
                        audit_id=str(uuid4()),
                        site_id=access.site_id,
                        occurred_at=access_time,
                        actor_user_id=access.actor_id,
                        action="preview.accessed",
                        entity_type="candidate_event",
                        entity_id=str(access.event_id),
                        payload=audit_payload,
                        idempotency_key=audit_key,
                    )
                )
                session.flush()
                session.commit()
                return True
            except BaseException:
                session.rollback()
                raise

    def claim_preview_receipts_for_retention(
        self,
        *,
        site_id: str,
        cutoff_at: datetime,
        limit: int,
    ) -> tuple[PreviewObjectReceiptV1, ...]:
        """Hide a finite ready batch before returning exact versions to delete."""

        site_id, cutoff_at, limit = self._validate_preview_retention_input(
            site_id=site_id,
            observed_at=cutoff_at,
            limit=limit,
        )
        with self.session_factory() as session:
            if session.get_bind().dialect.name == "postgresql":
                payload = session.scalar(
                    text(
                        """
                        SELECT public.pilot_claim_preview_receipts_for_retention(
                            :site_id,
                            :cutoff_at,
                            :limit
                        )
                        """
                    ),
                    {
                        "site_id": site_id,
                        "cutoff_at": cutoff_at,
                        "limit": limit,
                    },
                )
                session.commit()
                if isinstance(payload, str):
                    payload = json.loads(payload)
                if not isinstance(payload, list) or len(payload) > limit:
                    raise ReviewedConfigurationConflictError(
                        "preview retention claim exceeded its finite bound"
                    )
                return tuple(_preview_receipt_from_payload(item) for item in payload)
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            try:
                rows = list(
                    session.scalars(
                        select(PreviewPublicationModel)
                        .where(
                            PreviewPublicationModel.site_id == site_id,
                            or_(
                                PreviewPublicationModel.publication_state
                                == "retiring",
                                and_(
                                    PreviewPublicationModel.publication_state
                                    == "ready",
                                    PreviewPublicationModel.receipt_created_at
                                    <= cutoff_at,
                                ),
                            ),
                        )
                        .order_by(
                            PreviewPublicationModel.publication_state.desc(),
                            PreviewPublicationModel.receipt_created_at,
                            PreviewPublicationModel.event_id,
                        )
                        .limit(limit)
                        .with_for_update()
                    )
                )
                claimed_at = datetime.now(timezone.utc)
                receipts: list[PreviewObjectReceiptV1] = []
                for row in rows:
                    receipt = _preview_receipt_from_row(row)
                    if row.publication_state == "ready":
                        row.publication_state = "retiring"
                        row.retiring_at = max(claimed_at, receipt.created_at)
                    receipts.append(receipt)
                session.flush()
                session.commit()
                return tuple(receipts)
            except BaseException:
                session.rollback()
                raise

    def finalize_preview_retirement(
        self,
        *,
        site_id: str,
        event_id: UUID,
        receipt_sha256: str,
        retired_at: datetime,
    ) -> bool:
        """Terminalize one exact retention claim without permitting resurrection."""

        site_id, retired_at, _ = self._validate_preview_retention_input(
            site_id=site_id,
            observed_at=retired_at,
            limit=1,
        )
        if (
            type(event_id) is not UUID
            or re.fullmatch(r"[a-f0-9]{64}", receipt_sha256) is None
        ):
            raise ValueError("preview retirement identity is invalid")
        with self.session_factory() as session:
            if session.get_bind().dialect.name == "postgresql":
                finalized = bool(
                    session.scalar(
                        text(
                            """
                            SELECT public.pilot_finalize_preview_retirement(
                                :site_id,
                                CAST(:event_id AS uuid),
                                :receipt_sha256,
                                :retired_at
                            )
                            """
                        ),
                        {
                            "site_id": site_id,
                            "event_id": str(event_id),
                            "receipt_sha256": receipt_sha256,
                            "retired_at": retired_at,
                        },
                    )
                )
                session.commit()
                return finalized
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            try:
                row = session.get(
                    PreviewPublicationModel,
                    str(event_id),
                    with_for_update=True,
                )
                if (
                    row is None
                    or row.site_id != site_id
                    or row.receipt_sha256 != receipt_sha256
                ):
                    session.rollback()
                    return False
                if row.publication_state == "retired":
                    session.commit()
                    return True
                if row.publication_state != "retiring":
                    session.rollback()
                    return False
                if row.retiring_at is None or retired_at < _as_utc(row.retiring_at):
                    raise ValueError("preview retirement time cannot regress")
                row.publication_state = "retired"
                row.retired_at = retired_at
                session.flush()
                session.commit()
                return True
            except BaseException:
                session.rollback()
                raise

    def preview_version_is_protected(
        self,
        *,
        site_id: str,
        object_key: str,
        version_id: str,
        observed_at: datetime,
    ) -> bool:
        """Protect a live intent or its exact ready/retiring object version."""

        from protector.pilot.storage.object_store import validate_object_key
        from protector.pilot.storage.preview import PreviewObjectVersionV1

        site_id, observed_at, _ = self._validate_preview_retention_input(
            site_id=site_id,
            observed_at=observed_at,
            limit=1,
        )
        validate_object_key(object_key)
        PreviewObjectVersionV1(
            object_key=object_key,
            version_id=version_id,
            etag="validation-etag",
            size_bytes=0,
            last_modified=observed_at,
        )
        with self.session_factory() as session:
            if session.get_bind().dialect.name == "postgresql":
                return bool(
                    session.scalar(
                        text(
                            """
                            SELECT public.pilot_preview_version_is_protected(
                                :site_id,
                                :object_key,
                                :version_id,
                                :observed_at
                            )
                            """
                        ),
                        {
                            "site_id": site_id,
                            "object_key": object_key,
                            "version_id": version_id,
                            "observed_at": observed_at,
                        },
                    )
                )
            return (
                session.scalar(
                    select(func.count())
                    .select_from(PreviewPublicationModel)
                    .where(
                        PreviewPublicationModel.site_id == site_id,
                        PreviewPublicationModel.object_key == object_key,
                        or_(
                            and_(
                                PreviewPublicationModel.publication_state
                                == "reserved",
                                PreviewPublicationModel.intent_expires_at
                                > observed_at,
                            ),
                            and_(
                                PreviewPublicationModel.publication_state.in_(
                                    ("ready", "retiring")
                                ),
                                PreviewPublicationModel.version_id == version_id,
                            ),
                        ),
                    )
                )
                == 1
            )

    def prune_preview_access_receipts(
        self,
        *,
        site_id: str,
        cutoff_at: datetime,
        limit: int,
    ) -> int:
        """Delete at most one finite batch of expired redacted access receipts."""

        site_id, cutoff_at, limit = self._validate_preview_retention_input(
            site_id=site_id,
            observed_at=cutoff_at,
            limit=limit,
        )
        with self.session_factory() as session:
            if session.get_bind().dialect.name == "postgresql":
                pruned = int(
                    session.scalar(
                        text(
                            """
                            SELECT public.pilot_prune_preview_access_receipts(
                                :site_id,
                                :cutoff_at,
                                :limit
                            )
                            """
                        ),
                        {
                            "site_id": site_id,
                            "cutoff_at": cutoff_at,
                            "limit": limit,
                        },
                    )
                    or 0
                )
                session.commit()
                return pruned
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            try:
                access_ids = list(
                    session.scalars(
                        select(PreviewAccessReceiptModel.access_id)
                        .where(
                            PreviewAccessReceiptModel.site_id == site_id,
                            PreviewAccessReceiptModel.occurred_at < cutoff_at,
                        )
                        .order_by(
                            PreviewAccessReceiptModel.occurred_at,
                            PreviewAccessReceiptModel.access_id,
                        )
                        .limit(limit)
                    )
                )
                if access_ids:
                    session.execute(
                        delete(PreviewAccessReceiptModel).where(
                            PreviewAccessReceiptModel.access_id.in_(access_ids)
                        )
                    )
                session.commit()
                return len(access_ids)
            except BaseException:
                session.rollback()
                raise

    def retire_expired_preview_intents(
        self,
        *,
        site_id: str,
        observed_at: datetime,
        limit: int,
    ) -> int:
        """Terminalize a finite batch of expired, never-finalized reservations."""

        site_id, observed_at, limit = self._validate_preview_retention_input(
            site_id=site_id,
            observed_at=observed_at,
            limit=limit,
        )
        with self.session_factory() as session:
            if session.get_bind().dialect.name == "postgresql":
                retired = int(
                    session.scalar(
                        text(
                            """
                            SELECT public.pilot_retire_expired_preview_intents(
                                :site_id,
                                :observed_at,
                                :limit
                            )
                            """
                        ),
                        {
                            "site_id": site_id,
                            "observed_at": observed_at,
                            "limit": limit,
                        },
                    )
                    or 0
                )
                session.commit()
                return retired
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            try:
                rows = list(
                    session.scalars(
                        select(PreviewPublicationModel)
                        .where(
                            PreviewPublicationModel.site_id == site_id,
                            PreviewPublicationModel.publication_state
                            == "reserved",
                            PreviewPublicationModel.intent_expires_at
                            <= observed_at,
                        )
                        .order_by(
                            PreviewPublicationModel.intent_expires_at,
                            PreviewPublicationModel.event_id,
                        )
                        .limit(limit)
                        .with_for_update()
                    )
                )
                for row in rows:
                    row.publication_state = "retired"
                    row.retired_at = observed_at
                session.flush()
                session.commit()
                return len(rows)
            except BaseException:
                session.rollback()
                raise

    @staticmethod
    def _validate_preview_retention_input(
        *,
        site_id: str,
        observed_at: datetime,
        limit: int,
    ) -> tuple[str, datetime, int]:
        if (
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", site_id) is None
            or not isinstance(observed_at, datetime)
            or observed_at.tzinfo is None
            or observed_at.utcoffset() is None
            or not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= 1_000
        ):
            raise ValueError("preview retention input is invalid")
        return site_id, observed_at.astimezone(timezone.utc), limit

    def prune_operational_metadata(
        self,
        *,
        site_id: str,
        cutoff_at: datetime,
        limit: int,
    ) -> OperationalMetadataPruneCounts:
        """Delete finite site-scoped health and legacy-observation batches."""

        site_id, cutoff_at, limit = self._validate_preview_retention_input(
            site_id=site_id,
            observed_at=cutoff_at,
            limit=limit,
        )
        with self.session_factory() as session:
            if session.get_bind().dialect.name == "postgresql":
                payload = session.scalar(
                    text(
                        """
                        SELECT public.pilot_prune_operational_metadata(
                            :site_id,
                            :cutoff_at,
                            :limit
                        )
                        """
                    ),
                    {
                        "site_id": site_id,
                        "cutoff_at": cutoff_at,
                        "limit": limit,
                    },
                )
                if isinstance(payload, str):
                    payload = json.loads(payload)
                if (
                    not isinstance(payload, dict)
                    or set(payload) != {"health_samples", "observations"}
                    or any(
                        not isinstance(count, int)
                        or isinstance(count, bool)
                        or not 0 <= count <= limit
                        for count in payload.values()
                    )
                ):
                    raise ReviewedConfigurationConflictError(
                        "operational metadata prune returned invalid counts"
                    )
                session.commit()
                return OperationalMetadataPruneCounts(
                    health_samples=payload["health_samples"],
                    observations=payload["observations"],
                )

            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            try:
                health_sample_ids = list(
                    session.scalars(
                        select(CameraHealthSampleModel.health_sample_id)
                        .join(
                            CameraModel,
                            CameraModel.camera_id
                            == CameraHealthSampleModel.camera_id,
                        )
                        .where(
                            CameraModel.site_id == site_id,
                            CameraHealthSampleModel.observed_at < cutoff_at,
                        )
                        .order_by(
                            CameraHealthSampleModel.observed_at,
                            CameraHealthSampleModel.health_sample_id,
                        )
                        .limit(limit)
                    )
                )
                observation_ids = list(
                    session.scalars(
                        select(ObservationModel.observation_id)
                        .join(
                            CameraModel,
                            CameraModel.camera_id
                            == ObservationModel.camera_id,
                        )
                        .where(
                            CameraModel.site_id == site_id,
                            ObservationModel.received_at < cutoff_at,
                        )
                        .order_by(
                            ObservationModel.received_at,
                            ObservationModel.observation_id,
                        )
                        .limit(limit)
                    )
                )
                if health_sample_ids:
                    session.execute(
                        delete(CameraHealthSampleModel).where(
                            CameraHealthSampleModel.health_sample_id.in_(
                                health_sample_ids
                            )
                        )
                    )
                if observation_ids:
                    session.execute(
                        delete(ObservationModel).where(
                            ObservationModel.observation_id.in_(
                                observation_ids
                            )
                        )
                    )
                session.commit()
                return OperationalMetadataPruneCounts(
                    health_samples=len(health_sample_ids),
                    observations=len(observation_ids),
                )
            except BaseException:
                session.rollback()
                raise

    def authorize_telemetry_epoch(
        self,
        *,
        site_id: str,
        publisher: Literal["runtime", "notifications"],
        runtime_session_id: str,
        publisher_generation: int,
        sequence: int,
        observed_at: datetime,
        payload_digest: str,
        persist: Callable[[Session], None] | None = None,
    ) -> bool:
        """Advance one durable monotonic publisher epoch or reject resurrection."""

        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", site_id) is None:
            raise ValueError("telemetry site identity is invalid")
        if publisher not in {"runtime", "notifications"}:
            raise ValueError("telemetry publisher is invalid")
        if (
            re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}",
                runtime_session_id,
            )
            is None
        ):
            raise ValueError("telemetry session identity is invalid")
        if (
            not isinstance(publisher_generation, int)
            or isinstance(publisher_generation, bool)
            or not 1 <= publisher_generation <= 9_223_372_036_854_775_807
        ):
            raise ValueError("telemetry publisher generation is invalid")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
            raise ValueError("telemetry sequence is invalid")
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise ValueError("telemetry timestamp must be UTC-aware")
        observed_at = observed_at.astimezone(timezone.utc)
        if re.fullmatch(r"[a-f0-9]{64}", payload_digest) is None:
            raise ValueError("telemetry payload digest is invalid")
        if persist is not None and not callable(persist):
            raise ValueError("telemetry persistence callback is invalid")

        with self.session_factory.begin() as session:
            site = session.scalar(
                select(SiteModel)
                .where(SiteModel.site_id == site_id)
                .with_for_update()
            )
            if site is None:
                raise ValueError("telemetry site is unavailable")
            current = session.get(
                TelemetryPublisherEpochModel,
                (site_id, publisher),
                with_for_update=True,
            )
            if current is not None:
                if publisher_generation < current.generation:
                    raise ValueError("retired telemetry session cannot regain authority")
                if publisher_generation == current.generation:
                    if runtime_session_id != current.runtime_session_id:
                        raise ValueError(
                            "telemetry generation is bound to another session"
                        )
                    previous_observed_at = _as_utc(current.last_observed_at)
                    if sequence == current.last_sequence:
                        if payload_digest != current.last_payload_digest:
                            raise ValueError(
                                "telemetry sequence was replayed with a different body"
                            )
                        return False
                    if (
                        sequence < current.last_sequence
                        or observed_at < previous_observed_at
                    ):
                        raise ValueError("telemetry sequence regressed")
                    current.last_sequence = sequence
                    current.last_observed_at = observed_at
                    current.last_payload_digest = payload_digest
                    if persist is not None:
                        persist(session)
                    session.flush()
                    return True
                if runtime_session_id == current.runtime_session_id:
                    raise ValueError(
                        "new telemetry generation requires a new session identity"
                    )
                if observed_at < _as_utc(current.last_observed_at):
                    raise ValueError("telemetry session timestamp regressed")
                current.runtime_session_id = runtime_session_id
                current.generation = publisher_generation
                current.last_sequence = sequence
                current.last_observed_at = observed_at
                current.last_payload_digest = payload_digest
                current.activated_at = observed_at
                if persist is not None:
                    persist(session)
                session.flush()
                return True

            session.add(
                TelemetryPublisherEpochModel(
                    site_id=site_id,
                    publisher=publisher,
                    runtime_session_id=runtime_session_id,
                    generation=publisher_generation,
                    last_sequence=sequence,
                    last_observed_at=observed_at,
                    last_payload_digest=payload_digest,
                    activated_at=observed_at,
                )
            )
            if persist is not None:
                persist(session)
            session.flush()
            return True

    def list_cameras(
        self,
        *,
        site_id: str | None = None,
        state: str | None = None,
        enabled: bool | None = None,
    ) -> list[CameraModel]:
        statement: Select[tuple[CameraModel]] = select(CameraModel).order_by(CameraModel.camera_id)
        if site_id is not None:
            statement = statement.where(CameraModel.site_id == site_id)
        if state is not None:
            statement = statement.where(CameraModel.state == state)
        if enabled is not None:
            statement = statement.where(CameraModel.enabled == enabled)
        with self.session_factory() as session:
            return list(session.scalars(statement))

    def add_model_artifact(self, artifact: ModelArtifactV1) -> ModelArtifactModel:
        with self.session_factory.begin() as session:
            row = ModelArtifactModel(
                artifact_id=artifact.artifact_id,
                schema_version=artifact.schema_version,
                analytic=artifact.analytic,
                sha256=artifact.sha256,
                source=artifact.source,
                commercial_rights=(
                    artifact.commercial_rights.model_dump(mode="json")
                    if artifact.commercial_rights is not None
                    else None
                ),
                class_list=list(artifact.class_list),
                preprocessing=artifact.preprocessing,
            )
            session.add(row)
            session.flush()
            return row

    def provision_reviewed_configuration(
        self,
        *,
        site_revision: VerifiedSiteConfigRevision,
        ruleset_revision: VerifiedCameraRulesetRevision,
        gate_decisions: tuple[VerifiedModelGateDecision, ...],
    ) -> None:
        """Persist immutable signed revisions without making either one active."""

        compiled_rules = compile_verified_camera_rules(
            site_revision=site_revision,
            ruleset_revision=ruleset_revision,
            gate_decisions=gate_decisions,
        )
        site_document = site_revision.document
        ruleset_document = ruleset_revision.document
        config_values: dict[str, Any] = {
            "config_revision_id": site_document.config_revision_id,
            "schema_version": site_document.schema_version,
            "site_id": site_document.site_id,
            "revision": site_document.revision,
            "config_sha256": site_document.config_sha256,
            "artifact_sha256": site_revision.attestation.payload_sha256,
            "signature_sha256": site_revision.attestation.signature_sha256,
            "signing_key_spki_sha256": (
                site_revision.attestation.trust_key_spki_sha256
            ),
            "reviewed_by": site_document.reviewed_by,
            "reviewed_at": site_document.reviewed_at,
            "review_reference": site_document.review_reference,
            "canonical_config": site_document.config.model_dump(mode="json"),
        }
        ruleset_values: dict[str, Any] = {
            "ruleset_revision_id": ruleset_document.ruleset_revision_id,
            "schema_version": ruleset_document.schema_version,
            "ruleset_id": ruleset_document.ruleset_id,
            "revision": ruleset_document.revision,
            "site_id": ruleset_document.site_id,
            "config_revision_id": site_document.config_revision_id,
            "site_config_sha256": ruleset_document.site_config_sha256,
            "frozen_workload_sha256": ruleset_document.frozen_workload_sha256,
            "engine_sha256": ruleset_document.engine_sha256,
            "runtime_manifest_sha256": ruleset_document.runtime_manifest_sha256,
            "ruleset_sha256": ruleset_document.ruleset_sha256,
            "artifact_sha256": ruleset_revision.attestation.payload_sha256,
            "signature_sha256": ruleset_revision.attestation.signature_sha256,
            "signing_key_spki_sha256": (
                ruleset_revision.attestation.trust_key_spki_sha256
            ),
            "reviewed_by": ruleset_document.reviewed_by,
            "reviewed_at": ruleset_document.reviewed_at,
            "review_reference": ruleset_document.review_reference,
        }

        def exact(row: object, values: dict[str, Any]) -> bool:
            for name, value in values.items():
                persisted = getattr(row, name)
                if isinstance(value, datetime) and isinstance(persisted, datetime):
                    if _as_utc(persisted) != _as_utc(value):
                        return False
                elif persisted != value:
                    return False
            return True

        with self.session_factory.begin() as session:
            if session.get(SiteModel, site_document.site_id) is None:
                raise KeyError(f"unknown site: {site_document.site_id}")
            config_row = session.get(
                SiteConfigRevisionModel,
                site_document.config_revision_id,
            )
            if config_row is None:
                session.add(SiteConfigRevisionModel(**config_values))
                session.flush()
            elif not exact(config_row, config_values):
                raise ReviewedConfigurationConflictError(
                    "site configuration revision identity was reused"
                )

            ruleset_row = session.get(
                CameraRulesetRevisionModel,
                ruleset_document.ruleset_revision_id,
            )
            if ruleset_row is None:
                session.add(CameraRulesetRevisionModel(**ruleset_values))
                session.flush()
            elif not exact(ruleset_row, ruleset_values):
                raise ReviewedConfigurationConflictError(
                    "camera ruleset revision identity was reused"
                )

            expected_rules: dict[str, dict[str, Any]] = {}
            for rule in compiled_rules.rules:
                expected_rules[rule.rule_id] = {
                    "ruleset_revision_id": ruleset_document.ruleset_revision_id,
                    "rule_id": rule.rule_id,
                    "schema_version": "camera-rule.v1",
                    "revision": rule.revision,
                    "site_id": rule.site_id,
                    "camera_id": rule.camera_id,
                    "module": rule.module,
                    "enabled": rule.enabled,
                    "model_artifact_id": rule.model_artifact_id,
                    "model_decision_sha256": rule.model_decision_sha256,
                    "gate_mode": rule.gate_mode,
                    "minimum_confidence": rule.minimum_confidence,
                    "minimum_votes": rule.minimum_votes,
                    "sample_count": rule.sample_count,
                    "window_seconds": rule.window_seconds,
                    "evidence_seconds": rule.evidence_seconds,
                    "rule_spec": rule.spec.model_dump(mode="json"),
                    "rule_revision_sha256": rule.rule_revision_sha256,
                }
            existing_rules = {
                row.rule_id: row
                for row in session.scalars(
                    select(CameraRuleRevisionModel).where(
                        CameraRuleRevisionModel.ruleset_revision_id
                        == ruleset_document.ruleset_revision_id
                    )
                )
            }
            if existing_rules and set(existing_rules) != set(expected_rules):
                raise ReviewedConfigurationConflictError(
                    "persisted ruleset membership differs from reviewed rules"
                )
            for rule_id, values in expected_rules.items():
                existing = existing_rules.get(rule_id)
                if existing is None:
                    session.add(CameraRuleRevisionModel(**values))
                elif not exact(existing, values):
                    raise ReviewedConfigurationConflictError(
                        f"camera rule revision identity was reused: {rule_id}"
                    )
            session.flush()

    def activate_reviewed_configuration(
        self,
        *,
        site_id: str,
        config_revision_id: str,
        ruleset_revision_id: str,
        activated_by: str,
        activated_at: datetime,
        idempotency_key: str,
        expected_activation_generation: int,
        force_new_generation: bool = False,
    ) -> ConfigurationActivationReceiptV1:
        """Atomically select one active pair, audit it, and fence old queued writers."""

        identifier = r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}"
        if (
            re.fullmatch(identifier, site_id) is None
            or re.fullmatch(identifier, config_revision_id) is None
            or re.fullmatch(identifier, ruleset_revision_id) is None
            or re.fullmatch(identifier, activated_by) is None
            or not idempotency_key
            or len(idempotency_key) > 255
            or not isinstance(expected_activation_generation, int)
            or isinstance(expected_activation_generation, bool)
            or expected_activation_generation < 0
            or not isinstance(force_new_generation, bool)
        ):
            raise ValueError("configuration activation identity is invalid")
        if activated_at.tzinfo is None or activated_at.utcoffset() is None:
            raise ValueError("configuration activation time must be UTC-aware")
        activated_at = activated_at.astimezone(timezone.utc)
        with self.session_factory.begin() as session:
            site = session.scalar(
                select(SiteModel)
                .where(SiteModel.site_id == site_id)
                .with_for_update()
            )
            if site is None:
                raise KeyError(f"unknown site: {site_id}")
            config = session.get(SiteConfigRevisionModel, config_revision_id)
            ruleset = session.get(CameraRulesetRevisionModel, ruleset_revision_id)
            if (
                config is None
                or ruleset is None
                or config.site_id != site_id
                or ruleset.site_id != site_id
                or ruleset.config_revision_id != config_revision_id
                or ruleset.site_config_sha256 != config.config_sha256
            ):
                raise ReviewedConfigurationConflictError(
                    "configuration activation revisions do not match"
                )
            prior_activation = session.scalar(
                select(ConfigurationActivationModel)
                .where(
                    ConfigurationActivationModel.idempotency_key
                    == idempotency_key
                )
                .with_for_update()
            )
            prior_audit = session.scalar(
                select(AuditEntryModel)
                .where(AuditEntryModel.idempotency_key == idempotency_key)
                .with_for_update()
            )
            if prior_activation is not None:
                expected_audit_payload = {
                    "activated_by": prior_activation.activated_by,
                    "expected_activation_generation": (
                        prior_activation.expected_activation_generation
                    ),
                    "activation_generation": prior_activation.activation_generation,
                    "runtime_writer_generation": (
                        prior_activation.runtime_writer_generation
                    ),
                    "config_revision_id": prior_activation.config_revision_id,
                    "site_config_sha256": prior_activation.site_config_sha256,
                    "ruleset_revision_id": prior_activation.ruleset_revision_id,
                    "ruleset_sha256": prior_activation.ruleset_sha256,
                    "force_new_generation": (
                        prior_activation.force_new_generation
                    ),
                }
                if (
                    prior_activation.site_id != site_id
                    or prior_activation.config_revision_id != config_revision_id
                    or prior_activation.ruleset_revision_id != ruleset_revision_id
                    or prior_activation.activated_by != activated_by
                    or _as_utc(prior_activation.activated_at) != activated_at
                    or prior_activation.expected_activation_generation
                    != expected_activation_generation
                    or prior_activation.force_new_generation
                    != force_new_generation
                    or prior_audit is None
                    or prior_audit.action
                    != "pilot.configuration.activated"
                    or prior_audit.entity_id != site_id
                    or prior_audit.payload != expected_audit_payload
                ):
                    raise IdempotencyConflictError(
                        "configuration activation key was reused with different data"
                    )
                return self._configuration_activation_receipt(prior_activation)
            if prior_audit is not None:
                raise IdempotencyConflictError(
                    "configuration activation key belongs to different work"
                )

            active = session.get(
                ActivePilotConfigurationModel,
                site_id,
                with_for_update=True,
            )
            actual_generation = 0 if active is None else active.activation_generation
            if expected_activation_generation != actual_generation:
                raise StaleActivationGenerationError(
                    expected=expected_activation_generation,
                    actual=actual_generation,
                )
            if active is not None and activated_at < _as_utc(active.activated_at):
                raise ValueError("configuration activation time cannot regress")
            if (
                active is not None
                and active.config_revision_id != config_revision_id
            ):
                current_config = session.get(
                    SiteConfigRevisionModel,
                    active.config_revision_id,
                )
                current_storage = (
                    current_config.canonical_config.get("storage")
                    if current_config is not None
                    and isinstance(current_config.canonical_config, dict)
                    else None
                )
                replacement_storage = (
                    config.canonical_config.get("storage")
                    if isinstance(config.canonical_config, dict)
                    else None
                )
                if current_storage is None or replacement_storage is None:
                    raise ReviewedConfigurationConflictError(
                        "reviewed storage authority is unavailable"
                    )
                if current_storage != replacement_storage:
                    raise ReviewedConfigurationConflictError(
                        "storage configuration is immutable after first activation"
                    )
            if (
                active is not None
                and active.config_revision_id == config_revision_id
                and active.ruleset_revision_id == ruleset_revision_id
                and not force_new_generation
            ):
                raise ReviewedConfigurationConflictError(
                    "configuration is already active; replay its original idempotency key"
                )
            generation = actual_generation + 1
            writer = session.get(
                RuntimeWriterAuthorityModel,
                site_id,
                with_for_update=True,
            )
            writer_generation = (
                1 if writer is None else writer.writer_generation + 1
            )
            activation = ConfigurationActivationModel(
                site_id=site_id,
                expected_activation_generation=expected_activation_generation,
                activation_generation=generation,
                runtime_writer_generation=writer_generation,
                config_revision_id=config_revision_id,
                site_config_sha256=config.config_sha256,
                ruleset_revision_id=ruleset_revision_id,
                ruleset_sha256=ruleset.ruleset_sha256,
                activated_by=activated_by,
                activated_at=activated_at,
                idempotency_key=idempotency_key,
                force_new_generation=force_new_generation,
            )
            session.add(activation)
            session.flush()
            if active is None:
                active = ActivePilotConfigurationModel(
                    site_id=site_id,
                    activation_generation=generation,
                    config_revision_id=config_revision_id,
                    ruleset_revision_id=ruleset_revision_id,
                    activated_by=activated_by,
                    activated_at=activated_at,
                )
                session.add(active)
            else:
                active.activation_generation = generation
                active.config_revision_id = config_revision_id
                active.ruleset_revision_id = ruleset_revision_id
                active.activated_by = activated_by
                active.activated_at = activated_at

            if writer is None:
                writer = RuntimeWriterAuthorityModel(
                    site_id=site_id,
                    runtime_session_id=None,
                    writer_generation=writer_generation,
                    configuration_activation_generation=generation,
                    issued_at=activated_at,
                )
                session.add(writer)
            else:
                writer.runtime_session_id = None
                writer.writer_generation = writer_generation
                writer.configuration_activation_generation = generation
                writer.issued_at = activated_at
            session.flush()
            session.add(
                AuditEntryModel(
                    audit_id=str(uuid4()),
                    site_id=site_id,
                    occurred_at=activated_at,
                    actor_user_id=None,
                    action="pilot.configuration.activated",
                    entity_type="site",
                    entity_id=site_id,
                    payload={
                        "activated_by": activated_by,
                        "expected_activation_generation": (
                            expected_activation_generation
                        ),
                        "activation_generation": generation,
                        "runtime_writer_generation": writer_generation,
                        "config_revision_id": config_revision_id,
                        "site_config_sha256": config.config_sha256,
                        "ruleset_revision_id": ruleset_revision_id,
                        "ruleset_sha256": ruleset.ruleset_sha256,
                        "force_new_generation": force_new_generation,
                    },
                    idempotency_key=idempotency_key,
                )
            )
            session.flush()
            return self._configuration_activation_receipt(activation)

    @staticmethod
    def _configuration_activation_receipt(
        row: ConfigurationActivationModel,
    ) -> ConfigurationActivationReceiptV1:
        return ConfigurationActivationReceiptV1(
            site_id=row.site_id,
            expected_activation_generation=row.expected_activation_generation,
            activation_generation=row.activation_generation,
            runtime_writer_generation=row.runtime_writer_generation,
            config_revision_id=row.config_revision_id,
            site_config_sha256=row.site_config_sha256,
            ruleset_revision_id=row.ruleset_revision_id,
            ruleset_sha256=row.ruleset_sha256,
            activated_by=row.activated_by,
            activated_at=_as_utc(row.activated_at),
            idempotency_key=row.idempotency_key,
            force_new_generation=row.force_new_generation,
        )

    def issue_runtime_writer_receipt(
        self,
        *,
        site_id: str,
        runtime_session_id: str,
        issued_at: datetime,
        expected_writer_generation: int,
    ) -> RuntimeWriterReceiptV1:
        """Bind one runtime session to the active generation and return its receipt."""

        identifier = r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}"
        if (
            re.fullmatch(identifier, site_id) is None
            or re.fullmatch(identifier, runtime_session_id) is None
            or not isinstance(expected_writer_generation, int)
            or isinstance(expected_writer_generation, bool)
            or expected_writer_generation < 1
        ):
            raise ValueError("runtime writer identity is invalid")
        if issued_at.tzinfo is None or issued_at.utcoffset() is None:
            raise ValueError("runtime writer issue time must be UTC-aware")
        issued_at = issued_at.astimezone(timezone.utc)
        with self.session_factory.begin() as session:
            active = session.get(
                ActivePilotConfigurationModel,
                site_id,
                with_for_update=True,
            )
            if active is None:
                raise KeyError(f"site has no active reviewed configuration: {site_id}")
            writer = session.get(
                RuntimeWriterAuthorityModel,
                site_id,
                with_for_update=True,
            )
            if writer is None:
                raise ReviewedConfigurationConflictError(
                    "active configuration has no writer fence"
                )
            if writer.configuration_activation_generation != active.activation_generation:
                raise ReviewedConfigurationConflictError(
                    "runtime writer fence does not match active configuration"
                )
            prior_session = session.get(
                RuntimeWriterSessionModel,
                runtime_session_id,
                with_for_update=True,
            )
            if (
                prior_session is not None
                and writer.runtime_session_id != runtime_session_id
            ):
                raise RetiredRuntimeWriterError(
                    "retired runtime session ID cannot be reused"
                )
            if writer.writer_generation != expected_writer_generation:
                raise StaleRuntimeWriterGenerationError(
                    expected=expected_writer_generation,
                    actual=writer.writer_generation,
                )
            if issued_at < _as_utc(writer.issued_at):
                raise ValueError("runtime writer issue time cannot regress")
            if writer.runtime_session_id == runtime_session_id:
                if prior_session is None:
                    raise ReviewedConfigurationConflictError(
                        "writer authority exists without immutable session history"
                    )
                if _as_utc(prior_session.issued_at) != issued_at:
                    raise IdempotencyConflictError(
                        "runtime session was replayed with a different issue time"
                    )
                return self._runtime_writer_receipt(session, active, writer)
            assert prior_session is None
            if writer.runtime_session_id is not None:
                writer.writer_generation += 1
            writer.runtime_session_id = runtime_session_id
            writer.issued_at = issued_at
            session.flush()
            receipt = self._runtime_writer_receipt(session, active, writer)
            session.add(
                RuntimeWriterSessionModel(
                    runtime_session_id=runtime_session_id,
                    site_id=site_id,
                    writer_generation=writer.writer_generation,
                    configuration_activation_generation=(
                        writer.configuration_activation_generation
                    ),
                    issued_at=issued_at,
                    receipt_sha256=receipt.authority_sha256,
                )
            )
            session.flush()
            return receipt

    @staticmethod
    def _runtime_writer_receipt(
        session: Session,
        active: ActivePilotConfigurationModel,
        writer: RuntimeWriterAuthorityModel,
    ) -> RuntimeWriterReceiptV1:
        if writer.runtime_session_id is None:
            raise RetiredRuntimeWriterError("runtime writer generation is retired")
        config = session.get(SiteConfigRevisionModel, active.config_revision_id)
        ruleset = session.get(
            CameraRulesetRevisionModel,
            active.ruleset_revision_id,
        )
        if config is None or ruleset is None:
            raise ReviewedConfigurationConflictError(
                "active configuration revision is unavailable"
            )
        rules = list(
            session.scalars(
                select(CameraRuleRevisionModel).where(
                    CameraRuleRevisionModel.ruleset_revision_id
                    == active.ruleset_revision_id
                )
            )
        )
        receipt = _issue_runtime_writer_receipt(
            site_id=active.site_id,
            runtime_session_id=writer.runtime_session_id,
            runtime_writer_generation=writer.writer_generation,
            configuration_activation_generation=active.activation_generation,
            config_revision_id=config.config_revision_id,
            site_config_sha256=config.config_sha256,
            ruleset_revision_id=ruleset.ruleset_revision_id,
            ruleset_sha256=ruleset.ruleset_sha256,
            rule_revision_digests={
                rule.rule_id: rule.rule_revision_sha256 for rule in rules
            },
            issued_at=_as_utc(writer.issued_at),
        )
        history = session.get(
            RuntimeWriterSessionModel,
            writer.runtime_session_id,
        )
        if history is not None and (
            history.site_id != receipt.site_id
            or history.writer_generation != receipt.runtime_writer_generation
            or history.configuration_activation_generation
            != receipt.configuration_activation_generation
            or _as_utc(history.issued_at) != receipt.issued_at
            or history.receipt_sha256 != receipt.authority_sha256
        ):
            raise RetiredRuntimeWriterError(
                "runtime writer receipt does not match immutable session history"
            )
        return receipt

    def _require_current_writer_receipt(
        self,
        session: Session,
        receipt: RuntimeWriterReceiptV1,
    ) -> tuple[ActivePilotConfigurationModel, RuntimeWriterAuthorityModel]:
        if type(receipt) is not RuntimeWriterReceiptV1:
            raise TypeError("runtime write requires an exact repository-issued receipt")
        active = session.get(
            ActivePilotConfigurationModel,
            receipt.site_id,
            with_for_update=True,
        )
        writer = session.get(
            RuntimeWriterAuthorityModel,
            receipt.site_id,
            with_for_update=True,
        )
        if (
            active is None
            or writer is None
            or active.activation_generation
            != receipt.configuration_activation_generation
            or active.config_revision_id != receipt.config_revision_id
            or active.ruleset_revision_id != receipt.ruleset_revision_id
            or writer.runtime_session_id != receipt.runtime_session_id
            or writer.writer_generation != receipt.runtime_writer_generation
            or writer.configuration_activation_generation
            != receipt.configuration_activation_generation
        ):
            raise RetiredRuntimeWriterError(
                "retired runtime writer cannot exercise authority"
            )
        current = self._runtime_writer_receipt(session, active, writer)
        if current.authority_sha256 != receipt.authority_sha256:
            raise RetiredRuntimeWriterError(
                "runtime writer receipt does not match immutable authority"
            )
        return active, writer

    def activate_camera_epoch(
        self,
        *,
        receipt: RuntimeWriterReceiptV1,
        camera_id: str,
        source_epoch: UUID,
        expected_source_epoch: UUID | None,
        activated_at: datetime,
    ) -> CameraEpochActivationReceiptV1:
        """CAS one camera to a never-before-used source epoch for this site."""

        if (
            re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}",
                camera_id,
            )
            is None
            or type(source_epoch) is not UUID
            or (
                expected_source_epoch is not None
                and type(expected_source_epoch) is not UUID
            )
            or activated_at.tzinfo is None
            or activated_at.utcoffset() is None
        ):
            raise ValueError("camera epoch activation input is invalid")
        activated_at = activated_at.astimezone(timezone.utc)
        with self.session_factory.begin() as session:
            self._require_current_writer_receipt(session, receipt)
            camera = session.scalar(
                select(CameraModel)
                .where(CameraModel.camera_id == camera_id)
                .with_for_update()
            )
            if camera is None or camera.site_id != receipt.site_id:
                raise ReviewedConfigurationConflictError(
                    "camera does not belong to runtime writer site"
                )
            current = session.get(
                CameraEpochAuthorityModel,
                camera_id,
                with_for_update=True,
            )
            if activated_at < receipt.issued_at or (
                current is not None
                and activated_at < _as_utc(current.activated_at)
            ):
                raise ValueError("camera epoch activation time cannot regress")
            current_matches_writer = (
                current is not None
                and current.runtime_session_id == receipt.runtime_session_id
                and current.writer_generation
                == receipt.runtime_writer_generation
                and current.configuration_activation_generation
                == receipt.configuration_activation_generation
            )
            actual_source_epoch = (
                UUID(current.source_epoch)
                if current_matches_writer and current is not None
                else None
            )
            history = session.get(
                CameraEpochHistoryModel,
                (camera_id, str(source_epoch)),
                with_for_update=True,
            )
            expected_previous = (
                None
                if expected_source_epoch is None
                else str(expected_source_epoch)
            )
            if (
                current is not None
                and actual_source_epoch == source_epoch
                and history is not None
            ):
                if (
                    history.previous_source_epoch != expected_previous
                    or history.site_id != receipt.site_id
                    or history.runtime_session_id != receipt.runtime_session_id
                    or history.writer_generation
                    != receipt.runtime_writer_generation
                    or history.configuration_activation_generation
                    != receipt.configuration_activation_generation
                    or _as_utc(history.activated_at) != activated_at
                    or current.runtime_session_id != receipt.runtime_session_id
                    or current.writer_generation
                    != receipt.runtime_writer_generation
                    or current.configuration_activation_generation
                    != receipt.configuration_activation_generation
                ):
                    raise IdempotencyConflictError(
                        "camera epoch was replayed with different authority"
                    )
                return self._camera_epoch_receipt(
                    current,
                    previous_source_epoch=expected_source_epoch,
                )
            if history is not None:
                raise RetiredRuntimeWriterError(
                    "retired camera source epoch cannot be reused"
                )
            if actual_source_epoch != expected_source_epoch:
                raise StaleCameraEpochError(
                    "camera epoch CAS expected "
                    f"{expected_source_epoch}, found {actual_source_epoch}"
                )
            history = CameraEpochHistoryModel(
                camera_id=camera_id,
                source_epoch=str(source_epoch),
                previous_source_epoch=expected_previous,
                site_id=receipt.site_id,
                runtime_session_id=receipt.runtime_session_id,
                writer_generation=receipt.runtime_writer_generation,
                configuration_activation_generation=(
                    receipt.configuration_activation_generation
                ),
                activated_at=activated_at,
            )
            session.add(history)
            if current is None:
                current = CameraEpochAuthorityModel(
                    camera_id=camera_id,
                    site_id=receipt.site_id,
                    source_epoch=str(source_epoch),
                    runtime_session_id=receipt.runtime_session_id,
                    writer_generation=receipt.runtime_writer_generation,
                    configuration_activation_generation=(
                        receipt.configuration_activation_generation
                    ),
                    activated_at=activated_at,
                )
                session.add(current)
            else:
                current.source_epoch = str(source_epoch)
                current.runtime_session_id = receipt.runtime_session_id
                current.writer_generation = receipt.runtime_writer_generation
                current.configuration_activation_generation = (
                    receipt.configuration_activation_generation
                )
                current.activated_at = activated_at
            session.flush()
            return self._camera_epoch_receipt(
                current,
                previous_source_epoch=expected_source_epoch,
            )

    @staticmethod
    def _camera_epoch_receipt(
        row: CameraEpochAuthorityModel,
        *,
        previous_source_epoch: UUID | None,
    ) -> CameraEpochActivationReceiptV1:
        return CameraEpochActivationReceiptV1(
            site_id=row.site_id,
            camera_id=row.camera_id,
            source_epoch=UUID(row.source_epoch),
            previous_source_epoch=previous_source_epoch,
            runtime_session_id=row.runtime_session_id,
            runtime_writer_generation=row.writer_generation,
            configuration_activation_generation=(
                row.configuration_activation_generation
            ),
            activated_at=_as_utc(row.activated_at),
        )

    def store_provenanced_event(
        self,
        envelope: ProvenancedCandidateEventV2,
        *,
        receipt: RuntimeWriterReceiptV1,
    ) -> PersistedCandidateEventV2:
        """Atomically persist an exact replay or reject stale/conflicting authority."""

        if type(envelope) is not ProvenancedCandidateEventV2 or type(
            receipt
        ) is not RuntimeWriterReceiptV1:
            raise TypeError("provenanced event write requires validated contracts")
        provenance = envelope.provenance
        if (
            provenance.site_id != receipt.site_id
            or provenance.runtime_session_id != receipt.runtime_session_id
            or provenance.runtime_writer_generation
            != receipt.runtime_writer_generation
            or provenance.configuration_activation_generation
            != receipt.configuration_activation_generation
            or provenance.site_config_sha256 != receipt.site_config_sha256
            or provenance.ruleset_sha256 != receipt.ruleset_sha256
            or provenance.rule_revision_sha256
            != receipt.rule_revision_sha256(provenance.rule_id)
        ):
            raise RetiredRuntimeWriterError(
                "candidate provenance does not match runtime writer receipt"
            )
        with self.session_factory.begin() as session:
            self._require_current_writer_receipt(session, receipt)
            epoch = session.get(
                CameraEpochAuthorityModel,
                envelope.event.camera_id,
                with_for_update=True,
            )
            if (
                epoch is None
                or epoch.site_id != provenance.site_id
                or epoch.source_epoch != str(provenance.source_epoch)
                or epoch.runtime_session_id != receipt.runtime_session_id
                or epoch.writer_generation != receipt.runtime_writer_generation
                or epoch.configuration_activation_generation
                != receipt.configuration_activation_generation
            ):
                raise RetiredRuntimeWriterError(
                    "candidate source epoch is not current for this camera and writer"
                )
            existing = session.scalar(
                select(CandidateEventModel).where(
                    or_(
                        CandidateEventModel.event_id
                        == str(envelope.event.event_id),
                        CandidateEventModel.dedupe_key == envelope.event.dedupe_key,
                    )
                )
            )
            if existing is not None:
                existing_provenance = session.get(
                    CandidateEventProvenanceModel,
                    existing.event_id,
                )
                if existing_provenance is None:
                    raise IdempotencyConflictError(
                        "event identity belongs to a historical row without provenance"
                    )
                if existing_provenance.body_sha256 != envelope.body_sha256:
                    raise IdempotencyConflictError(
                        "event identity was reused with different data"
                    )
                return PersistedCandidateEventV2(
                    event=_event_from_row(existing),
                    provenance=_provenance_from_row(existing_provenance),
                )
            camera = session.get(CameraModel, envelope.event.camera_id)
            rule = session.get(
                CameraRuleRevisionModel,
                (receipt.ruleset_revision_id, provenance.rule_id),
            )
            if (
                camera is None
                or camera.site_id != provenance.site_id
                or rule is None
                or not rule.enabled
                or rule.site_id != provenance.site_id
                or rule.camera_id != envelope.event.camera_id
                or rule.module != envelope.event.module
                or rule.model_artifact_id != envelope.event.model_artifact_id
                or rule.revision != provenance.rule_revision
                or rule.rule_revision_sha256 != provenance.rule_revision_sha256
                or rule.model_decision_sha256
                != provenance.model_gate_decision_sha256
                or rule.gate_mode != provenance.gate_mode
            ):
                raise ReviewedConfigurationConflictError(
                    "candidate does not match active reviewed camera rule"
                )
            if session.get_bind().dialect.name == "postgresql":
                candidate_payload = envelope.event.model_dump(
                    mode="json",
                    exclude={"dedupe_key"},
                )
                candidate_payload["dedupe_key"] = envelope.event.dedupe_key
                provenance_payload = provenance.model_dump(mode="json")
                provenance_payload.update(
                    {
                        "ruleset_revision_id": receipt.ruleset_revision_id,
                        "body_sha256": envelope.body_sha256,
                        "body_canonical_json": envelope.canonical_body_json,
                    }
                )
                session.execute(
                    text(
                        """
                        SELECT public.pilot_ingest_candidate(
                            CAST(:candidate AS jsonb),
                            CAST(:provenance AS jsonb)
                        )
                        """
                    ),
                    {
                        "candidate": json.dumps(
                            candidate_payload,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        "provenance": json.dumps(
                            provenance_payload,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                    },
                ).scalar_one()
                return PersistedCandidateEventV2(
                    event=envelope.event,
                    provenance=provenance,
                )
            event_row = self._new_event_row(envelope.event)
            session.add(event_row)
            session.flush()
            session.add(
                CandidateEventProvenanceModel(
                    event_id=str(envelope.event.event_id),
                    schema_version=provenance.schema_version,
                    site_id=provenance.site_id,
                    runtime_session_id=provenance.runtime_session_id,
                    runtime_writer_generation=(
                        provenance.runtime_writer_generation
                    ),
                    configuration_activation_generation=(
                        provenance.configuration_activation_generation
                    ),
                    source_epoch=str(provenance.source_epoch),
                    ruleset_revision_id=receipt.ruleset_revision_id,
                    rule_id=provenance.rule_id,
                    rule_revision=provenance.rule_revision,
                    rule_revision_sha256=provenance.rule_revision_sha256,
                    ruleset_sha256=provenance.ruleset_sha256,
                    site_config_sha256=provenance.site_config_sha256,
                    model_gate_decision_sha256=(
                        provenance.model_gate_decision_sha256
                    ),
                    gate_mode=provenance.gate_mode,
                    body_sha256=envelope.body_sha256,
                )
            )
            session.flush()
            return PersistedCandidateEventV2(
                event=envelope.event,
                provenance=provenance,
            )

    def get_provenanced_event(
        self,
        event_id: UUID,
        *,
        allow_legacy: bool = False,
    ) -> PersistedCandidateEventV2:
        """Read provenance when present without inventing it for historical V1 rows."""

        with self.session_factory() as session:
            event_row = session.get(CandidateEventModel, str(event_id))
            if event_row is None:
                raise KeyError(f"unknown event: {event_id}")
            provenance_row = session.get(
                CandidateEventProvenanceModel,
                str(event_id),
            )
            if provenance_row is None:
                legacy_marker = session.get(
                    LegacyCandidateImportModel,
                    str(event_id),
                )
                if not allow_legacy or legacy_marker is None:
                    raise KeyError(
                        f"event has no candidate provenance or legacy marker: {event_id}"
                    )
            return PersistedCandidateEventV2(
                event=_event_from_row(event_row),
                provenance=(
                    _provenance_from_row(provenance_row)
                    if provenance_row is not None
                    else None
                ),
            )

    def import_pre_migration_legacy_event(
        self,
        event: CandidateEventV1,
        *,
        marker: LegacyCandidateImportV1,
    ) -> PersistedCandidateEventV2:
        """Import one explicitly marked pre-0006 event through the admin surface."""

        if type(event) is not CandidateEventV1 or type(
            marker
        ) is not LegacyCandidateImportV1:
            raise TypeError("legacy import requires exact validated contracts")
        if (
            marker.event_id != event.event_id
            or event.opened_at > marker.legacy_cutoff_at
        ):
            raise ValueError("legacy marker does not match a pre-cutoff event")
        with self.session_factory.begin() as session:
            existing = session.get(CandidateEventModel, str(event.event_id))
            existing_marker = session.get(
                LegacyCandidateImportModel,
                str(event.event_id),
            )
            existing_provenance = session.get(
                CandidateEventProvenanceModel,
                str(event.event_id),
            )
            if existing_provenance is not None:
                raise IdempotencyConflictError(
                    "provenanced event cannot be marked as legacy"
                )
            if existing is not None or existing_marker is not None:
                if (
                    existing is None
                    or existing_marker is None
                    or _event_from_row(existing) != event
                    or existing_marker.schema_version != marker.schema_version
                    or _as_utc(existing_marker.imported_at)
                    != marker.imported_at
                    or _as_utc(existing_marker.legacy_cutoff_at)
                    != marker.legacy_cutoff_at
                    or existing_marker.migration_revision
                    != marker.migration_revision
                ):
                    raise IdempotencyConflictError(
                        "legacy event identity was reused with different data"
                    )
                return PersistedCandidateEventV2(
                    event=event,
                    provenance=None,
                )
            session.add(self._new_event_row(event))
            session.flush()
            session.add(
                LegacyCandidateImportModel(
                    event_id=str(event.event_id),
                    schema_version=marker.schema_version,
                    imported_at=marker.imported_at,
                    legacy_cutoff_at=marker.legacy_cutoff_at,
                    migration_revision=marker.migration_revision,
                )
            )
            session.flush()
            return PersistedCandidateEventV2(event=event, provenance=None)

    def add_observation(self, observation: ObservationV1) -> ObservationModel:
        with self.session_factory.begin() as session:
            row = ObservationModel(
                observation_id=str(observation.observation_id),
                schema_version=observation.schema_version,
                dedupe_key=observation.dedupe_key,
                camera_id=observation.camera_id,
                stream_epoch=str(observation.stream_epoch),
                source_time=observation.source_time,
                timestamp_quality=observation.timestamp_quality,
                monotonic_seq=observation.monotonic_seq,
                module=observation.module,
                class_name=observation.class_name,
                confidence=observation.confidence,
                bbox=list(observation.bbox),
                track_id=observation.track_id,
                model_artifact_id=observation.model_artifact_id,
                sample_kind=observation.sample_kind,
                runtime_state=observation.runtime_state,
                received_at=observation.received_at,
            )
            session.add(row)
            session.flush()
            return row

    def count_observations(self) -> int:
        with self.session_factory() as session:
            return len(session.scalars(select(ObservationModel.observation_id)).all())

    def add_event(self, event: CandidateEventV1) -> CandidateEventModel:
        with self.session_factory.begin() as session:
            row = self._new_event_row(event)
            session.add(row)
            session.flush()
            return row

    def store_event_idempotent(self, event: CandidateEventV1) -> CandidateEventModel:
        with self.session_factory() as session:
            existing = session.scalar(
                select(CandidateEventModel).where(
                    or_(
                        CandidateEventModel.event_id == str(event.event_id),
                        CandidateEventModel.dedupe_key == event.dedupe_key,
                    )
                )
            )
            if existing is not None:
                persisted = _event_from_row(existing)
                if persisted.model_dump(mode="json", exclude={"dedupe_key"}) != event.model_dump(
                    mode="json", exclude={"dedupe_key"}
                ):
                    raise IdempotencyConflictError("event identity was reused with different data")
                return existing
            row = self._new_event_row(event)
            session.add(row)
            try:
                session.commit()
                return row
            except IntegrityError as insert_error:
                session.rollback()
                existing = session.scalar(
                    select(CandidateEventModel).where(
                        or_(
                            CandidateEventModel.event_id == str(event.event_id),
                            CandidateEventModel.dedupe_key == event.dedupe_key,
                        )
                    )
                )
                if existing is None:
                    raise insert_error
                persisted = _event_from_row(existing)
                if persisted.model_dump(mode="json", exclude={"dedupe_key"}) != event.model_dump(
                    mode="json", exclude={"dedupe_key"}
                ):
                    raise IdempotencyConflictError(
                        "event identity was reused with different data"
                    ) from insert_error
                return existing

    @staticmethod
    def _new_event_row(event: CandidateEventV1) -> CandidateEventModel:
        return CandidateEventModel(
            event_id=str(event.event_id),
            schema_version=event.schema_version,
            dedupe_key=event.dedupe_key,
            camera_id=event.camera_id,
            module=event.module,
            opened_at=event.opened_at,
            last_seen_at=event.last_seen_at,
            peak_confidence=event.peak_confidence,
            reason=event.reason,
            model_artifact_id=event.model_artifact_id,
            gate_mode=event.gate_mode,
            evidence_status=event.evidence_status,
            review_status=event.review_status,
            transition_history=">".join(event.transition_history),
        )

    def get_event(
        self,
        event_id: UUID,
        *,
        expected_site_id: str | None = None,
    ) -> CandidateEventV1:
        with self.session_factory() as session:
            statement = select(CandidateEventModel).where(
                CandidateEventModel.event_id == str(event_id)
            )
            if expected_site_id is not None:
                statement = statement.join(
                    CameraModel,
                    CameraModel.camera_id == CandidateEventModel.camera_id,
                ).where(CameraModel.site_id == expected_site_id)
            row = session.scalar(statement)
            if row is None:
                raise KeyError(f"unknown event: {event_id}")
            return _event_from_row(row)

    def mark_candidate_evidence_pending(self, event_id: UUID) -> CandidateEventV1:
        return self._set_candidate_evidence_status(
            event_id,
            target="pending",
            allowed=frozenset(("unavailable", "pending")),
        )

    def mark_candidate_evidence_failed(self, event_id: UUID) -> CandidateEventV1:
        return self._set_candidate_evidence_status(
            event_id,
            target="failed",
            allowed=frozenset(("unavailable", "pending", "failed")),
        )

    def _set_candidate_evidence_status(
        self,
        event_id: UUID,
        *,
        target: Literal["pending", "failed"],
        allowed: frozenset[str],
    ) -> CandidateEventV1:
        with self.session_factory() as session:
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            else:
                session.begin()
            try:
                row = session.scalar(
                    select(CandidateEventModel)
                    .where(CandidateEventModel.event_id == str(event_id))
                    .with_for_update()
                )
                if row is None:
                    raise KeyError(f"unknown event: {event_id}")
                if row.evidence_status not in allowed:
                    raise StaleStateError(expected=target, actual=row.evidence_status)
                row.evidence_status = target
                session.flush()
                event = _event_from_row(row)
                session.commit()
                return event
            except BaseException:
                session.rollback()
                raise

    def list_events(
        self,
        *,
        camera_id: str | None = None,
        module: str | None = None,
        gate_mode: str | None = None,
        review_status: str | None = None,
        opened_from: datetime | None = None,
        opened_to: datetime | None = None,
    ) -> list[CandidateEventV1]:
        statement: Select[tuple[CandidateEventModel]] = select(CandidateEventModel).order_by(
            CandidateEventModel.opened_at
        )
        filters = [
            value
            for value in (
                CandidateEventModel.camera_id == camera_id if camera_id is not None else None,
                CandidateEventModel.module == module if module is not None else None,
                CandidateEventModel.gate_mode == gate_mode if gate_mode is not None else None,
                (
                    CandidateEventModel.review_status == review_status
                    if review_status is not None
                    else None
                ),
                CandidateEventModel.opened_at >= opened_from if opened_from is not None else None,
                CandidateEventModel.opened_at <= opened_to if opened_to is not None else None,
            )
            if value is not None
        ]
        if filters:
            statement = statement.where(and_(*filters))
        with self.session_factory() as session:
            return [_event_from_row(row) for row in session.scalars(statement)]

    def add_user(
        self,
        *,
        user_id: str,
        username: str,
        password_hash: str,
        role: Literal["viewer", "operator", "admin"],
        totp_secret_encrypted: str | None = None,
        is_active: bool = True,
        auth_generation: int = 1,
    ) -> UserModel:
        display_username, normalized_username = prepare_username(username)
        self._authenticate_totp_envelope(totp_secret_encrypted)
        if auth_generation < 1:
            raise ValueError("auth generation must be positive")
        with self.session_factory.begin() as session:
            row = UserModel(
                user_id=user_id,
                username=display_username,
                normalized_username=normalized_username,
                password_hash=password_hash,
                role=role,
                totp_secret_encrypted=totp_secret_encrypted,
                is_active=is_active,
                auth_generation=auth_generation,
            )
            session.add(row)
            session.flush()
            return row

    def _authenticate_totp_envelope(self, encrypted: str | None) -> None:
        if encrypted is None:
            return
        if self._totp_envelopes is None:
            raise ValueError(
                "TOTP protection key is required to authenticate a seed before persistence"
            )
        try:
            self._totp_envelopes.authenticate(encrypted)
        except ValueError as exc:
            raise ValueError(
                f"invalid encrypted TOTP secret; {TOTP_ROTATION_INSTRUCTION}"
            ) from exc

    @staticmethod
    def _begin_auth_write(session: Session) -> None:
        if session.get_bind().dialect.name == "sqlite":
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        else:
            session.begin()

    @staticmethod
    def _lock_sole_site(session: Session) -> str:
        if session.get_bind().dialect.name == "postgresql":
            # Serialize only administrator lifecycle transactions without
            # granting the API UPDATE authority over site metadata.
            session.execute(
                text(
                    """
                    SELECT pg_advisory_xact_lock(
                        hashtextextended('kuzet-auth-lifecycle', 31)
                    )
                    """
                )
            )
        sites = list(
            session.scalars(
                select(SiteModel)
                .order_by(SiteModel.site_id)
            )
        )
        if len(sites) != 1:
            raise SoleSiteRequiredError("auth lifecycle requires exactly one site")
        return sites[0].site_id

    @staticmethod
    def _load_auth_user(
        session: Session,
        *,
        user_id: str,
        expected_auth_generation: int,
    ) -> UserModel:
        row = session.scalar(
            select(UserModel)
            .where(UserModel.user_id == user_id)
            .with_for_update()
        )
        if row is None:
            raise KeyError(f"unknown user: {user_id}")
        if row.auth_generation != expected_auth_generation:
            raise StaleAuthGenerationError(
                expected=expected_auth_generation,
                actual=row.auth_generation,
            )
        return row

    @staticmethod
    def _append_auth_audit(
        session: Session,
        *,
        site_id: str,
        actor_user_id: str | None,
        action: str,
        user_id: str,
        payload: dict[str, Any],
        occurred_at: datetime,
    ) -> None:
        session.add(
            AuditEntryModel(
                audit_id=str(uuid4()),
                site_id=site_id,
                occurred_at=occurred_at,
                actor_user_id=actor_user_id,
                action=action,
                entity_type="user",
                entity_id=user_id,
                payload=payload,
                idempotency_key=None,
            )
        )

    @staticmethod
    def _ensure_admin_survives(session: Session, row: UserModel, *, remains_admin: bool) -> None:
        if row.role != "admin" or not row.is_active or remains_admin:
            return
        other_active_admins = session.scalar(
            select(func.count())
            .select_from(UserModel)
            .where(
                UserModel.user_id != row.user_id,
                UserModel.role == "admin",
                UserModel.is_active.is_(True),
            )
        )
        if int(other_active_admins or 0) < 1:
            raise LastActiveAdminError("at least one active admin is required")

    def bootstrap_first_admin(
        self,
        *,
        user_id: str,
        username: str,
        password_hash: str,
        totp_secret_encrypted: str,
        occurred_at: datetime,
    ) -> UserModel:
        display_username, normalized_username = prepare_username(username)
        self._authenticate_totp_envelope(totp_secret_encrypted)
        with self.session_factory() as session:
            self._begin_auth_write(session)
            try:
                site_id = self._lock_sole_site(session)
                user_count = session.scalar(select(func.count()).select_from(UserModel))
                if int(user_count or 0) != 0:
                    raise BootstrapAlreadyCompletedError(
                        "first-admin bootstrap requires an empty user table"
                    )
                row = UserModel(
                    user_id=user_id,
                    username=display_username,
                    normalized_username=normalized_username,
                    password_hash=password_hash,
                    totp_secret_encrypted=totp_secret_encrypted,
                    totp_last_accepted_counter=None,
                    auth_generation=1,
                    role="admin",
                    is_active=True,
                )
                session.add(row)
                self._append_auth_audit(
                    session,
                    site_id=site_id,
                    actor_user_id=None,
                    action="auth.first_admin_bootstrapped",
                    user_id=user_id,
                    payload={
                        "role": "admin",
                        "auth_generation": 1,
                        "normalized_username_sha256": hashlib.sha256(
                            normalized_username.encode()
                        ).hexdigest(),
                    },
                    occurred_at=occurred_at,
                )
                session.flush()
                session.commit()
                return row
            except BaseException:
                session.rollback()
                raise

    def list_users(self) -> list[UserModel]:
        with self.session_factory() as session:
            sites = list(session.scalars(select(SiteModel.site_id)))
            if len(sites) != 1:
                raise SoleSiteRequiredError("auth lifecycle requires exactly one site")
            return list(
                session.scalars(
                    select(UserModel).order_by(
                        UserModel.normalized_username,
                        UserModel.user_id,
                    )
                )
            )

    def create_user(
        self,
        *,
        actor_user_id: str,
        user_id: str,
        username: str,
        password_hash: str,
        role: Literal["viewer", "operator", "admin"],
        totp_secret_encrypted: str,
        occurred_at: datetime,
    ) -> UserModel:
        display_username, normalized_username = prepare_username(username)
        self._authenticate_totp_envelope(totp_secret_encrypted)
        with self.session_factory() as session:
            self._begin_auth_write(session)
            try:
                site_id = self._lock_sole_site(session)
                row = UserModel(
                    user_id=user_id,
                    username=display_username,
                    normalized_username=normalized_username,
                    password_hash=password_hash,
                    totp_secret_encrypted=totp_secret_encrypted,
                    totp_last_accepted_counter=None,
                    auth_generation=1,
                    role=role,
                    is_active=True,
                )
                session.add(row)
                self._append_auth_audit(
                    session,
                    site_id=site_id,
                    actor_user_id=actor_user_id,
                    action="auth.user.created",
                    user_id=user_id,
                    payload={
                        "role": role,
                        "is_active": True,
                        "auth_generation": 1,
                        "normalized_username_sha256": hashlib.sha256(
                            normalized_username.encode()
                        ).hexdigest(),
                    },
                    occurred_at=occurred_at,
                )
                session.flush()
                session.commit()
                return row
            except IntegrityError as exc:
                session.rollback()
                raise UsernameConflictError("username or user identity already exists") from exc
            except BaseException:
                session.rollback()
                raise

    def set_user_role(
        self,
        *,
        actor_user_id: str,
        user_id: str,
        role: Literal["viewer", "operator", "admin"],
        expected_auth_generation: int,
        occurred_at: datetime,
    ) -> UserModel:
        return self._mutate_user(
            actor_user_id=actor_user_id,
            user_id=user_id,
            expected_auth_generation=expected_auth_generation,
            occurred_at=occurred_at,
            action="auth.user.role_changed",
            mutation=lambda row: self._set_role(row, role),
        )

    def set_user_active(
        self,
        *,
        actor_user_id: str,
        user_id: str,
        is_active: bool,
        expected_auth_generation: int,
        occurred_at: datetime,
    ) -> UserModel:
        return self._mutate_user(
            actor_user_id=actor_user_id,
            user_id=user_id,
            expected_auth_generation=expected_auth_generation,
            occurred_at=occurred_at,
            action="auth.user.active_changed",
            mutation=lambda row: self._set_active(row, is_active),
        )

    def set_user_password(
        self,
        *,
        actor_user_id: str,
        user_id: str,
        password_hash: str,
        expected_auth_generation: int,
        occurred_at: datetime,
    ) -> UserModel:
        if not password_hash:
            raise ValueError("password hash must not be empty")
        return self._mutate_user(
            actor_user_id=actor_user_id,
            user_id=user_id,
            expected_auth_generation=expected_auth_generation,
            occurred_at=occurred_at,
            action="auth.user.password_changed",
            mutation=lambda row: self._set_password(row, password_hash),
        )

    def reset_user_totp(
        self,
        *,
        actor_user_id: str,
        user_id: str,
        totp_secret_encrypted: str,
        expected_auth_generation: int,
        occurred_at: datetime,
    ) -> UserModel:
        self._authenticate_totp_envelope(totp_secret_encrypted)
        return self._mutate_user(
            actor_user_id=actor_user_id,
            user_id=user_id,
            expected_auth_generation=expected_auth_generation,
            occurred_at=occurred_at,
            action="auth.user.totp_reset",
            mutation=lambda row: self._set_totp(row, totp_secret_encrypted),
        )

    def revoke_user_sessions(
        self,
        *,
        actor_user_id: str,
        user_id: str,
        expected_auth_generation: int,
        occurred_at: datetime,
    ) -> UserModel:
        return self._mutate_user(
            actor_user_id=actor_user_id,
            user_id=user_id,
            expected_auth_generation=expected_auth_generation,
            occurred_at=occurred_at,
            action="auth.user.sessions_revoked",
            mutation=lambda row: {},
        )

    def _mutate_user(
        self,
        *,
        actor_user_id: str,
        user_id: str,
        expected_auth_generation: int,
        occurred_at: datetime,
        action: str,
        mutation: Callable[[UserModel], dict[str, Any]],
    ) -> UserModel:
        if expected_auth_generation < 1:
            raise ValueError("expected auth generation must be positive")
        with self.session_factory() as session:
            self._begin_auth_write(session)
            try:
                site_id = self._lock_sole_site(session)
                row = self._load_auth_user(
                    session,
                    user_id=user_id,
                    expected_auth_generation=expected_auth_generation,
                )
                payload = mutation(row)
                row.auth_generation += 1
                payload["auth_generation"] = row.auth_generation
                self._append_auth_audit(
                    session,
                    site_id=site_id,
                    actor_user_id=actor_user_id,
                    action=action,
                    user_id=user_id,
                    payload=payload,
                    occurred_at=occurred_at,
                )
                session.flush()
                session.commit()
                return row
            except BaseException:
                session.rollback()
                raise

    def _set_role(
        self,
        row: UserModel,
        role: Literal["viewer", "operator", "admin"],
    ) -> dict[str, Any]:
        self._ensure_admin_survives(
            object_session(row),
            row,
            remains_admin=role == "admin",
        )
        previous = row.role
        row.role = role
        return {"from_role": previous, "to_role": role}

    def _set_active(self, row: UserModel, is_active: bool) -> dict[str, Any]:
        self._ensure_admin_survives(
            object_session(row),
            row,
            remains_admin=is_active,
        )
        previous = row.is_active
        row.is_active = is_active
        return {"from_active": previous, "to_active": is_active}

    @staticmethod
    def _set_password(row: UserModel, password_hash: str) -> dict[str, Any]:
        row.password_hash = password_hash
        return {}

    @staticmethod
    def _set_totp(row: UserModel, encrypted: str) -> dict[str, Any]:
        row.totp_secret_encrypted = encrypted
        row.totp_last_accepted_counter = None
        return {}

    def accept_totp_counter(
        self,
        *,
        user_id: str,
        counter: int,
        expected_password_hash: str,
        expected_encrypted_secret: str,
    ) -> bool:
        """Atomically advance one user's accepted TOTP counter."""
        if counter < 0:
            raise ValueError("TOTP counter must be non-negative")
        with self.session_factory() as session:
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            result = session.execute(
                update(UserModel)
                .where(
                    UserModel.user_id == user_id,
                    UserModel.is_active.is_(True),
                    UserModel.password_hash == expected_password_hash,
                    UserModel.totp_secret_encrypted == expected_encrypted_secret,
                    or_(
                        UserModel.totp_last_accepted_counter.is_(None),
                        UserModel.totp_last_accepted_counter < counter,
                    ),
                )
                .values(totp_last_accepted_counter=counter)
            )
            session.commit()
            return result.rowcount == 1

    def append_audit(self, entry: AuditEntryInput) -> AuditEntryModel:
        with self.session_factory.begin() as session:
            if entry.idempotency_key is not None:
                existing = session.scalar(
                    select(AuditEntryModel).where(
                        AuditEntryModel.idempotency_key == entry.idempotency_key
                    )
                )
                if existing is not None:
                    if (
                        existing.action,
                        existing.entity_type,
                        existing.entity_id,
                        existing.payload,
                    ) != (
                        entry.action,
                        entry.entity_type,
                        entry.entity_id,
                        entry.payload,
                    ):
                        raise IdempotencyConflictError(
                            "audit idempotency key was reused with different data"
                        )
                    return existing
            row = AuditEntryModel(
                audit_id=str(uuid4()),
                site_id=_audit_site_id(session, entry.entity_type, entry.entity_id),
                occurred_at=entry.occurred_at,
                actor_user_id=entry.actor_user_id,
                action=entry.action,
                entity_type=entry.entity_type,
                entity_id=entry.entity_id,
                payload=dict(entry.payload),
                idempotency_key=entry.idempotency_key,
            )
            session.add(row)
            session.flush()
            return row

    def review_event(
        self,
        *,
        event_id: UUID,
        reviewer_id: str,
        target_status: ReviewStatus,
        idempotency_key: str,
        notes: str | None,
        reviewed_at: datetime,
    ) -> ReviewModel:
        with self.session_factory() as session:
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            row = session.scalar(
                select(CandidateEventModel)
                .where(CandidateEventModel.event_id == str(event_id))
                .with_for_update()
            )
            if row is None:
                session.rollback()
                raise KeyError(f"unknown event: {event_id}")
            existing = session.scalar(
                select(ReviewModel).where(
                    ReviewModel.event_id == str(event_id),
                    ReviewModel.idempotency_key == idempotency_key,
                )
            )
            if existing is not None:
                if (
                    existing.reviewer_id,
                    existing.to_status,
                    existing.notes,
                    _as_utc(existing.reviewed_at),
                ) != (reviewer_id, target_status, notes, _as_utc(reviewed_at)):
                    session.rollback()
                    raise IdempotencyConflictError(
                        "review idempotency key was reused with different data"
                    )
                session.commit()
                return existing

            current = _event_from_row(row)
            transitioned = current.transition_to(target_status)
            result = session.execute(
                update(CandidateEventModel)
                .where(
                    CandidateEventModel.event_id == str(event_id),
                    CandidateEventModel.review_status == current.review_status,
                )
                .values(
                    review_status=transitioned.review_status,
                    transition_history=">".join(transitioned.transition_history),
                )
            )
            if result.rowcount != 1:
                session.rollback()
                raise RuntimeError("event was reviewed concurrently")

            review = ReviewModel(
                review_id=str(uuid4()),
                event_id=str(event_id),
                reviewer_id=reviewer_id,
                from_status=current.review_status,
                to_status=target_status,
                notes=notes,
                idempotency_key=idempotency_key,
                reviewed_at=reviewed_at,
            )
            session.add(review)
            audit_site_id = session.scalar(
                select(CameraModel.site_id).where(CameraModel.camera_id == row.camera_id)
            )
            session.add(
                AuditEntryModel(
                    audit_id=str(uuid4()),
                    site_id=audit_site_id,
                    occurred_at=reviewed_at,
                    actor_user_id=reviewer_id,
                    action=f"event.{target_status}",
                    entity_type="candidate_event",
                    entity_id=str(event_id),
                    payload=_review_audit_payload(
                        from_status=current.review_status,
                        to_status=target_status,
                        notes=notes,
                    ),
                    idempotency_key=_review_audit_key(event_id, idempotency_key),
                )
            )
            session.flush()
            session.commit()
            return review

    def review_event_and_enqueue_notification(
        self,
        *,
        event_id: UUID,
        reviewer_id: str,
        target_status: ReviewStatus,
        expected_status: ReviewStatus,
        review_idempotency_key: str,
        notification_idempotency_key: str,
        notes: str | None,
        reviewed_at: datetime,
        expected_site_id: str | None = None,
    ) -> ReviewNotificationResult:
        """Commit review, audit, and any confirmed-operator outbox row together."""
        with self.session_factory() as session:
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            event_statement = select(CandidateEventModel).where(
                CandidateEventModel.event_id == str(event_id)
            )
            if expected_site_id is not None:
                event_statement = event_statement.join(
                    CameraModel,
                    CameraModel.camera_id == CandidateEventModel.camera_id,
                ).where(CameraModel.site_id == expected_site_id)
            event_row = session.scalar(event_statement.with_for_update())
            if event_row is None:
                session.rollback()
                raise KeyError(f"unknown event: {event_id}")
            conflicting_outbox = session.scalar(
                select(NotificationOutboxModel).where(
                    NotificationOutboxModel.idempotency_key == notification_idempotency_key,
                    NotificationOutboxModel.event_id != str(event_id),
                )
            )
            if conflicting_outbox is not None:
                session.rollback()
                raise IdempotencyConflictError(
                    "notification identity was reused with different data"
                )

            existing_review = session.scalar(
                select(ReviewModel).where(
                    ReviewModel.event_id == str(event_id),
                    ReviewModel.idempotency_key == review_idempotency_key,
                )
            )
            if existing_review is not None:
                if (
                    existing_review.reviewer_id,
                    existing_review.from_status,
                    existing_review.to_status,
                    existing_review.notes,
                    _as_utc(existing_review.reviewed_at),
                ) != (
                    reviewer_id,
                    expected_status,
                    target_status,
                    notes,
                    _as_utc(reviewed_at),
                ):
                    session.rollback()
                    raise IdempotencyConflictError(
                        "review idempotency key was reused with different data"
                    )
                outbox = session.scalar(
                    select(NotificationOutboxModel).where(
                        NotificationOutboxModel.event_id == str(event_id)
                    )
                )
                if outbox is not None and outbox.idempotency_key != notification_idempotency_key:
                    session.rollback()
                    raise IdempotencyConflictError(
                        "notification identity was reused with different data"
                    )
                persisted_event = _event_from_row(event_row)
                if (
                    outbox is None
                    and persisted_event.gate_mode == "operator"
                    and existing_review.to_status == "confirmed"
                ):
                    NotificationOutboxRecordV1.from_confirmed_event(
                        persisted_event,
                        idempotency_key=notification_idempotency_key,
                    )
                    outbox = NotificationOutboxModel(
                        outbox_id=str(uuid4()),
                        event_id=str(event_id),
                        idempotency_key=notification_idempotency_key,
                        status="pending",
                        payload={},
                        available_at=datetime.now(timezone.utc),
                    )
                    session.add(outbox)
                    session.flush()
                session.commit()
                return ReviewNotificationResult(review=existing_review, outbox=outbox)

            current = _event_from_row(event_row)
            if current.review_status != expected_status:
                session.rollback()
                raise StaleStateError(expected=expected_status, actual=current.review_status)
            transitioned = current.transition_to(target_status)
            event_row.review_status = transitioned.review_status
            event_row.transition_history = ">".join(transitioned.transition_history)
            review = ReviewModel(
                review_id=str(uuid4()),
                event_id=str(event_id),
                reviewer_id=reviewer_id,
                from_status=current.review_status,
                to_status=target_status,
                notes=notes,
                idempotency_key=review_idempotency_key,
                reviewed_at=reviewed_at,
            )
            session.add(review)
            audit_site_id = expected_site_id or session.scalar(
                select(CameraModel.site_id).where(
                    CameraModel.camera_id == event_row.camera_id
                )
            )
            session.add(
                AuditEntryModel(
                    audit_id=str(uuid4()),
                    site_id=audit_site_id,
                    occurred_at=reviewed_at,
                    actor_user_id=reviewer_id,
                    action=f"event.{target_status}",
                    entity_type="candidate_event",
                    entity_id=str(event_id),
                    payload=_review_audit_payload(
                        from_status=current.review_status,
                        to_status=target_status,
                        notes=notes,
                    ),
                    idempotency_key=_review_audit_key(event_id, review_idempotency_key),
                )
            )
            session.flush()

            outbox: NotificationOutboxModel | None = None
            if transitioned.gate_mode == "operator" and target_status == "confirmed":
                NotificationOutboxRecordV1.from_confirmed_event(
                    transitioned,
                    idempotency_key=notification_idempotency_key,
                )
                outbox = NotificationOutboxModel(
                    outbox_id=str(uuid4()),
                    event_id=str(event_id),
                    idempotency_key=notification_idempotency_key,
                    status="pending",
                    payload={},
                    available_at=datetime.now(timezone.utc),
                )
                session.add(outbox)
                session.flush()
            session.commit()
            return ReviewNotificationResult(review=review, outbox=outbox)

    def enqueue_notification(
        self,
        *,
        event_id: UUID,
        idempotency_key: str,
        payload: dict[str, Any] | None = None,
    ) -> NotificationOutboxModel:
        requested_payload = dict(payload or {})
        with self.session_factory() as session:
            existing = session.scalar(
                select(NotificationOutboxModel).where(
                    or_(
                        NotificationOutboxModel.event_id == str(event_id),
                        NotificationOutboxModel.idempotency_key == idempotency_key,
                    )
                )
            )
            if existing is not None:
                if (
                    existing.event_id != str(event_id)
                    or existing.idempotency_key != idempotency_key
                    or existing.payload != requested_payload
                ):
                    raise IdempotencyConflictError(
                        "notification identity was reused with different data"
                    )
                return existing
            event_row = session.get(CandidateEventModel, str(event_id))
            if event_row is None:
                raise KeyError(f"unknown event: {event_id}")
            event_contract = _event_from_row(event_row)
            NotificationOutboxRecordV1.from_confirmed_event(
                event_contract, idempotency_key=idempotency_key
            )
            row = NotificationOutboxModel(
                outbox_id=str(uuid4()),
                event_id=str(event_id),
                idempotency_key=idempotency_key,
                status="pending",
                payload=requested_payload,
                available_at=datetime.now(timezone.utc),
            )
            session.add(row)
            try:
                session.commit()
                return row
            except IntegrityError as insert_error:
                session.rollback()
                existing = session.scalar(
                    select(NotificationOutboxModel).where(
                        or_(
                            NotificationOutboxModel.event_id == str(event_id),
                            NotificationOutboxModel.idempotency_key == idempotency_key,
                        )
                    )
                )
                if existing is None:
                    raise insert_error
                if (
                    existing.event_id != str(event_id)
                    or existing.idempotency_key != idempotency_key
                    or existing.payload != requested_payload
                ):
                    raise IdempotencyConflictError(
                        "notification identity was reused with different data"
                    ) from insert_error
                return existing

    def add_evidence(self, evidence: EvidenceInput) -> EvidenceModel:
        with self.session_factory() as session:
            existing = session.scalar(
                select(EvidenceModel).where(
                    or_(
                        EvidenceModel.evidence_id == str(evidence.evidence_id),
                        EvidenceModel.object_key == evidence.object_key,
                    )
                )
            )
            if existing is not None:
                if not self._evidence_matches(existing, evidence):
                    raise IdempotencyConflictError(
                        "evidence identity was reused with different data"
                    )
                return existing
            row = EvidenceModel(
                evidence_id=str(evidence.evidence_id),
                event_id=str(evidence.event_id),
                object_key=evidence.object_key,
                sha256=evidence.sha256,
                codec=evidence.codec,
                start_at=evidence.start_at,
                end_at=evidence.end_at,
                source_reference=evidence.source_reference,
                status=evidence.status,
            )
            session.add(row)
            try:
                session.commit()
                return row
            except IntegrityError as insert_error:
                session.rollback()
                existing = session.scalar(
                    select(EvidenceModel).where(
                        or_(
                            EvidenceModel.evidence_id == str(evidence.evidence_id),
                            EvidenceModel.object_key == evidence.object_key,
                        )
                    )
                )
                if existing is None:
                    raise insert_error
                if not self._evidence_matches(existing, evidence):
                    raise IdempotencyConflictError(
                        "evidence identity was reused with different data"
                    ) from insert_error
                return existing

    def finalize_evidence(
        self,
        evidence: EvidenceInput,
        *,
        status: Literal["ready", "failed"],
    ) -> EvidenceModel:
        """Atomically align one evidence row and its candidate's visible status.

        Object publication happens before this transaction.  A retry may promote
        ``failed`` to ``ready`` after the object store verifies the same key and
        digest, but a ready identity can never be downgraded or repurposed.
        """
        with self.session_factory() as session:
            if session.get_bind().dialect.name == "sqlite":
                # SQLite ignores SELECT FOR UPDATE; acquire the writer slot
                # before reading either state so two workers cannot validate
                # the same stale pending row.
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            else:
                session.begin()
            try:
                event = session.scalar(
                    select(CandidateEventModel)
                    .where(CandidateEventModel.event_id == str(evidence.event_id))
                    .with_for_update()
                )
                if event is None:
                    raise KeyError(f"unknown event: {evidence.event_id}")
                row = session.scalar(
                    select(EvidenceModel)
                    .where(
                        or_(
                            EvidenceModel.evidence_id == str(evidence.evidence_id),
                            EvidenceModel.object_key == evidence.object_key,
                        )
                    )
                    .with_for_update()
                )
                if event.evidence_status == "ready" and status == "failed":
                    if row is None or not self._evidence_material_matches(row, evidence):
                        raise IdempotencyConflictError(
                            "failed replay conflicts with ready evidence identity"
                        )
                    session.commit()
                    return row
                event_transitions = {
                    "pending": {"ready", "failed"},
                    "failed": {"failed", "ready"},
                    "ready": {"ready"},
                }
                if status not in event_transitions.get(event.evidence_status, set()):
                    raise StaleStateError(expected=status, actual=event.evidence_status)
                if row is None:
                    row = EvidenceModel(
                        evidence_id=str(evidence.evidence_id),
                        event_id=str(evidence.event_id),
                        object_key=evidence.object_key,
                        sha256=evidence.sha256,
                        codec=evidence.codec,
                        start_at=evidence.start_at,
                        end_at=evidence.end_at,
                        source_reference=evidence.source_reference,
                        status=status,
                    )
                    session.add(row)
                else:
                    if not self._evidence_material_matches(row, evidence):
                        raise IdempotencyConflictError(
                            "evidence identity was reused with different data"
                        )
                    evidence_transitions = {
                        "pending": {"ready", "failed"},
                        "failed": {"failed", "ready"},
                        "ready": {"ready"},
                    }
                    if status not in evidence_transitions.get(row.status, set()):
                        raise IdempotencyConflictError("ready evidence cannot be downgraded")
                    row.status = status
                event.evidence_status = status
                session.flush()
                session.commit()
                return row
            except BaseException:
                session.rollback()
                raise

    @staticmethod
    def _evidence_matches(row: EvidenceModel, evidence: EvidenceInput) -> bool:
        return (
            row.evidence_id,
            row.event_id,
            row.object_key,
            row.sha256,
            row.codec,
            _as_utc(row.start_at),
            _as_utc(row.end_at),
            row.source_reference,
            row.status,
        ) == (
            str(evidence.evidence_id),
            str(evidence.event_id),
            evidence.object_key,
            evidence.sha256,
            evidence.codec,
            _as_utc(evidence.start_at),
            _as_utc(evidence.end_at),
            evidence.source_reference,
            evidence.status,
        )

    @staticmethod
    def _evidence_material_matches(row: EvidenceModel, evidence: EvidenceInput) -> bool:
        return (
            row.evidence_id,
            row.event_id,
            row.object_key,
            row.sha256,
            row.codec,
            _as_utc(row.start_at),
            _as_utc(row.end_at),
            row.source_reference,
        ) == (
            str(evidence.evidence_id),
            str(evidence.event_id),
            evidence.object_key,
            evidence.sha256,
            evidence.codec,
            _as_utc(evidence.start_at),
            _as_utc(evidence.end_at),
            evidence.source_reference,
        )

    def persist_journal_item(self, item: Any) -> None:
        """Commit one journal item before returning so the journal may acknowledge it."""
        validate_journal_work(item.kind, item.schema_version, item.payload)
        if item.kind == "candidate_event":
            self.store_event_idempotent(CandidateEventV1.model_validate(item.payload))
            return
        if item.kind == "evidence":
            evidence = EvidenceInput.from_payload(item.payload)
            if evidence.status in ("ready", "failed"):
                self.finalize_evidence(evidence, status=evidence.status)
            else:
                self.add_evidence(evidence)
            return
        if item.kind == "evidence_intent":
            intent = EvidenceIntent.from_payload(item.payload)
            if intent.status != "failed":
                raise ValueError("journalled evidence intent must be terminal")
            self.mark_candidate_evidence_failed(intent.event_id)
            return
        raise ValueError(f"unsupported journal item kind: {item.kind}")
