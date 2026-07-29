"""Portable SQLAlchemy schema for PostgreSQL pilot state."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    DDL,
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from protector.pilot.totp_envelope import PORTABLE_TOTP_ENVELOPE_CHECK


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class SiteModel(Base):
    __tablename__ = "sites"

    site_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    timezone_name: Mapped[str] = mapped_column(String(64), nullable=False, default="Asia/Almaty")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class CameraModel(Base):
    __tablename__ = "cameras"
    __table_args__ = (
        CheckConstraint("codec IN ('h264', 'h265')", name="ck_cameras_codec"),
        CheckConstraint(
            "state IN ('starting', 'online', 'degraded', 'offline', 'reconnecting')",
            name="ck_cameras_state",
        ),
        UniqueConstraint("site_id", "name", name="uq_cameras_site_name"),
        Index("ix_cameras_site_state", "site_id", "state"),
    )

    camera_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    site_id: Mapped[str] = mapped_column(
        ForeignKey("sites.site_id", ondelete="RESTRICT"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    source_reference: Mapped[str] = mapped_column(String(1024), nullable=False)
    codec: Mapped[str] = mapped_column(String(8), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="starting")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class CameraHealthSampleModel(Base):
    __tablename__ = "camera_health_samples"
    __table_args__ = (
        CheckConstraint(
            "state IN ('starting', 'online', 'degraded', 'offline', 'reconnecting')",
            name="ck_camera_health_state",
        ),
        CheckConstraint("reconnect_count >= 0", name="ck_camera_health_reconnect_count"),
        CheckConstraint("dropped_samples >= 0", name="ck_camera_health_dropped_samples"),
        Index("ix_camera_health_camera_observed", "camera_id", "observed_at"),
    )

    health_sample_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    camera_id: Mapped[str] = mapped_column(
        ForeignKey("cameras.camera_id", ondelete="CASCADE"), nullable=False
    )
    runtime_session_id: Mapped[str] = mapped_column(
        String(128), nullable=False, default="legacy", server_default="legacy"
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    last_frame_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reconnect_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    dropped_samples: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    degraded_reason: Mapped[str | None] = mapped_column(Text)


class TelemetryPublisherEpochModel(Base):
    __tablename__ = "telemetry_publisher_epochs"
    __table_args__ = (
        CheckConstraint(
            "publisher IN ('runtime', 'notifications')",
            name="ck_telemetry_publisher",
        ),
        CheckConstraint("generation > 0", name="ck_telemetry_generation"),
        CheckConstraint("last_sequence >= 0", name="ck_telemetry_last_sequence"),
        CheckConstraint(
            "length(last_payload_digest) = 64",
            name="ck_telemetry_payload_digest",
        ),
        Index(
            "ix_telemetry_publisher_generation",
            "site_id",
            "publisher",
            "generation",
        ),
    )

    site_id: Mapped[str] = mapped_column(
        ForeignKey("sites.site_id", ondelete="RESTRICT"),
        primary_key=True,
    )
    publisher: Mapped[str] = mapped_column(String(32), primary_key=True)
    runtime_session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    generation: Mapped[int] = mapped_column(BigInteger, nullable=False)
    last_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    last_payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    activated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


class ModelArtifactModel(Base):
    __tablename__ = "model_artifacts"
    __table_args__ = (
        CheckConstraint("sha256 IS NULL OR length(sha256) = 64", name="ck_model_artifacts_sha256"),
    )

    artifact_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    analytic: Mapped[str] = mapped_column(String(128), nullable=False)
    sha256: Mapped[str | None] = mapped_column(String(64))
    source: Mapped[str | None] = mapped_column(String(2048))
    commercial_rights: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    class_list: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    preprocessing: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class GateReportModel(Base):
    __tablename__ = "gate_reports"
    __table_args__ = (
        CheckConstraint(
            "report_type IN ('target_site', 'capacity', 'shadow_stage')",
            name="ck_gate_reports_type",
        ),
        CheckConstraint(
            "result_mode IN ('disabled', 'shadow', 'operator')",
            name="ck_gate_reports_result_mode",
        ),
        CheckConstraint("length(report_sha256) = 64", name="ck_gate_reports_sha256"),
        CheckConstraint(
            "stream_count IS NULL OR stream_count >= 1", name="ck_gate_reports_stream_count"
        ),
        UniqueConstraint(
            "artifact_id", "report_type", "report_reference", name="uq_gate_reports_provenance"
        ),
    )

    report_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_id: Mapped[str] = mapped_column(
        ForeignKey("model_artifacts.artifact_id", ondelete="RESTRICT"), nullable=False
    )
    report_type: Mapped[str] = mapped_column(String(32), nullable=False)
    site_id: Mapped[str | None] = mapped_column(ForeignKey("sites.site_id", ondelete="RESTRICT"))
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    report_reference: Mapped[str] = mapped_column(String(2048), nullable=False)
    report_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    signed_by: Mapped[str] = mapped_column(String(255), nullable=False)
    signed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    stream_count: Mapped[int | None] = mapped_column(Integer)
    result_mode: Mapped[str] = mapped_column(String(16), nullable=False)
    reasons: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class ObservationModel(Base):
    __tablename__ = "observations"
    __table_args__ = (
        CheckConstraint("schema_version = 'observation.v1'", name="ck_observations_schema"),
        CheckConstraint(
            "timestamp_quality IN ('camera_rtcp', 'host_ntp_fallback')",
            name="ck_observations_timestamp_quality",
        ),
        CheckConstraint("monotonic_seq >= 0", name="ck_observations_monotonic_seq"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_observations_confidence"),
        CheckConstraint(
            "sample_kind IN ('fresh', 'cached_display')", name="ck_observations_sample_kind"
        ),
        CheckConstraint(
            "runtime_state IN ('starting', 'online', 'degraded', 'offline', 'reconnecting')",
            name="ck_observations_runtime_state",
        ),
        Index("ix_observations_camera_source_time", "camera_id", "source_time"),
    )

    observation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    dedupe_key: Mapped[str] = mapped_column(String(1024), nullable=False, unique=True)
    camera_id: Mapped[str] = mapped_column(
        ForeignKey("cameras.camera_id", ondelete="RESTRICT"), nullable=False
    )
    stream_epoch: Mapped[str] = mapped_column(String(36), nullable=False)
    source_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    timestamp_quality: Mapped[str] = mapped_column(String(32), nullable=False)
    monotonic_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    module: Mapped[str] = mapped_column(String(128), nullable=False)
    class_name: Mapped[str] = mapped_column(String(128), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    bbox: Mapped[list[float]] = mapped_column(JSON, nullable=False)
    track_id: Mapped[str | None] = mapped_column(String(255))
    model_artifact_id: Mapped[str] = mapped_column(
        ForeignKey("model_artifacts.artifact_id", ondelete="RESTRICT"), nullable=False
    )
    sample_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    runtime_state: Mapped[str] = mapped_column(String(32), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CandidateEventModel(Base):
    __tablename__ = "candidate_events"
    __table_args__ = (
        CheckConstraint("schema_version = 'candidate-event.v1'", name="ck_candidate_events_schema"),
        CheckConstraint(
            "gate_mode IN ('disabled', 'shadow', 'operator')",
            name="ck_candidate_events_gate_mode",
        ),
        CheckConstraint(
            "evidence_status IN ('pending', 'ready', 'failed', 'unavailable')",
            name="ck_candidate_events_evidence_status",
        ),
        CheckConstraint(
            "review_status IN "
            "('observation', 'candidate', 'confirmed', 'rejected', 'expired', 'escalated')",
            name="ck_candidate_events_review_status",
        ),
        CheckConstraint(
            "peak_confidence >= 0 AND peak_confidence <= 1",
            name="ck_candidate_events_peak_confidence",
        ),
        CheckConstraint("last_seen_at >= opened_at", name="ck_candidate_events_time_range"),
        CheckConstraint(
            "(review_status = 'observation' AND transition_history = 'observation') OR "
            "(review_status = 'candidate' AND "
            "transition_history = 'observation>candidate') OR "
            "(review_status = 'confirmed' AND "
            "transition_history = 'observation>candidate>confirmed') OR "
            "(review_status = 'rejected' AND "
            "transition_history = 'observation>candidate>rejected') OR "
            "(review_status = 'expired' AND "
            "transition_history = 'observation>candidate>expired') OR "
            "(review_status = 'escalated' AND "
            "transition_history = 'observation>candidate>confirmed>escalated')",
            name="ck_candidate_events_lifecycle",
        ),
        Index("ix_candidate_events_camera_opened", "camera_id", "opened_at"),
        Index(
            "ix_candidate_events_filters",
            "module",
            "gate_mode",
            "review_status",
            "opened_at",
        ),
    )

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    dedupe_key: Mapped[str] = mapped_column(String(1024), nullable=False, unique=True)
    camera_id: Mapped[str] = mapped_column(
        ForeignKey("cameras.camera_id", ondelete="RESTRICT"), nullable=False
    )
    module: Mapped[str] = mapped_column(String(128), nullable=False)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    peak_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    model_artifact_id: Mapped[str] = mapped_column(
        ForeignKey("model_artifacts.artifact_id", ondelete="RESTRICT"), nullable=False
    )
    gate_mode: Mapped[str] = mapped_column(String(16), nullable=False)
    evidence_status: Mapped[str] = mapped_column(String(16), nullable=False)
    review_status: Mapped[str] = mapped_column(String(16), nullable=False)
    transition_history: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class EvidenceModel(Base):
    __tablename__ = "evidence"
    __table_args__ = (
        CheckConstraint("length(sha256) = 64", name="ck_evidence_sha256"),
        CheckConstraint("codec IN ('h264', 'h265')", name="ck_evidence_codec"),
        CheckConstraint(
            "status IN ('pending', 'ready', 'failed', 'unavailable')",
            name="ck_evidence_status",
        ),
        CheckConstraint("end_at >= start_at", name="ck_evidence_time_range"),
        UniqueConstraint("event_id", "object_key", name="uq_evidence_event_object"),
    )

    evidence_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_id: Mapped[str] = mapped_column(
        ForeignKey("candidate_events.event_id", ondelete="CASCADE"), nullable=False
    )
    object_key: Mapped[str] = mapped_column(String(2048), nullable=False, unique=True)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    codec: Mapped[str] = mapped_column(String(8), nullable=False)
    start_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_reference: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


for evidence_operation in ("INSERT", "UPDATE"):
    event.listen(
        EvidenceModel.__table__,
        "after_create",
        DDL(
            f"""
            CREATE TRIGGER trg_evidence_duration_{evidence_operation.lower()}
            BEFORE {evidence_operation} ON evidence
            FOR EACH ROW
            WHEN NEW.end_at <= NEW.start_at
              OR (julianday(NEW.end_at) - julianday(NEW.start_at)) * 86400.0 > 10.0001
              OR (
                  NEW.status = 'ready'
                  AND (julianday(NEW.end_at) - julianday(NEW.start_at)) * 86400.0 < 3.9999
              )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'evidence duration violates the bounded clip policy'
                );
            END
            """
        ).execute_if(dialect="sqlite"),
    )
event.listen(
    EvidenceModel.__table__,
    "after_create",
    DDL(
        """
        CREATE OR REPLACE FUNCTION pilot_validate_evidence_duration()
        RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
            duration_seconds double precision;
        BEGIN
            duration_seconds := EXTRACT(EPOCH FROM (NEW.end_at - NEW.start_at));
            IF duration_seconds <= 0
               OR duration_seconds > 10
               OR (NEW.status = 'ready' AND duration_seconds < 4) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'evidence duration violates the bounded clip policy';
            END IF;
            RETURN NEW;
        END;
        $$;
        """
    ).execute_if(dialect="postgresql"),
)
event.listen(
    EvidenceModel.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_evidence_duration
        BEFORE INSERT OR UPDATE ON evidence
        FOR EACH ROW EXECUTE FUNCTION pilot_validate_evidence_duration()
        """
    ).execute_if(dialect="postgresql"),
)
event.listen(
    EvidenceModel.__table__,
    "after_drop",
    DDL("DROP FUNCTION IF EXISTS pilot_validate_evidence_duration()").execute_if(
        dialect="postgresql"
    ),
)


class UserModel(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('viewer', 'operator', 'admin')", name="ck_users_role"),
        CheckConstraint(
            PORTABLE_TOTP_ENVELOPE_CHECK,
            name="ck_users_totp_encrypted_envelope",
        ),
    )

    user_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    username: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(1024), nullable=False)
    totp_secret_encrypted: Mapped[str | None] = mapped_column(Text)
    totp_last_accepted_counter: Mapped[int | None] = mapped_column(BigInteger)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class ReviewModel(Base):
    __tablename__ = "reviews"
    __table_args__ = (
        CheckConstraint("from_status IN ('candidate', 'confirmed')", name="ck_reviews_from_status"),
        CheckConstraint(
            "to_status IN ('confirmed', 'rejected', 'expired', 'escalated')",
            name="ck_reviews_to_status",
        ),
        CheckConstraint(
            "(from_status = 'candidate' AND "
            "to_status IN ('confirmed', 'rejected', 'expired')) OR "
            "(from_status = 'confirmed' AND to_status = 'escalated')",
            name="ck_reviews_legal_transition",
        ),
        UniqueConstraint("event_id", "idempotency_key", name="uq_reviews_event_idempotency"),
    )

    review_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_id: Mapped[str] = mapped_column(
        ForeignKey("candidate_events.event_id", ondelete="RESTRICT"), nullable=False
    )
    reviewer_id: Mapped[str] = mapped_column(
        ForeignKey("users.user_id", ondelete="RESTRICT"), nullable=False
    )
    from_status: Mapped[str] = mapped_column(String(16), nullable=False)
    to_status: Mapped[str] = mapped_column(String(16), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuditEntryModel(Base):
    __tablename__ = "audit_entries"
    __table_args__ = (
        Index("ix_audit_entries_entity", "entity_type", "entity_id", "occurred_at"),
        Index("ix_audit_entries_site_occurred", "site_id", "occurred_at", "audit_id"),
    )

    audit_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    site_id: Mapped[str | None] = mapped_column(
        ForeignKey("sites.site_id", ondelete="RESTRICT"),
        nullable=True,
    )
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.user_id", ondelete="RESTRICT")
    )
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(128), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    idempotency_key: Mapped[str | None] = mapped_column(String(255), unique=True)


@event.listens_for(AuditEntryModel, "before_update")
@event.listens_for(AuditEntryModel, "before_delete")
def reject_audit_mutation(*_: object) -> None:
    raise ValueError("audit entries are append-only")


class AuditArchiveReceiptModel(Base):
    __tablename__ = "audit_archive_receipts"
    __table_args__ = (
        CheckConstraint("length(archive_sha256) = 64", name="ck_audit_archive_sha256"),
        CheckConstraint(
            "row_count > 0 AND row_count <= 10000",
            name="ck_audit_archive_row_count",
        ),
        CheckConstraint(
            "length(detached_signature) <= 16384",
            name="ck_audit_archive_signature_bound",
        ),
        CheckConstraint(
            "length(canonical_receipt) <= 16384",
            name="ck_audit_archive_receipt_bound",
        ),
        UniqueConstraint("archive_object_key", name="uq_audit_archive_object_key"),
    )

    receipt_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    site_id: Mapped[str] = mapped_column(
        ForeignKey("sites.site_id", ondelete="RESTRICT"), nullable=False
    )
    cutoff_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    archive_object_key: Mapped[str] = mapped_column(String(2048), nullable=False)
    archive_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    detached_signature: Mapped[str] = mapped_column(Text, nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    canonical_receipt: Mapped[str] = mapped_column(Text, nullable=False)
    row_count: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    pruned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditArchiveItemModel(Base):
    __tablename__ = "audit_archive_items"
    __table_args__ = (
        UniqueConstraint("audit_id", name="uq_audit_archive_item_audit"),
        Index("ix_audit_archive_items_receipt", "receipt_id", "audit_id"),
    )

    receipt_id: Mapped[str] = mapped_column(
        ForeignKey("audit_archive_receipts.receipt_id", ondelete="CASCADE"),
        primary_key=True,
    )
    audit_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_sha256: Mapped[str] = mapped_column(String(64), nullable=False)


@event.listens_for(AuditArchiveReceiptModel, "before_update")
@event.listens_for(AuditArchiveReceiptModel, "before_delete")
@event.listens_for(AuditArchiveItemModel, "before_update")
@event.listens_for(AuditArchiveItemModel, "before_delete")
def reject_audit_archive_receipt_mutation(*_: object) -> None:
    raise ValueError("audit archive receipts and items are append-only")


class AuditPruneAuthorizationModel(Base):
    __tablename__ = "audit_prune_authorizations"

    backend_pid: Mapped[int] = mapped_column(Integer, primary_key=True)
    transaction_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    audit_id: Mapped[str] = mapped_column(String(36), primary_key=True)


class AuditItemCompactionAuthorizationModel(Base):
    __tablename__ = "audit_item_compaction_authorizations"

    backend_pid: Mapped[int] = mapped_column(Integer, primary_key=True)
    transaction_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    receipt_id: Mapped[str] = mapped_column(String(36), primary_key=True)


event.listen(
    AuditEntryModel.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_audit_entries_no_update
        BEFORE UPDATE ON audit_entries
        BEGIN
            SELECT RAISE(ABORT, 'audit entries are append-only');
        END
        """
    ).execute_if(dialect="sqlite"),
)
event.listen(
    AuditEntryModel.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_audit_entries_no_delete
        BEFORE DELETE ON audit_entries
        BEGIN
            SELECT RAISE(ABORT, 'audit entries are append-only');
        END
        """
    ).execute_if(dialect="sqlite"),
)
event.listen(
    AuditEntryModel.__table__,
    "after_create",
    DDL(
        """
        CREATE OR REPLACE FUNCTION pilot_reject_audit_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'audit entries are append-only';
        END;
        $$;
        """
    ).execute_if(dialect="postgresql"),
)
event.listen(
    AuditEntryModel.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_audit_entries_append_only
        BEFORE UPDATE OR DELETE ON audit_entries
        FOR EACH ROW EXECUTE FUNCTION pilot_reject_audit_mutation()
        """
    ).execute_if(dialect="postgresql"),
)
event.listen(
    AuditEntryModel.__table__,
    "after_drop",
    DDL("DROP FUNCTION IF EXISTS pilot_reject_audit_mutation()").execute_if(dialect="postgresql"),
)


class NotificationOutboxModel(Base):
    __tablename__ = "notification_outbox"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'delivering', 'delivered', 'dead_letter')",
            name="ck_notification_outbox_status",
        ),
        Index(
            "ix_notification_outbox_claim",
            "status",
            "available_at",
            "lease_expires_at",
        ),
    )

    outbox_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_id: Mapped[str] = mapped_column(
        ForeignKey("candidate_events.event_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    lease_token: Mapped[str | None] = mapped_column(String(36))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


event.listen(
    NotificationOutboxModel.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_notification_outbox_confirmed_operator
        BEFORE INSERT ON notification_outbox
        FOR EACH ROW
        BEGIN
            SELECT CASE
                WHEN NOT EXISTS (
                    SELECT 1
                    FROM candidate_events
                    WHERE event_id = NEW.event_id
                      AND gate_mode = 'operator'
                      AND review_status = 'confirmed'
                )
                THEN RAISE(
                    ABORT,
                    'notification outbox requires a confirmed operator event'
                )
            END;
            SELECT CASE
                WHEN NOT EXISTS (
                    SELECT 1
                    FROM candidate_events AS event
                    JOIN reviews AS review
                      ON review.event_id = event.event_id
                     AND review.from_status = 'candidate'
                     AND review.to_status = 'confirmed'
                    WHERE event.event_id = NEW.event_id
                      AND event.transition_history = 'observation>candidate>confirmed'
                )
                THEN RAISE(
                    ABORT,
                    'notification outbox requires valid review provenance'
                )
            END;
        END
        """
    ).execute_if(dialect="sqlite"),
)
event.listen(
    NotificationOutboxModel.__table__,
    "after_create",
    DDL(
        """
        CREATE OR REPLACE FUNCTION pilot_validate_notification_outbox()
        RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
            event_gate_mode text;
            event_review_status text;
            event_transition_history text;
        BEGIN
            SELECT gate_mode, review_status, transition_history
            INTO event_gate_mode, event_review_status, event_transition_history
            FROM candidate_events
            WHERE event_id = NEW.event_id;
            IF event_gate_mode IS DISTINCT FROM 'operator'
               OR event_review_status IS DISTINCT FROM 'confirmed' THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'notification outbox requires a confirmed operator event';
            END IF;
            IF event_transition_history <> 'observation>candidate>confirmed'
               OR NOT EXISTS (
                   SELECT 1
                   FROM reviews
                   WHERE event_id = NEW.event_id
                     AND from_status = 'candidate'
                     AND to_status = 'confirmed'
               ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'notification outbox requires valid review provenance';
            END IF;
            RETURN NEW;
        END;
        $$;
        """
    ).execute_if(dialect="postgresql"),
)
event.listen(
    NotificationOutboxModel.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_notification_outbox_confirmed_operator
        BEFORE INSERT ON notification_outbox
        FOR EACH ROW EXECUTE FUNCTION pilot_validate_notification_outbox()
        """
    ).execute_if(dialect="postgresql"),
)
event.listen(
    NotificationOutboxModel.__table__,
    "after_drop",
    DDL("DROP FUNCTION IF EXISTS pilot_validate_notification_outbox()").execute_if(
        dialect="postgresql"
    ),
)


class DeliveryAttemptModel(Base):
    __tablename__ = "delivery_attempts"
    __table_args__ = (
        CheckConstraint("attempt_number >= 1", name="ck_delivery_attempts_number"),
        CheckConstraint(
            "status IN ('sending', 'delivered', 'failed')",
            name="ck_delivery_attempts_status",
        ),
        UniqueConstraint("outbox_id", "attempt_number", name="uq_delivery_attempt_number"),
    )

    delivery_attempt_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    outbox_id: Mapped[str] = mapped_column(
        ForeignKey("notification_outbox.outbox_id", ondelete="CASCADE"), nullable=False
    )
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    attempted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    response_reference: Mapped[str | None] = mapped_column(String(2048))
    error: Mapped[str | None] = mapped_column(Text)
