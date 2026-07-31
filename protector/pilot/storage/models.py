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
    ForeignKeyConstraint,
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
        UniqueConstraint("site_id", "camera_id", name="uq_cameras_site_camera"),
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
        Index(
            "uq_camera_health_latest_per_camera",
            "camera_id",
            unique=True,
        ).ddl_if(dialect="postgresql"),
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


class SiteConfigRevisionModel(Base):
    __tablename__ = "site_config_revisions"
    __table_args__ = (
        CheckConstraint("revision > 0", name="ck_site_config_revision_positive"),
        CheckConstraint("length(config_sha256) = 64", name="ck_site_config_sha256"),
        CheckConstraint("length(artifact_sha256) = 64", name="ck_site_config_artifact_sha256"),
        CheckConstraint("length(signature_sha256) = 64", name="ck_site_config_signature_sha256"),
        CheckConstraint(
            "length(signing_key_spki_sha256) = 64",
            name="ck_site_config_signing_key_sha256",
        ),
        UniqueConstraint("site_id", "revision", name="uq_site_config_revision"),
        UniqueConstraint("site_id", "config_sha256", name="uq_site_config_digest"),
        UniqueConstraint(
            "site_id",
            "config_revision_id",
            name="uq_site_config_site_revision_id",
        ),
    )

    config_revision_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    site_id: Mapped[str] = mapped_column(
        ForeignKey("sites.site_id", ondelete="RESTRICT"), nullable=False
    )
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    config_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    signature_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    signing_key_spki_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    reviewed_by: Mapped[str] = mapped_column(String(255), nullable=False)
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    review_reference: Mapped[str] = mapped_column(String(2048), nullable=False)
    canonical_config: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class CameraRulesetRevisionModel(Base):
    __tablename__ = "camera_ruleset_revisions"
    __table_args__ = (
        CheckConstraint("revision > 0", name="ck_camera_ruleset_revision_positive"),
        CheckConstraint("length(site_config_sha256) = 64", name="ck_ruleset_site_config_sha256"),
        CheckConstraint(
            "length(frozen_workload_sha256) = 64",
            name="ck_ruleset_frozen_workload_sha256",
        ),
        CheckConstraint(
            "length(engine_sha256) = 64",
            name="ck_ruleset_engine_sha256",
        ),
        CheckConstraint(
            "length(runtime_manifest_sha256) = 64",
            name="ck_ruleset_runtime_manifest_sha256",
        ),
        CheckConstraint("length(ruleset_sha256) = 64", name="ck_ruleset_sha256"),
        CheckConstraint("length(artifact_sha256) = 64", name="ck_ruleset_artifact_sha256"),
        CheckConstraint("length(signature_sha256) = 64", name="ck_ruleset_signature_sha256"),
        CheckConstraint(
            "length(signing_key_spki_sha256) = 64",
            name="ck_ruleset_signing_key_sha256",
        ),
        UniqueConstraint("site_id", "ruleset_id", "revision", name="uq_ruleset_revision"),
        UniqueConstraint("site_id", "ruleset_sha256", name="uq_ruleset_digest"),
        UniqueConstraint(
            "site_id",
            "ruleset_revision_id",
            name="uq_ruleset_site_revision_id",
        ),
        UniqueConstraint(
            "site_id",
            "config_revision_id",
            "ruleset_revision_id",
            name="uq_ruleset_site_config_revision",
        ),
        ForeignKeyConstraint(
            ["site_id", "config_revision_id"],
            [
                "site_config_revisions.site_id",
                "site_config_revisions.config_revision_id",
            ],
            ondelete="RESTRICT",
        ),
    )

    ruleset_revision_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    ruleset_id: Mapped[str] = mapped_column(String(128), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    site_id: Mapped[str] = mapped_column(
        ForeignKey("sites.site_id", ondelete="RESTRICT"), nullable=False
    )
    config_revision_id: Mapped[str] = mapped_column(String(128), nullable=False)
    site_config_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    frozen_workload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    engine_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    runtime_manifest_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    ruleset_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    signature_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    signing_key_spki_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    reviewed_by: Mapped[str] = mapped_column(String(255), nullable=False)
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    review_reference: Mapped[str] = mapped_column(String(2048), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class CameraRuleRevisionModel(Base):
    __tablename__ = "camera_rule_revisions"
    __table_args__ = (
        CheckConstraint("revision > 0", name="ck_camera_rule_revision_positive"),
        CheckConstraint(
            "gate_mode IN ('disabled', 'shadow', 'operator')",
            name="ck_camera_rule_gate_mode",
        ),
        CheckConstraint(
            "minimum_confidence >= 0 AND minimum_confidence <= 1",
            name="ck_camera_rule_confidence",
        ),
        CheckConstraint(
            "minimum_votes >= 1 AND minimum_votes <= 64",
            name="ck_camera_rule_votes",
        ),
        CheckConstraint(
            "sample_count >= minimum_votes AND sample_count <= 64",
            name="ck_camera_rule_samples",
        ),
        CheckConstraint(
            "window_seconds > 0 AND window_seconds <= 60",
            name="ck_camera_rule_window",
        ),
        CheckConstraint(
            "evidence_seconds >= 4 AND evidence_seconds <= 10",
            name="ck_camera_rule_evidence",
        ),
        CheckConstraint(
            "length(model_decision_sha256) = 64",
            name="ck_camera_rule_decision_sha256",
        ),
        CheckConstraint(
            "length(rule_revision_sha256) = 64",
            name="ck_camera_rule_revision_sha256",
        ),
        ForeignKeyConstraint(
            ["site_id", "ruleset_revision_id"],
            [
                "camera_ruleset_revisions.site_id",
                "camera_ruleset_revisions.ruleset_revision_id",
            ],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["site_id", "camera_id"],
            ["cameras.site_id", "cameras.camera_id"],
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "site_id",
            "rule_id",
            "revision",
            name="uq_camera_rule_identity_revision",
        ),
        UniqueConstraint(
            "site_id",
            "ruleset_revision_id",
            "rule_id",
            name="uq_camera_rule_site_ruleset_rule",
        ),
        UniqueConstraint(
            "ruleset_revision_id",
            "camera_id",
            "module",
            name="uq_ruleset_camera_module",
        ),
    )

    ruleset_revision_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    site_id: Mapped[str] = mapped_column(
        ForeignKey("sites.site_id", ondelete="RESTRICT"), nullable=False
    )
    camera_id: Mapped[str] = mapped_column(String(128), nullable=False)
    module: Mapped[str] = mapped_column(String(128), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    model_artifact_id: Mapped[str] = mapped_column(
        ForeignKey("model_artifacts.artifact_id", ondelete="RESTRICT"), nullable=False
    )
    model_decision_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    gate_mode: Mapped[str] = mapped_column(String(16), nullable=False)
    minimum_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    minimum_votes: Mapped[int] = mapped_column(Integer, nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False)
    window_seconds: Mapped[float] = mapped_column(Float, nullable=False)
    evidence_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    rule_spec: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    rule_revision_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class ConfigurationActivationModel(Base):
    """Append-only activation receipts; the active table is only a pointer."""

    __tablename__ = "configuration_activations"
    __table_args__ = (
        CheckConstraint("activation_generation > 0", name="ck_activation_generation"),
        CheckConstraint(
            "expected_activation_generation >= 0",
            name="ck_activation_expected_generation",
        ),
        CheckConstraint(
            "runtime_writer_generation > 0",
            name="ck_activation_writer_generation",
        ),
        CheckConstraint(
            "length(site_config_sha256) = 64",
            name="ck_activation_site_config_sha256",
        ),
        CheckConstraint(
            "length(ruleset_sha256) = 64",
            name="ck_activation_ruleset_sha256",
        ),
        ForeignKeyConstraint(
            ["site_id", "config_revision_id"],
            [
                "site_config_revisions.site_id",
                "site_config_revisions.config_revision_id",
            ],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["site_id", "config_revision_id", "ruleset_revision_id"],
            [
                "camera_ruleset_revisions.site_id",
                "camera_ruleset_revisions.config_revision_id",
                "camera_ruleset_revisions.ruleset_revision_id",
            ],
            ondelete="RESTRICT",
        ),
        UniqueConstraint("idempotency_key", name="uq_activation_idempotency"),
        UniqueConstraint(
            "site_id",
            "activation_generation",
            "config_revision_id",
            "ruleset_revision_id",
            name="uq_activation_exact_pointer",
        ),
    )

    site_id: Mapped[str] = mapped_column(
        ForeignKey("sites.site_id", ondelete="RESTRICT"), primary_key=True
    )
    expected_activation_generation: Mapped[int] = mapped_column(
        BigInteger, nullable=False
    )
    activation_generation: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    runtime_writer_generation: Mapped[int] = mapped_column(BigInteger, nullable=False)
    config_revision_id: Mapped[str] = mapped_column(String(128), nullable=False)
    site_config_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    ruleset_revision_id: Mapped[str] = mapped_column(String(128), nullable=False)
    ruleset_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    activated_by: Mapped[str] = mapped_column(String(128), nullable=False)
    activated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    force_new_generation: Mapped[bool] = mapped_column(Boolean, nullable=False)


class ActivePilotConfigurationModel(Base):
    __tablename__ = "active_pilot_configurations"
    __table_args__ = (
        CheckConstraint(
            "activation_generation > 0",
            name="ck_active_configuration_generation",
        ),
        UniqueConstraint(
            "site_id",
            "activation_generation",
            name="uq_active_site_generation",
        ),
        ForeignKeyConstraint(
            ["site_id", "config_revision_id"],
            [
                "site_config_revisions.site_id",
                "site_config_revisions.config_revision_id",
            ],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["site_id", "config_revision_id", "ruleset_revision_id"],
            [
                "camera_ruleset_revisions.site_id",
                "camera_ruleset_revisions.config_revision_id",
                "camera_ruleset_revisions.ruleset_revision_id",
            ],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            [
                "site_id",
                "activation_generation",
                "config_revision_id",
                "ruleset_revision_id",
            ],
            [
                "configuration_activations.site_id",
                "configuration_activations.activation_generation",
                "configuration_activations.config_revision_id",
                "configuration_activations.ruleset_revision_id",
            ],
            ondelete="RESTRICT",
        ),
    )

    site_id: Mapped[str] = mapped_column(
        ForeignKey("sites.site_id", ondelete="RESTRICT"), primary_key=True
    )
    activation_generation: Mapped[int] = mapped_column(BigInteger, nullable=False)
    config_revision_id: Mapped[str] = mapped_column(String(128), nullable=False)
    ruleset_revision_id: Mapped[str] = mapped_column(String(128), nullable=False)
    activated_by: Mapped[str] = mapped_column(String(128), nullable=False)
    activated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RuntimeWriterAuthorityModel(Base):
    __tablename__ = "runtime_writer_authorities"
    __table_args__ = (
        CheckConstraint("writer_generation > 0", name="ck_runtime_writer_generation"),
        CheckConstraint(
            "configuration_activation_generation > 0",
            name="ck_runtime_writer_activation_generation",
        ),
        ForeignKeyConstraint(
            ["site_id", "configuration_activation_generation"],
            [
                "configuration_activations.site_id",
                "configuration_activations.activation_generation",
            ],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["site_id", "configuration_activation_generation"],
            [
                "active_pilot_configurations.site_id",
                "active_pilot_configurations.activation_generation",
            ],
            deferrable=True,
            initially="DEFERRED",
            ondelete="RESTRICT",
        ),
    )

    site_id: Mapped[str] = mapped_column(
        ForeignKey("sites.site_id", ondelete="RESTRICT"), primary_key=True
    )
    runtime_session_id: Mapped[str | None] = mapped_column(String(128))
    writer_generation: Mapped[int] = mapped_column(BigInteger, nullable=False)
    configuration_activation_generation: Mapped[int] = mapped_column(
        BigInteger, nullable=False
    )
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RuntimeWriterSessionModel(Base):
    """Append-only writer issuance history; session IDs can never be resurrected."""

    __tablename__ = "runtime_writer_sessions"
    __table_args__ = (
        CheckConstraint("writer_generation > 0", name="ck_writer_session_generation"),
        CheckConstraint(
            "configuration_activation_generation > 0",
            name="ck_writer_session_activation_generation",
        ),
        CheckConstraint("length(receipt_sha256) = 64", name="ck_writer_receipt_sha256"),
        UniqueConstraint(
            "site_id",
            "writer_generation",
            name="uq_writer_session_site_generation",
        ),
        UniqueConstraint(
            "site_id",
            "runtime_session_id",
            "writer_generation",
            "configuration_activation_generation",
            name="uq_writer_session_exact_authority",
        ),
        ForeignKeyConstraint(
            ["site_id", "configuration_activation_generation"],
            [
                "configuration_activations.site_id",
                "configuration_activations.activation_generation",
            ],
            ondelete="RESTRICT",
        ),
    )

    runtime_session_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    site_id: Mapped[str] = mapped_column(
        ForeignKey("sites.site_id", ondelete="RESTRICT"), nullable=False
    )
    writer_generation: Mapped[int] = mapped_column(BigInteger, nullable=False)
    configuration_activation_generation: Mapped[int] = mapped_column(
        BigInteger, nullable=False
    )
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    receipt_sha256: Mapped[str] = mapped_column(String(64), nullable=False)


class CameraEpochAuthorityModel(Base):
    """Current per-camera source epoch bound to one exact writer session."""

    __tablename__ = "camera_epoch_authorities"
    __table_args__ = (
        ForeignKeyConstraint(
            ["site_id", "camera_id"],
            ["cameras.site_id", "cameras.camera_id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            [
                "site_id",
                "runtime_session_id",
                "writer_generation",
                "configuration_activation_generation",
            ],
            [
                "runtime_writer_sessions.site_id",
                "runtime_writer_sessions.runtime_session_id",
                "runtime_writer_sessions.writer_generation",
                "runtime_writer_sessions.configuration_activation_generation",
            ],
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "site_id",
            "camera_id",
            "source_epoch",
            name="uq_camera_epoch_active_identity",
        ),
    )

    camera_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    site_id: Mapped[str] = mapped_column(String(128), nullable=False)
    source_epoch: Mapped[str] = mapped_column(String(36), nullable=False)
    runtime_session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    writer_generation: Mapped[int] = mapped_column(BigInteger, nullable=False)
    configuration_activation_generation: Mapped[int] = mapped_column(
        BigInteger, nullable=False
    )
    activated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CameraEpochHistoryModel(Base):
    """Append-only epoch history prevents retired source epochs from returning."""

    __tablename__ = "camera_epoch_history"
    __table_args__ = (
        ForeignKeyConstraint(
            ["site_id", "camera_id"],
            ["cameras.site_id", "cameras.camera_id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            [
                "site_id",
                "runtime_session_id",
                "writer_generation",
                "configuration_activation_generation",
            ],
            [
                "runtime_writer_sessions.site_id",
                "runtime_writer_sessions.runtime_session_id",
                "runtime_writer_sessions.writer_generation",
                "runtime_writer_sessions.configuration_activation_generation",
            ],
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "site_id",
            "camera_id",
            "source_epoch",
            name="uq_camera_epoch_history_site_identity",
        ),
    )

    camera_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    source_epoch: Mapped[str] = mapped_column(String(36), primary_key=True)
    previous_source_epoch: Mapped[str | None] = mapped_column(String(36))
    site_id: Mapped[str] = mapped_column(String(128), nullable=False)
    runtime_session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    writer_generation: Mapped[int] = mapped_column(BigInteger, nullable=False)
    configuration_activation_generation: Mapped[int] = mapped_column(
        BigInteger, nullable=False
    )
    activated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class LegacyCandidateImportModel(Base):
    """One explicit marker for a candidate imported at the 0006 cutover."""

    __tablename__ = "legacy_candidate_imports"
    __table_args__ = (
        CheckConstraint(
            "migration_revision = '0006_event_provenance'",
            name="ck_legacy_candidate_migration",
        ),
        CheckConstraint(
            "schema_version = 'legacy-candidate-import.v1'",
            name="ck_legacy_candidate_schema",
        ),
        CheckConstraint(
            "legacy_cutoff_at <= imported_at",
            name="ck_legacy_candidate_cutoff",
        ),
    )

    event_id: Mapped[str] = mapped_column(
        ForeignKey("candidate_events.event_id", ondelete="RESTRICT"), primary_key=True
    )
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    legacy_cutoff_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    migration_revision: Mapped[str] = mapped_column(String(64), nullable=False)


class CandidateEventProvenanceModel(Base):
    __tablename__ = "candidate_event_provenance"
    __table_args__ = (
        CheckConstraint(
            "schema_version = 'candidate-event-provenance.v1'",
            name="ck_candidate_provenance_schema",
        ),
        CheckConstraint(
            "runtime_writer_generation > 0",
            name="ck_candidate_provenance_writer_generation",
        ),
        CheckConstraint(
            "configuration_activation_generation > 0",
            name="ck_candidate_provenance_activation_generation",
        ),
        CheckConstraint("rule_revision > 0", name="ck_candidate_provenance_rule_revision"),
        CheckConstraint(
            "gate_mode IN ('shadow', 'operator')",
            name="ck_candidate_provenance_gate_mode",
        ),
        CheckConstraint(
            "length(rule_revision_sha256) = 64",
            name="ck_candidate_provenance_rule_sha256",
        ),
        CheckConstraint(
            "length(ruleset_sha256) = 64",
            name="ck_candidate_provenance_ruleset_sha256",
        ),
        CheckConstraint(
            "length(site_config_sha256) = 64",
            name="ck_candidate_provenance_config_sha256",
        ),
        CheckConstraint(
            "length(model_gate_decision_sha256) = 64",
            name="ck_candidate_provenance_decision_sha256",
        ),
        CheckConstraint(
            "length(body_sha256) = 64",
            name="ck_candidate_provenance_body_sha256",
        ),
        ForeignKeyConstraint(
            ["site_id", "ruleset_revision_id", "rule_id"],
            [
                "camera_rule_revisions.site_id",
                "camera_rule_revisions.ruleset_revision_id",
                "camera_rule_revisions.rule_id",
            ],
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "event_id",
            "site_id",
            "runtime_session_id",
            "runtime_writer_generation",
            "configuration_activation_generation",
            "source_epoch",
            "rule_revision_sha256",
            "site_config_sha256",
            "body_sha256",
            name="uq_candidate_provenance_preview_authority",
        ),
        Index(
            "ix_candidate_provenance_runtime",
            "site_id",
            "runtime_writer_generation",
            "runtime_session_id",
        ),
    )

    event_id: Mapped[str] = mapped_column(
        ForeignKey("candidate_events.event_id", ondelete="CASCADE"), primary_key=True
    )
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    site_id: Mapped[str] = mapped_column(
        ForeignKey("sites.site_id", ondelete="RESTRICT"), nullable=False
    )
    runtime_session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    runtime_writer_generation: Mapped[int] = mapped_column(BigInteger, nullable=False)
    configuration_activation_generation: Mapped[int] = mapped_column(
        BigInteger, nullable=False
    )
    source_epoch: Mapped[str] = mapped_column(String(36), nullable=False)
    ruleset_revision_id: Mapped[str] = mapped_column(String(128), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    rule_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    rule_revision_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    ruleset_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    site_config_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    model_gate_decision_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    gate_mode: Mapped[str] = mapped_column(String(16), nullable=False)
    body_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


@event.listens_for(SiteConfigRevisionModel, "before_update")
@event.listens_for(SiteConfigRevisionModel, "before_delete")
@event.listens_for(CameraRulesetRevisionModel, "before_update")
@event.listens_for(CameraRulesetRevisionModel, "before_delete")
@event.listens_for(CameraRuleRevisionModel, "before_update")
@event.listens_for(CameraRuleRevisionModel, "before_delete")
@event.listens_for(ConfigurationActivationModel, "before_update")
@event.listens_for(ConfigurationActivationModel, "before_delete")
@event.listens_for(RuntimeWriterSessionModel, "before_update")
@event.listens_for(RuntimeWriterSessionModel, "before_delete")
@event.listens_for(CameraEpochHistoryModel, "before_update")
@event.listens_for(CameraEpochHistoryModel, "before_delete")
@event.listens_for(LegacyCandidateImportModel, "before_update")
@event.listens_for(LegacyCandidateImportModel, "before_delete")
@event.listens_for(CandidateEventProvenanceModel, "before_update")
@event.listens_for(CandidateEventProvenanceModel, "before_delete")
def reject_reviewed_revision_mutation(*_: object) -> None:
    raise ValueError("reviewed revisions and candidate provenance are immutable")


event.listen(
    SiteConfigRevisionModel.__table__,
    "after_create",
    DDL(
        """
        CREATE OR REPLACE FUNCTION pilot_reject_reviewed_revision_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'reviewed revisions and candidate provenance are immutable';
        END;
        $$
        """
    ).execute_if(dialect="postgresql"),
)
for immutable_table in (
    SiteConfigRevisionModel.__table__,
    CameraRulesetRevisionModel.__table__,
    CameraRuleRevisionModel.__table__,
    ConfigurationActivationModel.__table__,
    RuntimeWriterSessionModel.__table__,
    CameraEpochHistoryModel.__table__,
    LegacyCandidateImportModel.__table__,
    CandidateEventProvenanceModel.__table__,
):
    for immutable_operation in ("UPDATE", "DELETE"):
        event.listen(
            immutable_table,
            "after_create",
            DDL(
                f"""
                CREATE TRIGGER trg_{immutable_table.name}_{immutable_operation.lower()}_immutable
                BEFORE {immutable_operation} ON {immutable_table.name}
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'reviewed revisions and candidate provenance are immutable'
                    );
                END
                """
            ).execute_if(dialect="sqlite"),
        )
    event.listen(
        immutable_table,
        "after_create",
        DDL(
            f"""
            CREATE TRIGGER trg_{immutable_table.name}_immutable
            BEFORE UPDATE OR DELETE ON {immutable_table.name}
            FOR EACH ROW
            EXECUTE FUNCTION pilot_reject_reviewed_revision_mutation()
            """
        ).execute_if(dialect="postgresql"),
    )

event.listen(
    SiteConfigRevisionModel.__table__,
    "after_drop",
    DDL(
        "DROP FUNCTION IF EXISTS pilot_reject_reviewed_revision_mutation()"
    ).execute_if(dialect="postgresql"),
)

event.listen(
    CandidateEventProvenanceModel.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_legacy_candidate_import_fence
        BEFORE INSERT ON legacy_candidate_imports
        FOR EACH ROW
        BEGIN
            SELECT CASE WHEN EXISTS (
                SELECT 1 FROM candidate_event_provenance
                 WHERE event_id = NEW.event_id
            ) THEN RAISE(ABORT, 'provenanced event cannot become legacy') END;
            SELECT CASE WHEN NOT EXISTS (
                SELECT 1 FROM candidate_events
                 WHERE event_id = NEW.event_id
                   AND opened_at <= NEW.legacy_cutoff_at
            ) THEN RAISE(ABORT, 'legacy marker does not match pre-cutoff event') END;
        END
        """
    ).execute_if(dialect="sqlite"),
)


event.listen(
    CandidateEventProvenanceModel.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_candidate_provenance_fence
        BEFORE INSERT ON candidate_event_provenance
        FOR EACH ROW
        BEGIN
            SELECT CASE WHEN EXISTS (
                SELECT 1 FROM legacy_candidate_imports
                 WHERE event_id = NEW.event_id
            ) THEN RAISE(ABORT, 'legacy event cannot gain runtime provenance') END;
            SELECT CASE WHEN NOT EXISTS (
                SELECT 1
                  FROM active_pilot_configurations AS active
                  JOIN site_config_revisions AS config
                    ON config.config_revision_id = active.config_revision_id
                  JOIN camera_ruleset_revisions AS ruleset
                    ON ruleset.ruleset_revision_id = active.ruleset_revision_id
                  JOIN runtime_writer_authorities AS writer
                    ON writer.site_id = active.site_id
                  JOIN candidate_events AS candidate
                    ON candidate.event_id = NEW.event_id
                  JOIN camera_epoch_authorities AS epoch
                    ON epoch.camera_id = candidate.camera_id
                 WHERE active.site_id = NEW.site_id
                   AND active.activation_generation =
                       NEW.configuration_activation_generation
                   AND config.config_sha256 = NEW.site_config_sha256
                   AND ruleset.ruleset_revision_id = NEW.ruleset_revision_id
                   AND ruleset.ruleset_sha256 = NEW.ruleset_sha256
                   AND writer.runtime_session_id = NEW.runtime_session_id
                   AND writer.writer_generation = NEW.runtime_writer_generation
                   AND writer.configuration_activation_generation =
                       NEW.configuration_activation_generation
                   AND epoch.site_id = NEW.site_id
                   AND epoch.source_epoch = NEW.source_epoch
                   AND epoch.runtime_session_id = NEW.runtime_session_id
                   AND epoch.writer_generation = NEW.runtime_writer_generation
                   AND epoch.configuration_activation_generation =
                       NEW.configuration_activation_generation
            ) THEN RAISE(ABORT, 'retired runtime writer cannot persist candidate') END;
            SELECT CASE WHEN NOT EXISTS (
                SELECT 1
                  FROM camera_rule_revisions AS rule
                  JOIN candidate_events AS candidate
                    ON candidate.event_id = NEW.event_id
                  JOIN cameras AS camera
                    ON camera.camera_id = candidate.camera_id
                 WHERE rule.ruleset_revision_id = NEW.ruleset_revision_id
                   AND rule.rule_id = NEW.rule_id
                   AND rule.revision = NEW.rule_revision
                   AND rule.rule_revision_sha256 = NEW.rule_revision_sha256
                   AND rule.model_decision_sha256 =
                       NEW.model_gate_decision_sha256
                   AND rule.gate_mode = NEW.gate_mode
                   AND rule.enabled = 1
                   AND rule.camera_id = candidate.camera_id
                   AND rule.module = candidate.module
                   AND rule.model_artifact_id = candidate.model_artifact_id
                   AND candidate.gate_mode = NEW.gate_mode
                   AND candidate.evidence_status = 'pending'
                   AND candidate.review_status = 'candidate'
                   AND candidate.transition_history = 'observation>candidate'
                   AND camera.site_id = NEW.site_id
            ) THEN RAISE(ABORT, 'candidate provenance does not match active camera rule') END;
        END
        """
    ).execute_if(dialect="sqlite"),
)


event.listen(
    CandidateEventProvenanceModel.__table__,
    "after_create",
    DDL(
        """
        CREATE OR REPLACE FUNCTION pilot_validate_candidate_provenance()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM public.legacy_candidate_imports
                 WHERE event_id = NEW.event_id
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'legacy event cannot gain runtime provenance';
            END IF;
            IF NOT EXISTS (
                SELECT 1
                  FROM public.active_pilot_configurations AS active
                  JOIN public.site_config_revisions AS config
                    ON config.config_revision_id = active.config_revision_id
                  JOIN public.camera_ruleset_revisions AS ruleset
                    ON ruleset.ruleset_revision_id = active.ruleset_revision_id
                  JOIN public.runtime_writer_authorities AS writer
                    ON writer.site_id = active.site_id
                  JOIN public.candidate_events AS candidate
                    ON candidate.event_id = NEW.event_id
                  JOIN public.camera_epoch_authorities AS epoch
                    ON epoch.camera_id = candidate.camera_id
                 WHERE active.site_id = NEW.site_id
                   AND active.activation_generation =
                       NEW.configuration_activation_generation
                   AND config.config_sha256 = NEW.site_config_sha256
                   AND ruleset.ruleset_revision_id = NEW.ruleset_revision_id
                   AND ruleset.ruleset_sha256 = NEW.ruleset_sha256
                   AND writer.runtime_session_id = NEW.runtime_session_id
                   AND writer.writer_generation = NEW.runtime_writer_generation
                   AND writer.configuration_activation_generation =
                       NEW.configuration_activation_generation
                   AND epoch.site_id = NEW.site_id
                   AND epoch.source_epoch = NEW.source_epoch
                   AND epoch.runtime_session_id = NEW.runtime_session_id
                   AND epoch.writer_generation = NEW.runtime_writer_generation
                   AND epoch.configuration_activation_generation =
                       NEW.configuration_activation_generation
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'retired runtime writer cannot persist candidate';
            END IF;
            IF NOT EXISTS (
                SELECT 1
                  FROM public.camera_rule_revisions AS rule
                  JOIN public.candidate_events AS candidate
                    ON candidate.event_id = NEW.event_id
                  JOIN public.cameras AS camera
                    ON camera.camera_id = candidate.camera_id
                 WHERE rule.ruleset_revision_id = NEW.ruleset_revision_id
                   AND rule.rule_id = NEW.rule_id
                   AND rule.revision = NEW.rule_revision
                   AND rule.rule_revision_sha256 = NEW.rule_revision_sha256
                   AND rule.model_decision_sha256 =
                       NEW.model_gate_decision_sha256
                   AND rule.gate_mode = NEW.gate_mode
                   AND rule.enabled
                   AND rule.camera_id = candidate.camera_id
                   AND rule.module = candidate.module
                   AND rule.model_artifact_id = candidate.model_artifact_id
                   AND candidate.gate_mode = NEW.gate_mode
                   AND candidate.evidence_status = 'pending'
                   AND candidate.review_status = 'candidate'
                   AND candidate.transition_history = 'observation>candidate'
                   AND camera.site_id = NEW.site_id
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'candidate provenance does not match active camera rule';
            END IF;
            RETURN NEW;
        END;
        $$;
        """
    ).execute_if(dialect="postgresql"),
)
event.listen(
    CandidateEventProvenanceModel.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_candidate_provenance_fence
        BEFORE INSERT ON candidate_event_provenance
        FOR EACH ROW EXECUTE FUNCTION pilot_validate_candidate_provenance()
        """
    ).execute_if(dialect="postgresql"),
)
event.listen(
    CandidateEventProvenanceModel.__table__,
    "after_drop",
    DDL(
        "DROP FUNCTION IF EXISTS pilot_validate_candidate_provenance()"
    ).execute_if(dialect="postgresql"),
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
        CheckConstraint("auth_generation > 0", name="ck_users_auth_generation"),
        CheckConstraint(
            PORTABLE_TOTP_ENVELOPE_CHECK,
            name="ck_users_totp_encrypted_envelope",
        ),
    )

    user_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    username: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    normalized_username: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(1024), nullable=False)
    totp_secret_encrypted: Mapped[str | None] = mapped_column(Text)
    totp_last_accepted_counter: Mapped[int | None] = mapped_column(BigInteger)
    auth_generation: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=1, server_default="1"
    )
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


class PreviewPublicationModel(Base):
    """One terminal, immutable-material preview publication per candidate."""

    __tablename__ = "preview_publications"
    __table_args__ = (
        CheckConstraint(
            "intent_schema_version = 'preview-publication-intent.v1'",
            name="ck_preview_intent_schema",
        ),
        CheckConstraint(
            "publication_state IN ('reserved', 'ready', 'retiring', 'retired')",
            name="ck_preview_publication_state",
        ),
        CheckConstraint(
            "length(sha256) = 64",
            name="ck_preview_publication_sha256",
        ),
        CheckConstraint(
            "length(configuration_sha256) = 64",
            name="ck_preview_configuration_sha256",
        ),
        CheckConstraint(
            "runtime_writer_generation > 0",
            name="ck_preview_writer_generation",
        ),
        CheckConstraint(
            "configuration_activation_generation > 0",
            name="ck_preview_activation_generation",
        ),
        CheckConstraint(
            "length(rule_revision_sha256) = 64",
            name="ck_preview_rule_sha256",
        ),
        CheckConstraint(
            "length(candidate_body_sha256) = 64",
            name="ck_preview_candidate_body_sha256",
        ),
        CheckConstraint(
            "intent_expires_at > intent_created_at",
            name="ck_preview_intent_time_range",
        ),
        CheckConstraint(
            "receipt_schema_version IS NULL OR "
            "receipt_schema_version = 'preview-object-receipt.v1'",
            name="ck_preview_receipt_schema",
        ),
        CheckConstraint(
            "size_bytes IS NULL OR "
            "(size_bytes > 0 AND size_bytes <= 16777216)",
            name="ck_preview_size_bound",
        ),
        CheckConstraint(
            "media_type IS NULL OR media_type = 'video/mp4'",
            name="ck_preview_media_type",
        ),
        CheckConstraint(
            "server_side_encryption IS NULL OR "
            "server_side_encryption IN ('AES256', 'aws:kms')",
            name="ck_preview_encryption",
        ),
        CheckConstraint(
            "(server_side_encryption IS NULL AND kms_key_id IS NULL) OR "
            "(server_side_encryption = 'AES256' AND kms_key_id IS NULL) OR "
            "(server_side_encryption = 'aws:kms' AND kms_key_id IS NOT NULL)",
            name="ck_preview_kms_identity",
        ),
        CheckConstraint(
            "receipt_sha256 IS NULL OR length(receipt_sha256) = 64",
            name="ck_preview_receipt_sha256",
        ),
        ForeignKeyConstraint(
            [
                "event_id",
                "site_id",
                "runtime_session_id",
                "runtime_writer_generation",
                "configuration_activation_generation",
                "source_epoch",
                "rule_revision_sha256",
                "configuration_sha256",
                "candidate_body_sha256",
            ],
            [
                "candidate_event_provenance.event_id",
                "candidate_event_provenance.site_id",
                "candidate_event_provenance.runtime_session_id",
                "candidate_event_provenance.runtime_writer_generation",
                "candidate_event_provenance.configuration_activation_generation",
                "candidate_event_provenance.source_epoch",
                "candidate_event_provenance.rule_revision_sha256",
                "candidate_event_provenance.site_config_sha256",
                "candidate_event_provenance.body_sha256",
            ],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            [
                "site_id",
                "runtime_session_id",
                "runtime_writer_generation",
                "configuration_activation_generation",
            ],
            [
                "runtime_writer_sessions.site_id",
                "runtime_writer_sessions.runtime_session_id",
                "runtime_writer_sessions.writer_generation",
                "runtime_writer_sessions.configuration_activation_generation",
            ],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["site_id", "camera_id", "source_epoch"],
            [
                "camera_epoch_history.site_id",
                "camera_epoch_history.camera_id",
                "camera_epoch_history.source_epoch",
            ],
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "site_id",
            "event_id",
            name="uq_preview_site_event",
        ),
        UniqueConstraint(
            "evidence_id",
            name="uq_preview_evidence_identity",
        ),
        UniqueConstraint(
            "object_key",
            name="uq_preview_object_identity",
        ),
        UniqueConstraint(
            "receipt_sha256",
            name="uq_preview_receipt_identity",
        ),
        UniqueConstraint(
            "site_id",
            "event_id",
            "receipt_sha256",
            name="uq_preview_access_authority",
        ),
        Index(
            "ix_preview_retention_claim",
            "site_id",
            "publication_state",
            "receipt_created_at",
            "event_id",
        ),
        Index(
            "ix_preview_intent_expiry",
            "site_id",
            "publication_state",
            "intent_expires_at",
            "event_id",
        ),
    )

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    site_id: Mapped[str] = mapped_column(String(128), nullable=False)
    camera_id: Mapped[str] = mapped_column(String(128), nullable=False)
    evidence_id: Mapped[str] = mapped_column(String(36), nullable=False)
    intent_schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    publication_state: Mapped[str] = mapped_column(String(16), nullable=False)
    object_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    configuration_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    runtime_session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    runtime_writer_generation: Mapped[int] = mapped_column(BigInteger, nullable=False)
    configuration_activation_generation: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )
    source_epoch: Mapped[str] = mapped_column(String(36), nullable=False)
    rule_revision_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    candidate_body_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    intent_created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    intent_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    receipt_schema_version: Mapped[str | None] = mapped_column(String(64))
    checksum_sha256: Mapped[str | None] = mapped_column(String(44))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    media_type: Mapped[str | None] = mapped_column(String(32))
    etag: Mapped[str | None] = mapped_column(String(512))
    version_id: Mapped[str | None] = mapped_column(String(1024))
    server_side_encryption: Mapped[str | None] = mapped_column(String(16))
    kms_key_id: Mapped[str | None] = mapped_column(String(2048))
    receipt_sha256: Mapped[str | None] = mapped_column(String(64))
    receipt_created_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    retiring_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PreviewAccessReceiptModel(Base):
    """Redacted, append-only proof that an exact ready preview was accessed."""

    __tablename__ = "preview_access_receipts"
    __table_args__ = (
        CheckConstraint(
            "schema_version = 'preview-access-receipt.v1'",
            name="ck_preview_access_schema",
        ),
        CheckConstraint(
            "length(receipt_sha256) = 64",
            name="ck_preview_access_receipt_sha256",
        ),
        ForeignKeyConstraint(
            ["site_id", "event_id", "receipt_sha256"],
            [
                "preview_publications.site_id",
                "preview_publications.event_id",
                "preview_publications.receipt_sha256",
            ],
            ondelete="RESTRICT",
        ),
        Index(
            "ix_preview_access_site_occurred",
            "site_id",
            "occurred_at",
            "access_id",
        ),
    )

    access_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    site_id: Mapped[str] = mapped_column(
        ForeignKey("sites.site_id", ondelete="RESTRICT"),
        nullable=False,
    )
    event_id: Mapped[str] = mapped_column(String(36), nullable=False)
    actor_id: Mapped[str] = mapped_column(
        ForeignKey("users.user_id", ondelete="RESTRICT"),
        nullable=False,
    )
    receipt_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


event.listen(
    PreviewPublicationModel.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_preview_publication_insert_guard
        BEFORE INSERT ON preview_publications
        FOR EACH ROW
        WHEN
          NEW.publication_state <> 'reserved'
          OR NEW.receipt_schema_version IS NOT NULL
          OR NEW.checksum_sha256 IS NOT NULL
          OR NEW.size_bytes IS NOT NULL
          OR NEW.media_type IS NOT NULL
          OR NEW.etag IS NOT NULL
          OR NEW.version_id IS NOT NULL
          OR NEW.server_side_encryption IS NOT NULL
          OR NEW.kms_key_id IS NOT NULL
          OR NEW.receipt_sha256 IS NOT NULL
          OR NEW.receipt_created_at IS NOT NULL
          OR NEW.retiring_at IS NOT NULL
          OR NEW.retired_at IS NOT NULL
          OR NEW.intent_expires_at > datetime(NEW.intent_created_at, '+1 hour')
          OR NEW.object_key <> (
            NEW.site_id || '/' || NEW.event_id || '/' || NEW.evidence_id ||
            '/' || NEW.sha256 || '.mp4'
          )
          OR NOT EXISTS (
            SELECT 1
              FROM candidate_events AS candidate
              JOIN cameras AS camera
                ON camera.camera_id = candidate.camera_id
              JOIN candidate_event_provenance AS provenance
                ON provenance.event_id = candidate.event_id
              JOIN active_pilot_configurations AS active
                ON active.site_id = provenance.site_id
              JOIN site_config_revisions AS config
                ON config.site_id = active.site_id
               AND config.config_revision_id = active.config_revision_id
              JOIN runtime_writer_authorities AS writer
                ON writer.site_id = active.site_id
              JOIN camera_epoch_authorities AS epoch
                ON epoch.camera_id = candidate.camera_id
             WHERE candidate.event_id = NEW.event_id
               AND candidate.camera_id = NEW.camera_id
               AND candidate.evidence_status = 'pending'
               AND candidate.review_status = 'candidate'
               AND candidate.transition_history = 'observation>candidate'
               AND camera.site_id = NEW.site_id
               AND provenance.site_id = NEW.site_id
               AND provenance.runtime_session_id = NEW.runtime_session_id
               AND provenance.runtime_writer_generation =
                   NEW.runtime_writer_generation
               AND provenance.configuration_activation_generation =
                   NEW.configuration_activation_generation
               AND provenance.source_epoch = NEW.source_epoch
               AND provenance.rule_revision_sha256 =
                   NEW.rule_revision_sha256
               AND provenance.site_config_sha256 =
                   NEW.configuration_sha256
               AND provenance.body_sha256 = NEW.candidate_body_sha256
               AND active.activation_generation =
                   NEW.configuration_activation_generation
               AND active.ruleset_revision_id =
                   provenance.ruleset_revision_id
               AND config.config_sha256 = NEW.configuration_sha256
               AND writer.runtime_session_id = NEW.runtime_session_id
               AND writer.writer_generation = NEW.runtime_writer_generation
               AND writer.configuration_activation_generation =
                   NEW.configuration_activation_generation
               AND epoch.site_id = NEW.site_id
               AND epoch.source_epoch = NEW.source_epoch
               AND epoch.runtime_session_id = NEW.runtime_session_id
               AND epoch.writer_generation = NEW.runtime_writer_generation
               AND epoch.configuration_activation_generation =
                   NEW.configuration_activation_generation
          )
        BEGIN
          SELECT RAISE(
            ABORT,
            'preview reservation lacks exact current candidate authority'
          );
        END
        """
    ).execute_if(dialect="sqlite"),
)
event.listen(
    PreviewPublicationModel.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_preview_publication_update_guard
        BEFORE UPDATE ON preview_publications
        FOR EACH ROW
        WHEN
          OLD.event_id IS NOT NEW.event_id
          OR OLD.site_id IS NOT NEW.site_id
          OR OLD.camera_id IS NOT NEW.camera_id
          OR OLD.evidence_id IS NOT NEW.evidence_id
          OR OLD.intent_schema_version IS NOT NEW.intent_schema_version
          OR OLD.object_key IS NOT NEW.object_key
          OR OLD.sha256 IS NOT NEW.sha256
          OR OLD.configuration_sha256 IS NOT NEW.configuration_sha256
          OR OLD.runtime_session_id IS NOT NEW.runtime_session_id
          OR OLD.runtime_writer_generation IS NOT NEW.runtime_writer_generation
          OR OLD.configuration_activation_generation
             IS NOT NEW.configuration_activation_generation
          OR OLD.source_epoch IS NOT NEW.source_epoch
          OR OLD.rule_revision_sha256 IS NOT NEW.rule_revision_sha256
          OR OLD.candidate_body_sha256 IS NOT NEW.candidate_body_sha256
          OR OLD.intent_created_at IS NOT NEW.intent_created_at
          OR OLD.intent_expires_at IS NOT NEW.intent_expires_at
          OR (
            OLD.publication_state <> 'reserved'
            AND (
              OLD.receipt_schema_version IS NOT NEW.receipt_schema_version
              OR OLD.checksum_sha256 IS NOT NEW.checksum_sha256
              OR OLD.size_bytes IS NOT NEW.size_bytes
              OR OLD.media_type IS NOT NEW.media_type
              OR OLD.etag IS NOT NEW.etag
              OR OLD.version_id IS NOT NEW.version_id
              OR OLD.server_side_encryption IS NOT NEW.server_side_encryption
              OR OLD.kms_key_id IS NOT NEW.kms_key_id
              OR OLD.receipt_sha256 IS NOT NEW.receipt_sha256
              OR OLD.receipt_created_at IS NOT NEW.receipt_created_at
            )
          )
          OR NOT (
            (
              OLD.publication_state = 'reserved'
              AND NEW.publication_state = 'ready'
              AND NEW.receipt_schema_version = 'preview-object-receipt.v1'
              AND NEW.checksum_sha256 IS NOT NULL
              AND NEW.size_bytes BETWEEN 1 AND 16777216
              AND NEW.media_type = 'video/mp4'
              AND NEW.etag IS NOT NULL
              AND NEW.version_id IS NOT NULL
              AND NEW.server_side_encryption IS NOT NULL
              AND NEW.receipt_sha256 IS NOT NULL
              AND NEW.receipt_created_at IS OLD.intent_created_at
              AND NEW.retiring_at IS NULL
              AND NEW.retired_at IS NULL
            )
            OR (
              OLD.publication_state = 'reserved'
              AND NEW.publication_state = 'retired'
              AND NEW.receipt_schema_version IS NULL
              AND NEW.checksum_sha256 IS NULL
              AND NEW.size_bytes IS NULL
              AND NEW.media_type IS NULL
              AND NEW.etag IS NULL
              AND NEW.version_id IS NULL
              AND NEW.server_side_encryption IS NULL
              AND NEW.kms_key_id IS NULL
              AND NEW.receipt_sha256 IS NULL
              AND NEW.receipt_created_at IS NULL
              AND NEW.retiring_at IS NULL
              AND NEW.retired_at >= OLD.intent_expires_at
            )
            OR (
              OLD.publication_state = 'ready'
              AND NEW.publication_state = 'retiring'
              AND NEW.retiring_at >= OLD.receipt_created_at
              AND NEW.retired_at IS NULL
            )
            OR (
              OLD.publication_state = 'retiring'
              AND NEW.publication_state = 'retired'
              AND NEW.retiring_at IS OLD.retiring_at
              AND NEW.retired_at >= OLD.retiring_at
            )
          )
        BEGIN
          SELECT RAISE(
            ABORT,
            'preview publication material is immutable; preview publication '
            || 'cannot be resurrected'
          );
        END
        """
    ).execute_if(dialect="sqlite"),
)
event.listen(
    PreviewPublicationModel.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_preview_publication_delete_guard
        BEFORE DELETE ON preview_publications
        FOR EACH ROW
        BEGIN
          SELECT RAISE(
            ABORT,
            'preview publication cannot be deleted or resurrected'
          );
        END
        """
    ).execute_if(dialect="sqlite"),
)
event.listen(
    PreviewAccessReceiptModel.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_preview_access_update_guard
        BEFORE UPDATE ON preview_access_receipts
        FOR EACH ROW
        BEGIN
          SELECT RAISE(ABORT, 'preview access receipts are append-only');
        END
        """
    ).execute_if(dialect="sqlite"),
)
event.listen(
    PreviewPublicationModel.__table__,
    "after_create",
    DDL(
        """
        CREATE OR REPLACE FUNCTION pilot_validate_preview_publication_insert()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
          IF NEW.publication_state <> 'reserved'
             OR NEW.receipt_schema_version IS NOT NULL
             OR NEW.checksum_sha256 IS NOT NULL
             OR NEW.size_bytes IS NOT NULL
             OR NEW.media_type IS NOT NULL
             OR NEW.etag IS NOT NULL
             OR NEW.version_id IS NOT NULL
             OR NEW.server_side_encryption IS NOT NULL
             OR NEW.kms_key_id IS NOT NULL
             OR NEW.receipt_sha256 IS NOT NULL
             OR NEW.receipt_created_at IS NOT NULL
             OR NEW.retiring_at IS NOT NULL
             OR NEW.retired_at IS NOT NULL
             OR NEW.intent_expires_at >
                NEW.intent_created_at + interval '1 hour'
             OR NEW.object_key <> (
               NEW.site_id || '/' || NEW.event_id || '/' ||
               NEW.evidence_id || '/' || NEW.sha256 || '.mp4'
             )
             OR NOT EXISTS (
               SELECT 1
                 FROM public.candidate_events AS candidate
                 JOIN public.cameras AS camera
                   ON camera.camera_id = candidate.camera_id
                 JOIN public.candidate_event_provenance AS provenance
                   ON provenance.event_id = candidate.event_id
                 JOIN public.active_pilot_configurations AS active
                   ON active.site_id = provenance.site_id
                 JOIN public.site_config_revisions AS config
                   ON config.site_id = active.site_id
                  AND config.config_revision_id = active.config_revision_id
                 JOIN public.runtime_writer_authorities AS writer
                   ON writer.site_id = active.site_id
                 JOIN public.camera_epoch_authorities AS epoch
                   ON epoch.camera_id = candidate.camera_id
                WHERE candidate.event_id = NEW.event_id
                  AND candidate.camera_id = NEW.camera_id
                  AND candidate.evidence_status = 'pending'
                  AND candidate.review_status = 'candidate'
                  AND candidate.transition_history = 'observation>candidate'
                  AND camera.site_id = NEW.site_id
                  AND provenance.site_id = NEW.site_id
                  AND provenance.runtime_session_id = NEW.runtime_session_id
                  AND provenance.runtime_writer_generation =
                      NEW.runtime_writer_generation
                  AND provenance.configuration_activation_generation =
                      NEW.configuration_activation_generation
                  AND provenance.source_epoch = NEW.source_epoch
                  AND provenance.rule_revision_sha256 =
                      NEW.rule_revision_sha256
                  AND provenance.site_config_sha256 =
                      NEW.configuration_sha256
                  AND provenance.body_sha256 = NEW.candidate_body_sha256
                  AND active.activation_generation =
                      NEW.configuration_activation_generation
                  AND active.ruleset_revision_id =
                      provenance.ruleset_revision_id
                  AND config.config_sha256 = NEW.configuration_sha256
                  AND writer.runtime_session_id = NEW.runtime_session_id
                  AND writer.writer_generation =
                      NEW.runtime_writer_generation
                  AND writer.configuration_activation_generation =
                      NEW.configuration_activation_generation
                  AND epoch.site_id = NEW.site_id
                  AND epoch.source_epoch = NEW.source_epoch
                  AND epoch.runtime_session_id = NEW.runtime_session_id
                  AND epoch.writer_generation =
                      NEW.runtime_writer_generation
                  AND epoch.configuration_activation_generation =
                      NEW.configuration_activation_generation
             ) THEN
            RAISE EXCEPTION USING
              ERRCODE = '23514',
              MESSAGE =
                'preview reservation lacks exact current candidate authority';
          END IF;
          RETURN NEW;
        END;
        $$
        """
    ).execute_if(dialect="postgresql"),
)
event.listen(
    PreviewPublicationModel.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_preview_publication_insert_guard
        BEFORE INSERT ON preview_publications
        FOR EACH ROW
        EXECUTE FUNCTION pilot_validate_preview_publication_insert()
        """
    ).execute_if(dialect="postgresql"),
)
event.listen(
    PreviewPublicationModel.__table__,
    "after_create",
    DDL(
        """
        CREATE OR REPLACE FUNCTION pilot_guard_preview_publication_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION USING
              ERRCODE = '23514',
              MESSAGE = 'preview publication cannot be deleted or resurrected';
          END IF;
          IF ROW(
            OLD.event_id, OLD.site_id, OLD.camera_id, OLD.evidence_id,
            OLD.intent_schema_version, OLD.object_key, OLD.sha256,
            OLD.configuration_sha256, OLD.runtime_session_id,
            OLD.runtime_writer_generation,
            OLD.configuration_activation_generation, OLD.source_epoch,
            OLD.rule_revision_sha256, OLD.candidate_body_sha256,
            OLD.intent_created_at, OLD.intent_expires_at
          ) IS DISTINCT FROM ROW(
            NEW.event_id, NEW.site_id, NEW.camera_id, NEW.evidence_id,
            NEW.intent_schema_version, NEW.object_key, NEW.sha256,
            NEW.configuration_sha256, NEW.runtime_session_id,
            NEW.runtime_writer_generation,
            NEW.configuration_activation_generation, NEW.source_epoch,
            NEW.rule_revision_sha256, NEW.candidate_body_sha256,
            NEW.intent_created_at, NEW.intent_expires_at
          ) THEN
            RAISE EXCEPTION USING
              ERRCODE = '23514',
              MESSAGE = 'preview publication material is immutable';
          END IF;
          IF OLD.publication_state <> 'reserved'
             AND ROW(
               OLD.receipt_schema_version, OLD.checksum_sha256,
               OLD.size_bytes, OLD.media_type, OLD.etag, OLD.version_id,
               OLD.server_side_encryption, OLD.kms_key_id,
               OLD.receipt_sha256, OLD.receipt_created_at
             ) IS DISTINCT FROM ROW(
               NEW.receipt_schema_version, NEW.checksum_sha256,
               NEW.size_bytes, NEW.media_type, NEW.etag, NEW.version_id,
               NEW.server_side_encryption, NEW.kms_key_id,
               NEW.receipt_sha256, NEW.receipt_created_at
             ) THEN
            RAISE EXCEPTION USING
              ERRCODE = '23514',
              MESSAGE = 'preview publication material is immutable';
          END IF;
          IF NOT (
            (
              OLD.publication_state = 'reserved'
              AND NEW.publication_state = 'ready'
              AND NEW.receipt_schema_version = 'preview-object-receipt.v1'
              AND NEW.checksum_sha256 IS NOT NULL
              AND NEW.size_bytes BETWEEN 1 AND 16777216
              AND NEW.media_type = 'video/mp4'
              AND NEW.etag IS NOT NULL
              AND NEW.version_id IS NOT NULL
              AND NEW.server_side_encryption IS NOT NULL
              AND NEW.receipt_sha256 IS NOT NULL
              AND NEW.receipt_created_at IS NOT DISTINCT FROM
                  OLD.intent_created_at
              AND NEW.retiring_at IS NULL
              AND NEW.retired_at IS NULL
            )
            OR (
              OLD.publication_state = 'reserved'
              AND NEW.publication_state = 'retired'
              AND NEW.receipt_schema_version IS NULL
              AND NEW.checksum_sha256 IS NULL
              AND NEW.size_bytes IS NULL
              AND NEW.media_type IS NULL
              AND NEW.etag IS NULL
              AND NEW.version_id IS NULL
              AND NEW.server_side_encryption IS NULL
              AND NEW.kms_key_id IS NULL
              AND NEW.receipt_sha256 IS NULL
              AND NEW.receipt_created_at IS NULL
              AND NEW.retiring_at IS NULL
              AND NEW.retired_at >= OLD.intent_expires_at
            )
            OR (
              OLD.publication_state = 'ready'
              AND NEW.publication_state = 'retiring'
              AND NEW.retiring_at >= OLD.receipt_created_at
              AND NEW.retired_at IS NULL
            )
            OR (
              OLD.publication_state = 'retiring'
              AND NEW.publication_state = 'retired'
              AND NEW.retiring_at IS NOT DISTINCT FROM OLD.retiring_at
              AND NEW.retired_at >= OLD.retiring_at
            )
          ) THEN
            RAISE EXCEPTION USING
              ERRCODE = '23514',
              MESSAGE = 'preview publication cannot be resurrected';
          END IF;
          RETURN NEW;
        END;
        $$
        """
    ).execute_if(dialect="postgresql"),
)
event.listen(
    PreviewPublicationModel.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_preview_publication_mutation_guard
        BEFORE UPDATE OR DELETE ON preview_publications
        FOR EACH ROW
        EXECUTE FUNCTION pilot_guard_preview_publication_mutation()
        """
    ).execute_if(dialect="postgresql"),
)
event.listen(
    PreviewAccessReceiptModel.__table__,
    "after_create",
    DDL(
        """
        CREATE OR REPLACE FUNCTION pilot_guard_preview_access_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
          IF TG_OP = 'UPDATE' THEN
            RAISE EXCEPTION USING
              ERRCODE = '23514',
              MESSAGE = 'preview access receipts are append-only';
          END IF;
          RETURN OLD;
        END;
        $$
        """
    ).execute_if(dialect="postgresql"),
)
event.listen(
    PreviewAccessReceiptModel.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_preview_access_update_guard
        BEFORE UPDATE ON preview_access_receipts
        FOR EACH ROW
        EXECUTE FUNCTION pilot_guard_preview_access_mutation()
        """
    ).execute_if(dialect="postgresql"),
)
event.listen(
    PreviewAccessReceiptModel.__table__,
    "after_drop",
    DDL(
        "DROP FUNCTION IF EXISTS pilot_guard_preview_access_mutation()"
    ).execute_if(dialect="postgresql"),
)
event.listen(
    PreviewPublicationModel.__table__,
    "after_drop",
    DDL(
        "DROP FUNCTION IF EXISTS pilot_guard_preview_publication_mutation()"
    ).execute_if(dialect="postgresql"),
)
event.listen(
    PreviewPublicationModel.__table__,
    "after_drop",
    DDL(
        "DROP FUNCTION IF EXISTS pilot_validate_preview_publication_insert()"
    ).execute_if(dialect="postgresql"),
)


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
