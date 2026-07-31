"""Add reviewed rules, generation fences, epochs, and atomic event provenance.

Revision ID: 0006_event_provenance
Revises: 0005_auth_lifecycle
Create Date: 2026-07-31
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006_event_provenance"
down_revision: Union[str, Sequence[str], None] = "0005_auth_lifecycle"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_IMMUTABLE_TABLES = (
    "site_config_revisions",
    "camera_ruleset_revisions",
    "camera_rule_revisions",
    "configuration_activations",
    "runtime_writer_sessions",
    "camera_epoch_history",
    "legacy_candidate_imports",
    "candidate_event_provenance",
)


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    with op.batch_alter_table("cameras") as batch:
        batch.create_unique_constraint(
            "uq_cameras_site_camera",
            ["site_id", "camera_id"],
        )

    op.create_table(
        "site_config_revisions",
        sa.Column("config_revision_id", sa.String(length=128), nullable=False),
        sa.Column("schema_version", sa.String(length=64), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("config_sha256", sa.String(length=64), nullable=False),
        sa.Column("artifact_sha256", sa.String(length=64), nullable=False),
        sa.Column("signature_sha256", sa.String(length=64), nullable=False),
        sa.Column("signing_key_spki_sha256", sa.String(length=64), nullable=False),
        sa.Column("reviewed_by", sa.String(length=255), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("review_reference", sa.String(length=2048), nullable=False),
        sa.Column("canonical_config", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("revision > 0", name="ck_site_config_revision_positive"),
        sa.CheckConstraint("length(config_sha256) = 64", name="ck_site_config_sha256"),
        sa.CheckConstraint(
            "length(artifact_sha256) = 64",
            name="ck_site_config_artifact_sha256",
        ),
        sa.CheckConstraint(
            "length(signature_sha256) = 64",
            name="ck_site_config_signature_sha256",
        ),
        sa.CheckConstraint(
            "length(signing_key_spki_sha256) = 64",
            name="ck_site_config_signing_key_sha256",
        ),
        sa.ForeignKeyConstraint(["site_id"], ["sites.site_id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("config_revision_id"),
        sa.UniqueConstraint("site_id", "revision", name="uq_site_config_revision"),
        sa.UniqueConstraint(
            "site_id",
            "config_sha256",
            name="uq_site_config_digest",
        ),
        sa.UniqueConstraint(
            "site_id",
            "config_revision_id",
            name="uq_site_config_site_revision_id",
        ),
    )
    op.create_table(
        "camera_ruleset_revisions",
        sa.Column("ruleset_revision_id", sa.String(length=128), nullable=False),
        sa.Column("schema_version", sa.String(length=64), nullable=False),
        sa.Column("ruleset_id", sa.String(length=128), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("config_revision_id", sa.String(length=128), nullable=False),
        sa.Column("site_config_sha256", sa.String(length=64), nullable=False),
        sa.Column("frozen_workload_sha256", sa.String(length=64), nullable=False),
        sa.Column("engine_sha256", sa.String(length=64), nullable=False),
        sa.Column("runtime_manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("ruleset_sha256", sa.String(length=64), nullable=False),
        sa.Column("artifact_sha256", sa.String(length=64), nullable=False),
        sa.Column("signature_sha256", sa.String(length=64), nullable=False),
        sa.Column("signing_key_spki_sha256", sa.String(length=64), nullable=False),
        sa.Column("reviewed_by", sa.String(length=255), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("review_reference", sa.String(length=2048), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "revision > 0",
            name="ck_camera_ruleset_revision_positive",
        ),
        sa.CheckConstraint(
            "length(site_config_sha256) = 64",
            name="ck_ruleset_site_config_sha256",
        ),
        sa.CheckConstraint(
            "length(frozen_workload_sha256) = 64",
            name="ck_ruleset_frozen_workload_sha256",
        ),
        sa.CheckConstraint(
            "length(engine_sha256) = 64",
            name="ck_ruleset_engine_sha256",
        ),
        sa.CheckConstraint(
            "length(runtime_manifest_sha256) = 64",
            name="ck_ruleset_runtime_manifest_sha256",
        ),
        sa.CheckConstraint("length(ruleset_sha256) = 64", name="ck_ruleset_sha256"),
        sa.CheckConstraint(
            "length(artifact_sha256) = 64",
            name="ck_ruleset_artifact_sha256",
        ),
        sa.CheckConstraint(
            "length(signature_sha256) = 64",
            name="ck_ruleset_signature_sha256",
        ),
        sa.CheckConstraint(
            "length(signing_key_spki_sha256) = 64",
            name="ck_ruleset_signing_key_sha256",
        ),
        sa.ForeignKeyConstraint(
            ["site_id", "config_revision_id"],
            [
                "site_config_revisions.site_id",
                "site_config_revisions.config_revision_id",
            ],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["site_id"], ["sites.site_id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("ruleset_revision_id"),
        sa.UniqueConstraint(
            "site_id",
            "ruleset_id",
            "revision",
            name="uq_ruleset_revision",
        ),
        sa.UniqueConstraint("site_id", "ruleset_sha256", name="uq_ruleset_digest"),
        sa.UniqueConstraint(
            "site_id",
            "ruleset_revision_id",
            name="uq_ruleset_site_revision_id",
        ),
        sa.UniqueConstraint(
            "site_id",
            "config_revision_id",
            "ruleset_revision_id",
            name="uq_ruleset_site_config_revision",
        ),
    )
    op.create_table(
        "camera_rule_revisions",
        sa.Column("ruleset_revision_id", sa.String(length=128), nullable=False),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column("schema_version", sa.String(length=64), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("camera_id", sa.String(length=128), nullable=False),
        sa.Column("module", sa.String(length=128), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("model_artifact_id", sa.String(length=255), nullable=False),
        sa.Column("model_decision_sha256", sa.String(length=64), nullable=False),
        sa.Column("gate_mode", sa.String(length=16), nullable=False),
        sa.Column("minimum_confidence", sa.Float(), nullable=False),
        sa.Column("minimum_votes", sa.Integer(), nullable=False),
        sa.Column("sample_count", sa.Integer(), nullable=False),
        sa.Column("window_seconds", sa.Float(), nullable=False),
        sa.Column("evidence_seconds", sa.Integer(), nullable=False),
        sa.Column("rule_spec", sa.JSON(), nullable=False),
        sa.Column("rule_revision_sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("revision > 0", name="ck_camera_rule_revision_positive"),
        sa.CheckConstraint(
            "gate_mode IN ('disabled', 'shadow', 'operator')",
            name="ck_camera_rule_gate_mode",
        ),
        sa.CheckConstraint(
            "minimum_confidence >= 0 AND minimum_confidence <= 1",
            name="ck_camera_rule_confidence",
        ),
        sa.CheckConstraint(
            "minimum_votes >= 1 AND minimum_votes <= 64",
            name="ck_camera_rule_votes",
        ),
        sa.CheckConstraint(
            "sample_count >= minimum_votes AND sample_count <= 64",
            name="ck_camera_rule_samples",
        ),
        sa.CheckConstraint(
            "window_seconds > 0 AND window_seconds <= 60",
            name="ck_camera_rule_window",
        ),
        sa.CheckConstraint(
            "evidence_seconds >= 4 AND evidence_seconds <= 10",
            name="ck_camera_rule_evidence",
        ),
        sa.CheckConstraint(
            "length(model_decision_sha256) = 64",
            name="ck_camera_rule_decision_sha256",
        ),
        sa.CheckConstraint(
            "length(rule_revision_sha256) = 64",
            name="ck_camera_rule_revision_sha256",
        ),
        sa.ForeignKeyConstraint(
            ["site_id", "camera_id"],
            ["cameras.site_id", "cameras.camera_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["model_artifact_id"],
            ["model_artifacts.artifact_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["site_id", "ruleset_revision_id"],
            [
                "camera_ruleset_revisions.site_id",
                "camera_ruleset_revisions.ruleset_revision_id",
            ],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("ruleset_revision_id", "rule_id"),
        sa.UniqueConstraint(
            "site_id",
            "rule_id",
            "revision",
            name="uq_camera_rule_identity_revision",
        ),
        sa.UniqueConstraint(
            "site_id",
            "ruleset_revision_id",
            "rule_id",
            name="uq_camera_rule_site_ruleset_rule",
        ),
        sa.UniqueConstraint(
            "ruleset_revision_id",
            "camera_id",
            "module",
            name="uq_ruleset_camera_module",
        ),
    )
    op.create_table(
        "configuration_activations",
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("expected_activation_generation", sa.BigInteger(), nullable=False),
        sa.Column("activation_generation", sa.BigInteger(), nullable=False),
        sa.Column("runtime_writer_generation", sa.BigInteger(), nullable=False),
        sa.Column("config_revision_id", sa.String(length=128), nullable=False),
        sa.Column("site_config_sha256", sa.String(length=64), nullable=False),
        sa.Column("ruleset_revision_id", sa.String(length=128), nullable=False),
        sa.Column("ruleset_sha256", sa.String(length=64), nullable=False),
        sa.Column("activated_by", sa.String(length=128), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("force_new_generation", sa.Boolean(), nullable=False),
        sa.CheckConstraint(
            "expected_activation_generation >= 0",
            name="ck_activation_expected_generation",
        ),
        sa.CheckConstraint(
            "activation_generation > 0",
            name="ck_activation_generation",
        ),
        sa.CheckConstraint(
            "runtime_writer_generation > 0",
            name="ck_activation_writer_generation",
        ),
        sa.CheckConstraint(
            "length(site_config_sha256) = 64",
            name="ck_activation_site_config_sha256",
        ),
        sa.CheckConstraint(
            "length(ruleset_sha256) = 64",
            name="ck_activation_ruleset_sha256",
        ),
        sa.ForeignKeyConstraint(
            ["site_id", "config_revision_id"],
            [
                "site_config_revisions.site_id",
                "site_config_revisions.config_revision_id",
            ],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["site_id", "config_revision_id", "ruleset_revision_id"],
            [
                "camera_ruleset_revisions.site_id",
                "camera_ruleset_revisions.config_revision_id",
                "camera_ruleset_revisions.ruleset_revision_id",
            ],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("site_id", "activation_generation"),
        sa.UniqueConstraint("idempotency_key", name="uq_activation_idempotency"),
        sa.UniqueConstraint(
            "site_id",
            "activation_generation",
            "config_revision_id",
            "ruleset_revision_id",
            name="uq_activation_exact_pointer",
        ),
    )
    op.create_table(
        "active_pilot_configurations",
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("activation_generation", sa.BigInteger(), nullable=False),
        sa.Column("config_revision_id", sa.String(length=128), nullable=False),
        sa.Column("ruleset_revision_id", sa.String(length=128), nullable=False),
        sa.Column("activated_by", sa.String(length=128), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "activation_generation > 0",
            name="ck_active_configuration_generation",
        ),
        sa.ForeignKeyConstraint(
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
        sa.ForeignKeyConstraint(
            ["site_id", "config_revision_id"],
            [
                "site_config_revisions.site_id",
                "site_config_revisions.config_revision_id",
            ],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["site_id", "config_revision_id", "ruleset_revision_id"],
            [
                "camera_ruleset_revisions.site_id",
                "camera_ruleset_revisions.config_revision_id",
                "camera_ruleset_revisions.ruleset_revision_id",
            ],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("site_id"),
        sa.UniqueConstraint(
            "site_id",
            "activation_generation",
            name="uq_active_site_generation",
        ),
    )
    op.create_table(
        "runtime_writer_authorities",
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("runtime_session_id", sa.String(length=128), nullable=True),
        sa.Column("writer_generation", sa.BigInteger(), nullable=False),
        sa.Column(
            "configuration_activation_generation",
            sa.BigInteger(),
            nullable=False,
        ),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "writer_generation > 0",
            name="ck_runtime_writer_generation",
        ),
        sa.CheckConstraint(
            "configuration_activation_generation > 0",
            name="ck_runtime_writer_activation_generation",
        ),
        sa.ForeignKeyConstraint(
            ["site_id", "configuration_activation_generation"],
            [
                "configuration_activations.site_id",
                "configuration_activations.activation_generation",
            ],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["site_id", "configuration_activation_generation"],
            [
                "active_pilot_configurations.site_id",
                "active_pilot_configurations.activation_generation",
            ],
            deferrable=True,
            initially="DEFERRED",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("site_id"),
    )
    op.create_table(
        "runtime_writer_sessions",
        sa.Column("runtime_session_id", sa.String(length=128), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("writer_generation", sa.BigInteger(), nullable=False),
        sa.Column(
            "configuration_activation_generation",
            sa.BigInteger(),
            nullable=False,
        ),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("receipt_sha256", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "writer_generation > 0",
            name="ck_writer_session_generation",
        ),
        sa.CheckConstraint(
            "configuration_activation_generation > 0",
            name="ck_writer_session_activation_generation",
        ),
        sa.CheckConstraint(
            "length(receipt_sha256) = 64",
            name="ck_writer_receipt_sha256",
        ),
        sa.ForeignKeyConstraint(
            ["site_id", "configuration_activation_generation"],
            [
                "configuration_activations.site_id",
                "configuration_activations.activation_generation",
            ],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("runtime_session_id"),
        sa.UniqueConstraint(
            "site_id",
            "writer_generation",
            name="uq_writer_session_site_generation",
        ),
        sa.UniqueConstraint(
            "site_id",
            "runtime_session_id",
            "writer_generation",
            "configuration_activation_generation",
            name="uq_writer_session_exact_authority",
        ),
    )
    op.create_table(
        "camera_epoch_history",
        sa.Column("camera_id", sa.String(length=128), nullable=False),
        sa.Column("source_epoch", sa.String(length=36), nullable=False),
        sa.Column("previous_source_epoch", sa.String(length=36), nullable=True),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("runtime_session_id", sa.String(length=128), nullable=False),
        sa.Column("writer_generation", sa.BigInteger(), nullable=False),
        sa.Column(
            "configuration_activation_generation",
            sa.BigInteger(),
            nullable=False,
        ),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["site_id", "camera_id"],
            ["cameras.site_id", "cameras.camera_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
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
        sa.PrimaryKeyConstraint("camera_id", "source_epoch"),
    )
    op.create_table(
        "camera_epoch_authorities",
        sa.Column("camera_id", sa.String(length=128), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("source_epoch", sa.String(length=36), nullable=False),
        sa.Column("runtime_session_id", sa.String(length=128), nullable=False),
        sa.Column("writer_generation", sa.BigInteger(), nullable=False),
        sa.Column(
            "configuration_activation_generation",
            sa.BigInteger(),
            nullable=False,
        ),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["site_id", "camera_id"],
            ["cameras.site_id", "cameras.camera_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
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
        sa.PrimaryKeyConstraint("camera_id"),
        sa.UniqueConstraint(
            "site_id",
            "camera_id",
            "source_epoch",
            name="uq_camera_epoch_active_identity",
        ),
    )
    op.create_table(
        "legacy_candidate_imports",
        sa.Column("event_id", sa.String(length=36), nullable=False),
        sa.Column("schema_version", sa.String(length=64), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("legacy_cutoff_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("migration_revision", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "migration_revision = '0006_event_provenance'",
            name="ck_legacy_candidate_migration",
        ),
        sa.CheckConstraint(
            "schema_version = 'legacy-candidate-import.v1'",
            name="ck_legacy_candidate_schema",
        ),
        sa.CheckConstraint(
            "legacy_cutoff_at <= imported_at",
            name="ck_legacy_candidate_cutoff",
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["candidate_events.event_id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("event_id"),
    )
    op.execute(
        """
        INSERT INTO legacy_candidate_imports (
            event_id,
            schema_version,
            imported_at,
            legacy_cutoff_at,
            migration_revision
        )
        SELECT
            event_id,
            'legacy-candidate-import.v1',
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP,
            '0006_event_provenance'
        FROM candidate_events
        """
    )
    op.create_table(
        "candidate_event_provenance",
        sa.Column("event_id", sa.String(length=36), nullable=False),
        sa.Column("schema_version", sa.String(length=64), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("runtime_session_id", sa.String(length=128), nullable=False),
        sa.Column("runtime_writer_generation", sa.BigInteger(), nullable=False),
        sa.Column(
            "configuration_activation_generation",
            sa.BigInteger(),
            nullable=False,
        ),
        sa.Column("source_epoch", sa.String(length=36), nullable=False),
        sa.Column("ruleset_revision_id", sa.String(length=128), nullable=False),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column("rule_revision", sa.Integer(), nullable=False),
        sa.Column("rule_revision_sha256", sa.String(length=64), nullable=False),
        sa.Column("ruleset_sha256", sa.String(length=64), nullable=False),
        sa.Column("site_config_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "model_gate_decision_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("gate_mode", sa.String(length=16), nullable=False),
        sa.Column("body_sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "schema_version = 'candidate-event-provenance.v1'",
            name="ck_candidate_provenance_schema",
        ),
        sa.CheckConstraint(
            "runtime_writer_generation > 0",
            name="ck_candidate_provenance_writer_generation",
        ),
        sa.CheckConstraint(
            "configuration_activation_generation > 0",
            name="ck_candidate_provenance_activation_generation",
        ),
        sa.CheckConstraint(
            "rule_revision > 0",
            name="ck_candidate_provenance_rule_revision",
        ),
        sa.CheckConstraint(
            "gate_mode IN ('shadow', 'operator')",
            name="ck_candidate_provenance_gate_mode",
        ),
        sa.CheckConstraint(
            "length(rule_revision_sha256) = 64",
            name="ck_candidate_provenance_rule_sha256",
        ),
        sa.CheckConstraint(
            "length(ruleset_sha256) = 64",
            name="ck_candidate_provenance_ruleset_sha256",
        ),
        sa.CheckConstraint(
            "length(site_config_sha256) = 64",
            name="ck_candidate_provenance_config_sha256",
        ),
        sa.CheckConstraint(
            "length(model_gate_decision_sha256) = 64",
            name="ck_candidate_provenance_decision_sha256",
        ),
        sa.CheckConstraint(
            "length(body_sha256) = 64",
            name="ck_candidate_provenance_body_sha256",
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["candidate_events.event_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["site_id", "ruleset_revision_id", "rule_id"],
            [
                "camera_rule_revisions.site_id",
                "camera_rule_revisions.ruleset_revision_id",
                "camera_rule_revisions.rule_id",
            ],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("event_id"),
    )
    op.create_index(
        "ix_candidate_provenance_runtime",
        "candidate_event_provenance",
        ["site_id", "runtime_writer_generation", "runtime_session_id"],
        unique=False,
    )

    if dialect == "sqlite":
        _create_sqlite_guards()
    elif dialect == "postgresql":
        _create_postgresql_guards_and_optional_runtime_grants()


def _create_sqlite_guards() -> None:
    for table in _IMMUTABLE_TABLES:
        for operation in ("UPDATE", "DELETE"):
            op.execute(
                f"""
                CREATE TRIGGER trg_{table}_{operation.lower()}_immutable
                BEFORE {operation} ON {table}
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'reviewed authority history is immutable'
                    );
                END
                """
            )
    op.execute(
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
    )
    op.execute(
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
                    ON config.site_id = active.site_id
                   AND config.config_revision_id = active.config_revision_id
                  JOIN camera_ruleset_revisions AS ruleset
                    ON ruleset.site_id = active.site_id
                   AND ruleset.ruleset_revision_id = active.ruleset_revision_id
                  JOIN runtime_writer_authorities AS writer
                    ON writer.site_id = active.site_id
                  JOIN candidate_events AS candidate
                    ON candidate.event_id = NEW.event_id
                  JOIN camera_epoch_authorities AS epoch
                    ON epoch.site_id = active.site_id
                   AND epoch.camera_id = candidate.camera_id
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
                   AND epoch.source_epoch = NEW.source_epoch
                   AND epoch.runtime_session_id = NEW.runtime_session_id
                   AND epoch.writer_generation = NEW.runtime_writer_generation
                   AND epoch.configuration_activation_generation =
                       NEW.configuration_activation_generation
            ) THEN RAISE(ABORT, 'retired runtime writer or epoch') END;
            SELECT CASE WHEN NOT EXISTS (
                SELECT 1
                  FROM camera_rule_revisions AS rule
                  JOIN candidate_events AS candidate
                    ON candidate.event_id = NEW.event_id
                  JOIN cameras AS camera
                    ON camera.camera_id = candidate.camera_id
                 WHERE rule.site_id = NEW.site_id
                   AND rule.ruleset_revision_id = NEW.ruleset_revision_id
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
            ) THEN RAISE(ABORT, 'candidate provenance does not match rule') END;
        END
        """
    )


def _create_postgresql_guards_and_optional_runtime_grants() -> None:
    op.execute(
        """
        DO $$
        BEGIN
          IF current_user = 'kuzet_runtime'
             OR EXISTS (
                SELECT 1
                  FROM pg_roles
                 WHERE rolname = 'kuzet_runtime'
                   AND rolsuper
             )
          THEN
            RAISE EXCEPTION
              'kuzet_runtime must be a non-owner, non-superuser runtime role';
          END IF;
        END
        $$;
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION pilot_reject_reviewed_revision_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'reviewed authority history is immutable';
        END;
        $$
        """
    )
    for table in _IMMUTABLE_TABLES:
        op.execute(
            f"""
            CREATE TRIGGER trg_{table}_immutable
            BEFORE UPDATE OR DELETE ON {table}
            FOR EACH ROW
            EXECUTE FUNCTION pilot_reject_reviewed_revision_mutation()
            """
        )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION pilot_validate_legacy_candidate_import()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM public.candidate_event_provenance
                 WHERE event_id = NEW.event_id
            ) OR NOT EXISTS (
                SELECT 1 FROM public.candidate_events
                 WHERE event_id = NEW.event_id
                   AND opened_at <= NEW.legacy_cutoff_at
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'legacy marker does not match a pre-cutoff event';
            END IF;
            RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_legacy_candidate_import_fence
        BEFORE INSERT ON legacy_candidate_imports
        FOR EACH ROW EXECUTE FUNCTION pilot_validate_legacy_candidate_import()
        """
    )
    op.execute(
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
                    ON config.site_id = active.site_id
                   AND config.config_revision_id = active.config_revision_id
                  JOIN public.camera_ruleset_revisions AS ruleset
                    ON ruleset.site_id = active.site_id
                   AND ruleset.ruleset_revision_id = active.ruleset_revision_id
                  JOIN public.runtime_writer_authorities AS writer
                    ON writer.site_id = active.site_id
                  JOIN public.candidate_events AS candidate
                    ON candidate.event_id = NEW.event_id
                  JOIN public.camera_epoch_authorities AS epoch
                    ON epoch.site_id = active.site_id
                   AND epoch.camera_id = candidate.camera_id
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
                   AND epoch.source_epoch = NEW.source_epoch
                   AND epoch.runtime_session_id = NEW.runtime_session_id
                   AND epoch.writer_generation = NEW.runtime_writer_generation
                   AND epoch.configuration_activation_generation =
                       NEW.configuration_activation_generation
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'retired runtime writer or epoch';
            END IF;
            IF NOT EXISTS (
                SELECT 1
                  FROM public.camera_rule_revisions AS rule
                  JOIN public.candidate_events AS candidate
                    ON candidate.event_id = NEW.event_id
                  JOIN public.cameras AS camera
                    ON camera.camera_id = candidate.camera_id
                 WHERE rule.site_id = NEW.site_id
                   AND rule.ruleset_revision_id = NEW.ruleset_revision_id
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
                    MESSAGE = 'candidate provenance does not match rule';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_candidate_provenance_fence
        BEFORE INSERT ON candidate_event_provenance
        FOR EACH ROW EXECUTE FUNCTION pilot_validate_candidate_provenance()
        """
    )
    op.execute(
        """
        CREATE FUNCTION pilot_ingest_candidate(
            candidate jsonb,
            provenance jsonb
        )
        RETURNS text
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
            existing_event_id text;
            existing_body_sha256 text;
            existing_material_matches boolean;
            transition_history text;
        BEGIN
            IF NOT (
                candidate ?& ARRAY[
                    'event_id', 'schema_version', 'dedupe_key', 'camera_id',
                    'module', 'opened_at', 'last_seen_at', 'peak_confidence',
                    'reason', 'model_artifact_id', 'gate_mode',
                    'evidence_status', 'review_status', 'transition_history'
                ]
            )
               OR (
                    SELECT count(*)
                      FROM jsonb_object_keys(candidate)
                  ) <> 14
               OR NOT (
                provenance ?& ARRAY[
                    'schema_version', 'site_id', 'runtime_session_id',
                    'runtime_writer_generation',
                    'configuration_activation_generation', 'source_epoch',
                    'ruleset_revision_id', 'rule_id', 'rule_revision',
                    'rule_revision_sha256', 'ruleset_sha256',
                    'site_config_sha256', 'model_gate_decision_sha256',
                    'gate_mode', 'body_sha256', 'body_canonical_json'
                ]
               )
               OR (
                    SELECT count(*)
                      FROM jsonb_object_keys(provenance)
                  ) <> 16
               OR candidate->>'schema_version' <> 'candidate-event.v1'
               OR candidate->>'evidence_status' <> 'pending'
               OR candidate->>'review_status' <> 'candidate'
               OR candidate->'transition_history'
                    <> '["observation", "candidate"]'::jsonb
               OR candidate->>'gate_mode' NOT IN ('shadow', 'operator')
               OR candidate->>'event_id'
                    !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
               OR provenance->>'source_epoch'
                    !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
               OR provenance->>'schema_version'
                    <> 'candidate-event-provenance.v1'
               OR provenance->>'gate_mode' <> candidate->>'gate_mode'
               OR jsonb_typeof(candidate->'peak_confidence') <> 'number'
               OR (candidate->>'peak_confidence')::double precision < 0.0
               OR (candidate->>'peak_confidence')::double precision > 1.0
               OR (candidate->>'last_seen_at')::timestamptz
                    < (candidate->>'opened_at')::timestamptz
               OR jsonb_typeof(
                    provenance->'runtime_writer_generation'
                  ) <> 'number'
               OR provenance->>'runtime_writer_generation' !~ '^[1-9][0-9]*$'
               OR jsonb_typeof(
                    provenance->'configuration_activation_generation'
                  ) <> 'number'
               OR provenance->>'configuration_activation_generation'
                    !~ '^[1-9][0-9]*$'
               OR jsonb_typeof(provenance->'rule_revision') <> 'number'
               OR provenance->>'rule_revision' !~ '^[1-9][0-9]*$'
               OR provenance->>'event_id' IS NOT NULL
               OR provenance->>'rule_revision_sha256'
                    !~ '^[0-9a-f]{64}$'
               OR provenance->>'ruleset_sha256' !~ '^[0-9a-f]{64}$'
               OR provenance->>'site_config_sha256' !~ '^[0-9a-f]{64}$'
               OR provenance->>'model_gate_decision_sha256'
                    !~ '^[0-9a-f]{64}$'
               OR provenance->>'body_sha256' !~ '^[0-9a-f]{64}$'
               OR (provenance->>'body_canonical_json')::jsonb
                    <> jsonb_build_object(
                        'schema_version',
                        'provenanced-candidate-event.v2',
                        'event',
                        candidate - 'dedupe_key',
                        'provenance',
                        provenance - ARRAY[
                            'ruleset_revision_id',
                            'body_sha256',
                            'body_canonical_json'
                        ]
                    )
               OR encode(
                    sha256(
                        convert_to(
                            provenance->>'body_canonical_json',
                            'UTF8'
                        )
                    ),
                    'hex'
                  ) <> provenance->>'body_sha256'
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'runtime may ingest only one fresh pending candidate';
            END IF;

            PERFORM 1
              FROM public.active_pilot_configurations AS active
              JOIN public.site_config_revisions AS config
                ON config.site_id = active.site_id
               AND config.config_revision_id = active.config_revision_id
              JOIN public.camera_ruleset_revisions AS ruleset
                ON ruleset.site_id = active.site_id
               AND ruleset.ruleset_revision_id = active.ruleset_revision_id
              JOIN public.runtime_writer_authorities AS writer
                ON writer.site_id = active.site_id
              JOIN public.camera_epoch_authorities AS epoch
                ON epoch.site_id = active.site_id
               AND epoch.camera_id = candidate->>'camera_id'
             WHERE active.site_id = provenance->>'site_id'
               AND active.activation_generation =
                   (provenance->>'configuration_activation_generation')::bigint
               AND config.config_sha256 = provenance->>'site_config_sha256'
               AND ruleset.ruleset_revision_id =
                   provenance->>'ruleset_revision_id'
               AND ruleset.ruleset_sha256 = provenance->>'ruleset_sha256'
               AND writer.runtime_session_id =
                   provenance->>'runtime_session_id'
               AND writer.writer_generation =
                   (provenance->>'runtime_writer_generation')::bigint
               AND writer.configuration_activation_generation =
                   (provenance->>'configuration_activation_generation')::bigint
               AND epoch.source_epoch = provenance->>'source_epoch'
               AND epoch.runtime_session_id =
                   provenance->>'runtime_session_id'
               AND epoch.writer_generation =
                   (provenance->>'runtime_writer_generation')::bigint
               AND epoch.configuration_activation_generation =
                   (provenance->>'configuration_activation_generation')::bigint
             FOR UPDATE OF active, writer, epoch;
            IF NOT FOUND THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'retired runtime writer or camera epoch';
            END IF;

            PERFORM 1
              FROM public.camera_rule_revisions AS rule
              JOIN public.cameras AS camera
                ON camera.site_id = rule.site_id
               AND camera.camera_id = rule.camera_id
             WHERE rule.site_id = provenance->>'site_id'
               AND rule.ruleset_revision_id =
                   provenance->>'ruleset_revision_id'
               AND rule.rule_id = provenance->>'rule_id'
               AND rule.revision =
                   (provenance->>'rule_revision')::integer
               AND rule.rule_revision_sha256 =
                   provenance->>'rule_revision_sha256'
               AND rule.model_decision_sha256 =
                   provenance->>'model_gate_decision_sha256'
               AND rule.gate_mode = provenance->>'gate_mode'
               AND rule.enabled
               AND rule.camera_id = candidate->>'camera_id'
               AND rule.module = candidate->>'module'
               AND rule.model_artifact_id =
                   candidate->>'model_artifact_id'
             FOR SHARE OF rule;
            IF NOT FOUND THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'candidate does not match active reviewed rule';
            END IF;

            SELECT
                c.event_id,
                p.body_sha256,
                (
                    c.schema_version = candidate->>'schema_version'
                    AND c.dedupe_key = candidate->>'dedupe_key'
                    AND c.camera_id = candidate->>'camera_id'
                    AND c.module = candidate->>'module'
                    AND c.opened_at =
                        (candidate->>'opened_at')::timestamptz
                    AND c.last_seen_at =
                        (candidate->>'last_seen_at')::timestamptz
                    AND c.peak_confidence =
                        (candidate->>'peak_confidence')::double precision
                    AND c.reason = candidate->>'reason'
                    AND c.model_artifact_id =
                        candidate->>'model_artifact_id'
                    AND c.gate_mode = candidate->>'gate_mode'
                    AND p.site_id = provenance->>'site_id'
                    AND p.runtime_session_id =
                        provenance->>'runtime_session_id'
                    AND p.runtime_writer_generation =
                        (provenance->>'runtime_writer_generation')::bigint
                    AND p.configuration_activation_generation =
                        (provenance->>'configuration_activation_generation')::bigint
                    AND p.source_epoch = provenance->>'source_epoch'
                    AND p.ruleset_revision_id =
                        provenance->>'ruleset_revision_id'
                    AND p.rule_id = provenance->>'rule_id'
                    AND p.rule_revision =
                        (provenance->>'rule_revision')::integer
                    AND p.rule_revision_sha256 =
                        provenance->>'rule_revision_sha256'
                    AND p.ruleset_sha256 = provenance->>'ruleset_sha256'
                    AND p.site_config_sha256 =
                        provenance->>'site_config_sha256'
                    AND p.model_gate_decision_sha256 =
                        provenance->>'model_gate_decision_sha256'
                    AND p.gate_mode = provenance->>'gate_mode'
                )
              INTO
                existing_event_id,
                existing_body_sha256,
                existing_material_matches
              FROM public.candidate_events AS c
              LEFT JOIN public.candidate_event_provenance AS p
                ON p.event_id = c.event_id
             WHERE c.event_id = candidate->>'event_id'
                OR c.dedupe_key = candidate->>'dedupe_key'
             FOR UPDATE OF c;
            IF FOUND THEN
                IF existing_body_sha256 IS NULL
                   OR existing_body_sha256 <> provenance->>'body_sha256'
                   OR NOT existing_material_matches
                THEN
                    RAISE EXCEPTION USING
                        ERRCODE = '23505',
                        MESSAGE = 'candidate identity reused with different data';
                END IF;
                RETURN existing_event_id;
            END IF;

            SELECT string_agg(value, '>' ORDER BY ordinal)
              INTO transition_history
              FROM jsonb_array_elements_text(
                    candidate->'transition_history'
              ) WITH ORDINALITY AS item(value, ordinal);

            INSERT INTO public.candidate_events (
                event_id,
                schema_version,
                dedupe_key,
                camera_id,
                module,
                opened_at,
                last_seen_at,
                peak_confidence,
                reason,
                model_artifact_id,
                gate_mode,
                evidence_status,
                review_status,
                transition_history,
                created_at
            ) VALUES (
                candidate->>'event_id',
                candidate->>'schema_version',
                candidate->>'dedupe_key',
                candidate->>'camera_id',
                candidate->>'module',
                (candidate->>'opened_at')::timestamptz,
                (candidate->>'last_seen_at')::timestamptz,
                (candidate->>'peak_confidence')::double precision,
                candidate->>'reason',
                candidate->>'model_artifact_id',
                candidate->>'gate_mode',
                candidate->>'evidence_status',
                candidate->>'review_status',
                transition_history,
                CURRENT_TIMESTAMP
            );
            INSERT INTO public.candidate_event_provenance (
                event_id,
                schema_version,
                site_id,
                runtime_session_id,
                runtime_writer_generation,
                configuration_activation_generation,
                source_epoch,
                ruleset_revision_id,
                rule_id,
                rule_revision,
                rule_revision_sha256,
                ruleset_sha256,
                site_config_sha256,
                model_gate_decision_sha256,
                gate_mode,
                body_sha256,
                created_at
            ) VALUES (
                candidate->>'event_id',
                provenance->>'schema_version',
                provenance->>'site_id',
                provenance->>'runtime_session_id',
                (provenance->>'runtime_writer_generation')::bigint,
                (provenance->>'configuration_activation_generation')::bigint,
                provenance->>'source_epoch',
                provenance->>'ruleset_revision_id',
                provenance->>'rule_id',
                (provenance->>'rule_revision')::integer,
                provenance->>'rule_revision_sha256',
                provenance->>'ruleset_sha256',
                provenance->>'site_config_sha256',
                provenance->>'model_gate_decision_sha256',
                provenance->>'gate_mode',
                provenance->>'body_sha256',
                CURRENT_TIMESTAMP
            );
            RETURN candidate->>'event_id';
        END;
        $$;
        """
    )
    op.execute(
        """
        REVOKE ALL ON FUNCTION pilot_reject_reviewed_revision_mutation()
        FROM PUBLIC
        """
    )
    op.execute(
        """
        REVOKE ALL ON FUNCTION pilot_validate_candidate_provenance()
        FROM PUBLIC
        """
    )
    op.execute(
        """
        REVOKE ALL ON FUNCTION pilot_validate_legacy_candidate_import()
        FROM PUBLIC
        """
    )
    op.execute(
        """
        REVOKE ALL ON FUNCTION pilot_ingest_candidate(jsonb, jsonb)
        FROM PUBLIC
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
          IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kuzet_runtime') THEN
            GRANT USAGE ON SCHEMA public TO kuzet_runtime;
            GRANT SELECT ON TABLE
              sites,
              cameras,
              model_artifacts,
              site_config_revisions,
              camera_ruleset_revisions,
              camera_rule_revisions,
              configuration_activations,
              active_pilot_configurations,
              runtime_writer_authorities,
              runtime_writer_sessions,
              camera_epoch_authorities,
              candidate_events,
              candidate_event_provenance
              TO kuzet_runtime;
            REVOKE INSERT, UPDATE, DELETE ON TABLE candidate_events
              FROM kuzet_runtime;
            REVOKE INSERT, UPDATE, DELETE ON TABLE candidate_event_provenance
              FROM kuzet_runtime;
            REVOKE INSERT, UPDATE, DELETE ON TABLE
              site_config_revisions,
              camera_ruleset_revisions,
              camera_rule_revisions,
              configuration_activations,
              active_pilot_configurations,
              runtime_writer_authorities,
              runtime_writer_sessions,
              camera_epoch_authorities,
              camera_epoch_history,
              legacy_candidate_imports
              FROM kuzet_runtime;
            GRANT EXECUTE ON FUNCTION pilot_ingest_candidate(jsonb, jsonb)
              TO kuzet_runtime;
          END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    connection = op.get_bind()
    provenance_count = connection.execute(
        sa.text("SELECT COUNT(*) FROM candidate_event_provenance")
    ).scalar_one()
    if provenance_count:
        raise RuntimeError(
            "0006 downgrade refused: provenance-bearing candidates must be retained"
        )
    unmarked_count = connection.execute(
        sa.text(
            """
            SELECT COUNT(*)
              FROM candidate_events AS candidate
              LEFT JOIN legacy_candidate_imports AS legacy
                ON legacy.event_id = candidate.event_id
             WHERE legacy.event_id IS NULL
            """
        )
    ).scalar_one()
    if unmarked_count:
        raise RuntimeError(
            "0006 downgrade refused: post-cutoff candidates lack legacy markers"
        )

    dialect = connection.dialect.name
    op.drop_index(
        "ix_candidate_provenance_runtime",
        table_name="candidate_event_provenance",
    )
    op.drop_table("candidate_event_provenance")
    if dialect == "postgresql":
        op.execute("DROP FUNCTION IF EXISTS pilot_ingest_candidate(jsonb, jsonb)")
        op.execute("DROP FUNCTION IF EXISTS pilot_validate_candidate_provenance()")
    op.drop_table("legacy_candidate_imports")
    if dialect == "postgresql":
        op.execute(
            "DROP FUNCTION IF EXISTS pilot_validate_legacy_candidate_import()"
        )
    op.drop_table("camera_epoch_authorities")
    op.drop_table("camera_epoch_history")
    op.drop_table("runtime_writer_sessions")
    op.drop_table("runtime_writer_authorities")
    op.drop_table("active_pilot_configurations")
    op.drop_table("configuration_activations")
    op.drop_table("camera_rule_revisions")
    op.drop_table("camera_ruleset_revisions")
    op.drop_table("site_config_revisions")
    if dialect == "postgresql":
        op.execute(
            "DROP FUNCTION IF EXISTS pilot_reject_reviewed_revision_mutation()"
        )
    with op.batch_alter_table("cameras") as batch:
        batch.drop_constraint("uq_cameras_site_camera", type_="unique")
