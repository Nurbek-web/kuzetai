"""Add durable, terminal preview publication and access persistence.

Revision ID: 0007_preview_persistence
Revises: 0006_event_provenance
Create Date: 2026-07-31
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0007_preview_persistence"
down_revision: Union[str, Sequence[str], None] = "0006_event_provenance"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    op.create_index(
        "uq_camera_epoch_history_site_identity",
        "camera_epoch_history",
        ["site_id", "camera_id", "source_epoch"],
        unique=True,
    )
    op.create_index(
        "uq_candidate_provenance_preview_authority",
        "candidate_event_provenance",
        [
            "event_id",
            "site_id",
            "runtime_session_id",
            "runtime_writer_generation",
            "configuration_activation_generation",
            "source_epoch",
            "rule_revision_sha256",
            "site_config_sha256",
            "body_sha256",
        ],
        unique=True,
    )
    op.create_table(
        "preview_publications",
        sa.Column("event_id", sa.String(length=36), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("camera_id", sa.String(length=128), nullable=False),
        sa.Column("evidence_id", sa.String(length=36), nullable=False),
        sa.Column("intent_schema_version", sa.String(length=64), nullable=False),
        sa.Column("publication_state", sa.String(length=16), nullable=False),
        sa.Column("object_key", sa.String(length=1024), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("configuration_sha256", sa.String(length=64), nullable=False),
        sa.Column("runtime_session_id", sa.String(length=128), nullable=False),
        sa.Column("runtime_writer_generation", sa.BigInteger(), nullable=False),
        sa.Column(
            "configuration_activation_generation",
            sa.BigInteger(),
            nullable=False,
        ),
        sa.Column("source_epoch", sa.String(length=36), nullable=False),
        sa.Column("rule_revision_sha256", sa.String(length=64), nullable=False),
        sa.Column("candidate_body_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "intent_created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "intent_expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("receipt_schema_version", sa.String(length=64), nullable=True),
        sa.Column("checksum_sha256", sa.String(length=44), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("media_type", sa.String(length=32), nullable=True),
        sa.Column("etag", sa.String(length=512), nullable=True),
        sa.Column("version_id", sa.String(length=1024), nullable=True),
        sa.Column(
            "server_side_encryption",
            sa.String(length=16),
            nullable=True,
        ),
        sa.Column("kms_key_id", sa.String(length=2048), nullable=True),
        sa.Column("receipt_sha256", sa.String(length=64), nullable=True),
        sa.Column(
            "receipt_created_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column("retiring_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "intent_schema_version = 'preview-publication-intent.v1'",
            name="ck_preview_intent_schema",
        ),
        sa.CheckConstraint(
            "publication_state IN ('reserved', 'ready', 'retiring', 'retired')",
            name="ck_preview_publication_state",
        ),
        sa.CheckConstraint(
            "length(sha256) = 64",
            name="ck_preview_publication_sha256",
        ),
        sa.CheckConstraint(
            "length(configuration_sha256) = 64",
            name="ck_preview_configuration_sha256",
        ),
        sa.CheckConstraint(
            "runtime_writer_generation > 0",
            name="ck_preview_writer_generation",
        ),
        sa.CheckConstraint(
            "configuration_activation_generation > 0",
            name="ck_preview_activation_generation",
        ),
        sa.CheckConstraint(
            "length(rule_revision_sha256) = 64",
            name="ck_preview_rule_sha256",
        ),
        sa.CheckConstraint(
            "length(candidate_body_sha256) = 64",
            name="ck_preview_candidate_body_sha256",
        ),
        sa.CheckConstraint(
            "intent_expires_at > intent_created_at",
            name="ck_preview_intent_time_range",
        ),
        sa.CheckConstraint(
            "receipt_schema_version IS NULL OR "
            "receipt_schema_version = 'preview-object-receipt.v1'",
            name="ck_preview_receipt_schema",
        ),
        sa.CheckConstraint(
            "size_bytes IS NULL OR "
            "(size_bytes > 0 AND size_bytes <= 16777216)",
            name="ck_preview_size_bound",
        ),
        sa.CheckConstraint(
            "media_type IS NULL OR media_type = 'video/mp4'",
            name="ck_preview_media_type",
        ),
        sa.CheckConstraint(
            "server_side_encryption IS NULL OR "
            "server_side_encryption IN ('AES256', 'aws:kms')",
            name="ck_preview_encryption",
        ),
        sa.CheckConstraint(
            "(server_side_encryption IS NULL AND kms_key_id IS NULL) OR "
            "(server_side_encryption = 'AES256' AND kms_key_id IS NULL) OR "
            "(server_side_encryption = 'aws:kms' AND kms_key_id IS NOT NULL)",
            name="ck_preview_kms_identity",
        ),
        sa.CheckConstraint(
            "receipt_sha256 IS NULL OR length(receipt_sha256) = 64",
            name="ck_preview_receipt_sha256",
        ),
        sa.ForeignKeyConstraint(
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
        sa.ForeignKeyConstraint(
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
        sa.ForeignKeyConstraint(
            ["site_id", "camera_id", "source_epoch"],
            [
                "camera_epoch_history.site_id",
                "camera_epoch_history.camera_id",
                "camera_epoch_history.source_epoch",
            ],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("event_id"),
        sa.UniqueConstraint(
            "site_id",
            "event_id",
            name="uq_preview_site_event",
        ),
        sa.UniqueConstraint(
            "evidence_id",
            name="uq_preview_evidence_identity",
        ),
        sa.UniqueConstraint(
            "object_key",
            name="uq_preview_object_identity",
        ),
        sa.UniqueConstraint(
            "receipt_sha256",
            name="uq_preview_receipt_identity",
        ),
        sa.UniqueConstraint(
            "site_id",
            "event_id",
            "receipt_sha256",
            name="uq_preview_access_authority",
        ),
    )
    op.create_index(
        "ix_preview_retention_claim",
        "preview_publications",
        ["site_id", "publication_state", "receipt_created_at", "event_id"],
    )
    op.create_index(
        "ix_preview_intent_expiry",
        "preview_publications",
        ["site_id", "publication_state", "intent_expires_at", "event_id"],
    )
    op.create_table(
        "preview_access_receipts",
        sa.Column("access_id", sa.String(length=36), nullable=False),
        sa.Column("schema_version", sa.String(length=64), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("event_id", sa.String(length=36), nullable=False),
        sa.Column("actor_id", sa.String(length=128), nullable=False),
        sa.Column("receipt_sha256", sa.String(length=64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "schema_version = 'preview-access-receipt.v1'",
            name="ck_preview_access_schema",
        ),
        sa.CheckConstraint(
            "length(receipt_sha256) = 64",
            name="ck_preview_access_receipt_sha256",
        ),
        sa.ForeignKeyConstraint(
            ["site_id"],
            ["sites.site_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["actor_id"],
            ["users.user_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["site_id", "event_id", "receipt_sha256"],
            [
                "preview_publications.site_id",
                "preview_publications.event_id",
                "preview_publications.receipt_sha256",
            ],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("access_id"),
    )
    op.create_index(
        "ix_preview_access_site_occurred",
        "preview_access_receipts",
        ["site_id", "occurred_at", "access_id"],
    )

    if dialect == "sqlite":
        _create_sqlite_guards()
    elif dialect == "postgresql":
        _create_postgresql_contracts()
    else:
        raise RuntimeError(
            "preview persistence supports only SQLite tests and PostgreSQL pilot"
        )


def _create_sqlite_guards() -> None:
    op.execute(
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
    )
    op.execute(
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
            'preview publication material is immutable; '
            || 'preview publication cannot be resurrected'
          );
        END
        """
    )
    op.execute(
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
    )
    op.execute(
        """
        CREATE TRIGGER trg_preview_access_update_guard
        BEFORE UPDATE ON preview_access_receipts
        FOR EACH ROW
        BEGIN
          SELECT RAISE(ABORT, 'preview access receipts are append-only');
        END
        """
    )


def _create_postgresql_contracts() -> None:
    op.execute(
        """
        CREATE FUNCTION pilot_validate_preview_publication_insert()
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
    )
    op.execute(
        """
        CREATE FUNCTION pilot_guard_preview_publication_mutation()
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
    )
    op.execute(
        """
        CREATE FUNCTION pilot_guard_preview_access_mutation()
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
    )
    op.execute(
        """
        CREATE TRIGGER trg_preview_publication_insert_guard
        BEFORE INSERT ON preview_publications
        FOR EACH ROW
        EXECUTE FUNCTION pilot_validate_preview_publication_insert()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_preview_publication_mutation_guard
        BEFORE UPDATE OR DELETE ON preview_publications
        FOR EACH ROW
        EXECUTE FUNCTION pilot_guard_preview_publication_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_preview_access_update_guard
        BEFORE UPDATE ON preview_access_receipts
        FOR EACH ROW
        EXECUTE FUNCTION pilot_guard_preview_access_mutation()
        """
    )
    _create_postgresql_runtime_functions()
    _create_postgresql_api_functions()
    _create_postgresql_retention_functions()
    _restrict_postgresql_roles()


def _create_postgresql_runtime_functions() -> None:
    op.execute(
        """
        CREATE FUNCTION pilot_get_active_site_config_sha256(p_site_id text)
        RETURNS text
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
          result text;
        BEGIN
          IF p_site_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
            RAISE EXCEPTION USING
              ERRCODE = '22023',
              MESSAGE = 'preview site identity is invalid';
          END IF;
          SELECT config.config_sha256
            INTO result
            FROM public.active_pilot_configurations AS active
            JOIN public.site_config_revisions AS config
              ON config.site_id = active.site_id
             AND config.config_revision_id = active.config_revision_id
           WHERE active.site_id = p_site_id;
          IF result IS NULL THEN
            RAISE EXCEPTION USING
              ERRCODE = '23514',
              MESSAGE = 'active reviewed configuration is unavailable';
          END IF;
          RETURN result;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION pilot_get_preview_object_context(
          p_site_id text,
          p_event_id uuid,
          p_evidence_id uuid,
          p_source_epoch uuid
        )
        RETURNS jsonb
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
          candidate public.candidate_events%ROWTYPE;
          camera public.cameras%ROWTYPE;
          provenance public.candidate_event_provenance%ROWTYPE;
          active public.active_pilot_configurations%ROWTYPE;
          config public.site_config_revisions%ROWTYPE;
          writer public.runtime_writer_authorities%ROWTYPE;
          epoch public.camera_epoch_authorities%ROWTYPE;
          rule public.camera_rule_revisions%ROWTYPE;
        BEGIN
          IF p_site_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
            RAISE EXCEPTION USING
              ERRCODE = '22023',
              MESSAGE = 'preview context site identity is invalid';
          END IF;
          SELECT * INTO candidate
            FROM public.candidate_events
           WHERE event_id = p_event_id::text
           FOR SHARE;
          IF candidate.event_id IS NULL THEN
            RAISE EXCEPTION USING
              ERRCODE = '23503',
              MESSAGE = 'preview candidate event is unavailable';
          END IF;
          SELECT * INTO camera
            FROM public.cameras
           WHERE camera_id = candidate.camera_id
           FOR SHARE;
          SELECT * INTO provenance
            FROM public.candidate_event_provenance
           WHERE event_id = candidate.event_id
           FOR SHARE;
          SELECT * INTO active
            FROM public.active_pilot_configurations
           WHERE site_id = p_site_id
           FOR SHARE;
          SELECT * INTO writer
            FROM public.runtime_writer_authorities
           WHERE site_id = p_site_id
           FOR SHARE;
          SELECT * INTO epoch
            FROM public.camera_epoch_authorities
           WHERE camera_id = candidate.camera_id
           FOR SHARE;
          IF active.config_revision_id IS NOT NULL THEN
            SELECT * INTO config
              FROM public.site_config_revisions
             WHERE config_revision_id = active.config_revision_id
             FOR SHARE;
          END IF;
          IF provenance.ruleset_revision_id IS NOT NULL THEN
            SELECT * INTO rule
              FROM public.camera_rule_revisions
             WHERE ruleset_revision_id = provenance.ruleset_revision_id
               AND rule_id = provenance.rule_id
             FOR SHARE;
          END IF;
          IF camera.site_id IS DISTINCT FROM p_site_id
             OR candidate.evidence_status <> 'pending'
             OR candidate.review_status <> 'candidate'
             OR candidate.transition_history <> 'observation>candidate'
             OR provenance.event_id IS NULL
             OR provenance.site_id IS DISTINCT FROM p_site_id
             OR provenance.source_epoch IS DISTINCT FROM
                p_source_epoch::text
             OR active.activation_generation IS DISTINCT FROM
                provenance.configuration_activation_generation
             OR active.ruleset_revision_id IS DISTINCT FROM
                provenance.ruleset_revision_id
             OR config.site_id IS DISTINCT FROM p_site_id
             OR config.config_sha256 IS DISTINCT FROM
                provenance.site_config_sha256
             OR writer.runtime_session_id IS DISTINCT FROM
                provenance.runtime_session_id
             OR writer.writer_generation IS DISTINCT FROM
                provenance.runtime_writer_generation
             OR writer.configuration_activation_generation IS DISTINCT FROM
                provenance.configuration_activation_generation
             OR epoch.site_id IS DISTINCT FROM p_site_id
             OR epoch.source_epoch IS DISTINCT FROM p_source_epoch::text
             OR epoch.runtime_session_id IS DISTINCT FROM
                provenance.runtime_session_id
             OR epoch.writer_generation IS DISTINCT FROM
                provenance.runtime_writer_generation
             OR epoch.configuration_activation_generation IS DISTINCT FROM
                provenance.configuration_activation_generation
             OR rule.site_id IS DISTINCT FROM p_site_id
             OR rule.camera_id IS DISTINCT FROM candidate.camera_id
             OR NOT rule.enabled
             OR rule.revision IS DISTINCT FROM provenance.rule_revision
             OR rule.rule_revision_sha256 IS DISTINCT FROM
                provenance.rule_revision_sha256
             OR rule.model_decision_sha256 IS DISTINCT FROM
                provenance.model_gate_decision_sha256
             OR rule.module IS DISTINCT FROM candidate.module
             OR rule.model_artifact_id IS DISTINCT FROM
                candidate.model_artifact_id
             OR rule.gate_mode IS DISTINCT FROM candidate.gate_mode
             OR rule.gate_mode IS DISTINCT FROM provenance.gate_mode
             OR EXISTS (
               SELECT 1
                 FROM public.evidence
                WHERE evidence_id = p_evidence_id::text
                  AND event_id <> p_event_id::text
             ) THEN
            RAISE EXCEPTION USING
              ERRCODE = '23514',
              MESSAGE = 'preview context lacks exact current candidate authority';
          END IF;
          RETURN jsonb_build_object(
            'site_id', p_site_id,
            'event_id', p_event_id::text,
            'evidence_id', p_evidence_id::text,
            'configuration_sha256', provenance.site_config_sha256,
            'runtime_session_id', provenance.runtime_session_id,
            'runtime_writer_generation',
              provenance.runtime_writer_generation,
            'configuration_activation_generation',
              provenance.configuration_activation_generation,
            'source_epoch', p_source_epoch::text,
            'rule_revision_sha256', provenance.rule_revision_sha256,
            'candidate_body_sha256', provenance.body_sha256
          );
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION pilot_prepare_preview_publication(p_intent jsonb)
        RETURNS jsonb
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
          candidate public.candidate_events%ROWTYPE;
          camera public.cameras%ROWTYPE;
          provenance public.candidate_event_provenance%ROWTYPE;
          active public.active_pilot_configurations%ROWTYPE;
          config public.site_config_revisions%ROWTYPE;
          writer public.runtime_writer_authorities%ROWTYPE;
          epoch public.camera_epoch_authorities%ROWTYPE;
          existing public.preview_publications%ROWTYPE;
          event_uuid uuid;
          evidence_uuid uuid;
          source_uuid uuid;
          created_at timestamptz;
          expires_at timestamptz;
          expected_keys text[] := ARRAY[
            'candidate_body_sha256',
            'configuration_activation_generation',
            'configuration_sha256',
            'created_at',
            'event_id',
            'evidence_id',
            'expires_at',
            'object_key',
            'rule_revision_sha256',
            'runtime_session_id',
            'runtime_writer_generation',
            'schema_version',
            'sha256',
            'site_id',
            'source_epoch'
          ];
        BEGIN
          IF jsonb_typeof(p_intent) <> 'object'
             OR (
               SELECT array_agg(key ORDER BY key)
                 FROM jsonb_object_keys(p_intent) AS key
             ) <> expected_keys
             OR p_intent->>'schema_version'
                <> 'preview-publication-intent.v1'
             OR jsonb_typeof(p_intent->'site_id') <> 'string'
             OR jsonb_typeof(p_intent->'event_id') <> 'string'
             OR jsonb_typeof(p_intent->'evidence_id') <> 'string'
             OR jsonb_typeof(p_intent->'object_key') <> 'string'
             OR jsonb_typeof(p_intent->'sha256') <> 'string'
             OR jsonb_typeof(p_intent->'configuration_sha256') <> 'string'
             OR jsonb_typeof(p_intent->'runtime_session_id') <> 'string'
             OR jsonb_typeof(
                  p_intent->'runtime_writer_generation'
                ) <> 'number'
             OR jsonb_typeof(
                  p_intent->'configuration_activation_generation'
                ) <> 'number'
             OR jsonb_typeof(p_intent->'source_epoch') <> 'string'
             OR jsonb_typeof(
                  p_intent->'rule_revision_sha256'
                ) <> 'string'
             OR jsonb_typeof(
                  p_intent->'candidate_body_sha256'
                ) <> 'string'
             OR jsonb_typeof(p_intent->'created_at') <> 'string'
             OR jsonb_typeof(p_intent->'expires_at') <> 'string' THEN
            RAISE EXCEPTION USING
              ERRCODE = '22023',
              MESSAGE = 'preview publication intent shape is invalid';
          END IF;
          IF p_intent->>'site_id'
                !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
             OR p_intent->>'runtime_session_id'
                !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
             OR p_intent->>'sha256' !~ '^[a-f0-9]{64}$'
             OR p_intent->>'configuration_sha256'
                !~ '^[a-f0-9]{64}$'
             OR p_intent->>'rule_revision_sha256'
                !~ '^[a-f0-9]{64}$'
             OR p_intent->>'candidate_body_sha256'
                !~ '^[a-f0-9]{64}$'
             OR (p_intent->>'runtime_writer_generation') !~ '^[1-9][0-9]*$'
             OR (p_intent->>'configuration_activation_generation')
                !~ '^[1-9][0-9]*$' THEN
            RAISE EXCEPTION USING
              ERRCODE = '22023',
              MESSAGE = 'preview publication intent values are invalid';
          END IF;
          event_uuid := (p_intent->>'event_id')::uuid;
          evidence_uuid := (p_intent->>'evidence_id')::uuid;
          source_uuid := (p_intent->>'source_epoch')::uuid;
          created_at := (p_intent->>'created_at')::timestamptz;
          expires_at := (p_intent->>'expires_at')::timestamptz;
          IF p_intent->>'created_at'
                !~ '(Z|[+-][0-9]{2}:[0-9]{2})$'
             OR p_intent->>'expires_at'
                !~ '(Z|[+-][0-9]{2}:[0-9]{2})$'
             OR expires_at <= created_at
             OR expires_at > created_at + interval '1 hour'
             OR expires_at <= clock_timestamp()
             OR created_at > clock_timestamp() + interval '5 minutes'
             OR created_at < clock_timestamp() - interval '5 minutes'
             OR length(p_intent->>'object_key') > 1024
             OR p_intent->>'object_key' <> (
               p_intent->>'site_id' || '/' || event_uuid::text || '/' ||
               evidence_uuid::text || '/' || p_intent->>'sha256' || '.mp4'
             ) THEN
            RAISE EXCEPTION USING
              ERRCODE = '22023',
              MESSAGE = 'preview publication intent is expired or noncanonical';
          END IF;
          SELECT *
            INTO candidate
            FROM public.candidate_events
           WHERE event_id = event_uuid::text
           FOR UPDATE;
          IF NOT FOUND THEN
            RAISE EXCEPTION USING
              ERRCODE = '23503',
              MESSAGE = 'preview candidate event is unavailable';
          END IF;
          SELECT * INTO camera
            FROM public.cameras
           WHERE camera_id = candidate.camera_id
           FOR SHARE;
          SELECT * INTO provenance
            FROM public.candidate_event_provenance
           WHERE event_id = event_uuid::text
           FOR SHARE;
          SELECT * INTO active
            FROM public.active_pilot_configurations
           WHERE site_id = p_intent->>'site_id'
           FOR UPDATE;
          SELECT * INTO writer
            FROM public.runtime_writer_authorities
           WHERE site_id = p_intent->>'site_id'
           FOR UPDATE;
          SELECT * INTO epoch
            FROM public.camera_epoch_authorities
           WHERE camera_id = candidate.camera_id
           FOR UPDATE;
          IF active.config_revision_id IS NOT NULL THEN
            SELECT * INTO config
              FROM public.site_config_revisions
             WHERE config_revision_id = active.config_revision_id
             FOR SHARE;
          END IF;
          IF camera.site_id IS DISTINCT FROM p_intent->>'site_id'
             OR candidate.evidence_status <> 'pending'
             OR candidate.review_status <> 'candidate'
             OR candidate.transition_history <> 'observation>candidate'
             OR provenance.event_id IS NULL
             OR provenance.site_id IS DISTINCT FROM p_intent->>'site_id'
             OR provenance.runtime_session_id IS DISTINCT FROM
                p_intent->>'runtime_session_id'
             OR provenance.runtime_writer_generation IS DISTINCT FROM
                (p_intent->>'runtime_writer_generation')::bigint
             OR provenance.configuration_activation_generation
                IS DISTINCT FROM
                (p_intent->>'configuration_activation_generation')::bigint
             OR provenance.source_epoch IS DISTINCT FROM source_uuid::text
             OR provenance.site_config_sha256 IS DISTINCT FROM
                p_intent->>'configuration_sha256'
             OR provenance.rule_revision_sha256 IS DISTINCT FROM
                p_intent->>'rule_revision_sha256'
             OR provenance.body_sha256 IS DISTINCT FROM
                p_intent->>'candidate_body_sha256'
             OR active.activation_generation IS DISTINCT FROM
                (p_intent->>'configuration_activation_generation')::bigint
             OR active.ruleset_revision_id IS DISTINCT FROM
                provenance.ruleset_revision_id
             OR config.site_id IS DISTINCT FROM p_intent->>'site_id'
             OR config.config_sha256 IS DISTINCT FROM
                p_intent->>'configuration_sha256'
             OR writer.runtime_session_id IS DISTINCT FROM
                p_intent->>'runtime_session_id'
             OR writer.writer_generation IS DISTINCT FROM
                (p_intent->>'runtime_writer_generation')::bigint
             OR writer.configuration_activation_generation IS DISTINCT FROM
                (p_intent->>'configuration_activation_generation')::bigint
             OR epoch.site_id IS DISTINCT FROM p_intent->>'site_id'
             OR epoch.source_epoch IS DISTINCT FROM source_uuid::text
             OR epoch.runtime_session_id IS DISTINCT FROM
                p_intent->>'runtime_session_id'
             OR epoch.writer_generation IS DISTINCT FROM
                (p_intent->>'runtime_writer_generation')::bigint
             OR epoch.configuration_activation_generation IS DISTINCT FROM
                (p_intent->>'configuration_activation_generation')::bigint
             OR NOT EXISTS (
               SELECT 1
                 FROM public.camera_rule_revisions AS rule
                WHERE rule.ruleset_revision_id =
                      provenance.ruleset_revision_id
                  AND rule.rule_id = provenance.rule_id
                  AND rule.site_id = provenance.site_id
                  AND rule.camera_id = candidate.camera_id
                  AND rule.enabled
                  AND rule.revision = provenance.rule_revision
                  AND rule.rule_revision_sha256 =
                      p_intent->>'rule_revision_sha256'
                  AND rule.model_decision_sha256 =
                      provenance.model_gate_decision_sha256
                  AND rule.module = candidate.module
                  AND rule.model_artifact_id = candidate.model_artifact_id
                  AND rule.gate_mode = candidate.gate_mode
                  AND rule.gate_mode = provenance.gate_mode
             ) THEN
            RAISE EXCEPTION USING
              ERRCODE = '23514',
              MESSAGE = 'preview context lacks exact current candidate authority';
          END IF;
          IF EXISTS (
            SELECT 1
              FROM public.evidence
             WHERE evidence_id = evidence_uuid::text
               AND event_id <> event_uuid::text
          ) THEN
            RAISE EXCEPTION USING
              ERRCODE = '23505',
              MESSAGE = 'preview evidence identity belongs to another event';
          END IF;
          SELECT * INTO existing
            FROM public.preview_publications
           WHERE event_id = event_uuid::text
           FOR UPDATE;
          IF existing.event_id IS NOT NULL THEN
            IF existing.site_id IS DISTINCT FROM p_intent->>'site_id'
               OR existing.evidence_id IS DISTINCT FROM evidence_uuid::text
               OR existing.object_key IS DISTINCT FROM
                  p_intent->>'object_key'
               OR existing.sha256 IS DISTINCT FROM p_intent->>'sha256'
               OR existing.configuration_sha256 IS DISTINCT FROM
                  p_intent->>'configuration_sha256'
               OR existing.runtime_session_id IS DISTINCT FROM
                  p_intent->>'runtime_session_id'
               OR existing.runtime_writer_generation IS DISTINCT FROM
                  (p_intent->>'runtime_writer_generation')::bigint
               OR existing.configuration_activation_generation
                  IS DISTINCT FROM
                  (p_intent->>'configuration_activation_generation')::bigint
               OR existing.source_epoch IS DISTINCT FROM source_uuid::text
               OR existing.rule_revision_sha256 IS DISTINCT FROM
                  p_intent->>'rule_revision_sha256'
               OR existing.candidate_body_sha256 IS DISTINCT FROM
                  p_intent->>'candidate_body_sha256' THEN
              RAISE EXCEPTION USING
                ERRCODE = '23505',
                MESSAGE =
                  'preview identity was reused with different material';
            END IF;
            IF existing.publication_state IN ('retiring', 'retired')
               OR (
                 existing.publication_state = 'reserved'
                 AND created_at >= existing.intent_expires_at
               ) THEN
              RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'terminal preview cannot be resurrected';
            END IF;
            RETURN jsonb_build_object(
              'schema_version', existing.intent_schema_version,
              'site_id', existing.site_id,
              'event_id', existing.event_id,
              'evidence_id', existing.evidence_id,
              'object_key', existing.object_key,
              'sha256', existing.sha256,
              'configuration_sha256', existing.configuration_sha256,
              'runtime_session_id', existing.runtime_session_id,
              'runtime_writer_generation',
                existing.runtime_writer_generation,
              'configuration_activation_generation',
                existing.configuration_activation_generation,
              'source_epoch', existing.source_epoch,
              'rule_revision_sha256', existing.rule_revision_sha256,
              'candidate_body_sha256', existing.candidate_body_sha256,
              'created_at', existing.intent_created_at,
              'expires_at', existing.intent_expires_at
            );
          END IF;
          IF EXISTS (
            SELECT 1 FROM public.preview_publications
             WHERE evidence_id = evidence_uuid::text
                OR object_key = p_intent->>'object_key'
          ) THEN
            RAISE EXCEPTION USING
              ERRCODE = '23505',
              MESSAGE = 'preview identity is already reserved';
          END IF;
          INSERT INTO public.preview_publications (
            event_id, site_id, camera_id, evidence_id,
            intent_schema_version, publication_state, object_key, sha256,
            configuration_sha256, runtime_session_id,
            runtime_writer_generation, configuration_activation_generation,
            source_epoch, rule_revision_sha256, candidate_body_sha256,
            intent_created_at, intent_expires_at
          ) VALUES (
            event_uuid::text, p_intent->>'site_id', candidate.camera_id,
            evidence_uuid::text, p_intent->>'schema_version', 'reserved',
            p_intent->>'object_key', p_intent->>'sha256',
            p_intent->>'configuration_sha256',
            p_intent->>'runtime_session_id',
            (p_intent->>'runtime_writer_generation')::bigint,
            (p_intent->>'configuration_activation_generation')::bigint,
            source_uuid::text, p_intent->>'rule_revision_sha256',
            p_intent->>'candidate_body_sha256', created_at, expires_at
          );
          RETURN p_intent;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION pilot_finalize_preview_receipt(
          p_intent jsonb,
          p_receipt jsonb
        )
        RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
          publication public.preview_publications%ROWTYPE;
          event_uuid uuid;
          canonical_receipt jsonb;
          intent_keys text[] := ARRAY[
            'candidate_body_sha256',
            'configuration_activation_generation',
            'configuration_sha256',
            'created_at',
            'event_id',
            'evidence_id',
            'expires_at',
            'object_key',
            'rule_revision_sha256',
            'runtime_session_id',
            'runtime_writer_generation',
            'schema_version',
            'sha256',
            'site_id',
            'source_epoch'
          ];
          expected_keys text[] := ARRAY[
            'candidate_body_sha256',
            'checksum_sha256',
            'configuration_activation_generation',
            'configuration_sha256',
            'created_at',
            'etag',
            'event_id',
            'evidence_id',
            'kms_key_id',
            'media_type',
            'object_key',
            'receipt_canonical_json',
            'receipt_sha256',
            'rule_revision_sha256',
            'runtime_session_id',
            'runtime_writer_generation',
            'schema_version',
            'server_side_encryption',
            'sha256',
            'site_id',
            'size_bytes',
            'source_epoch',
            'version_id'
          ];
        BEGIN
          IF jsonb_typeof(p_intent) <> 'object'
             OR jsonb_typeof(p_receipt) <> 'object'
             OR (
               SELECT array_agg(key ORDER BY key)
                 FROM jsonb_object_keys(p_intent) AS key
             ) <> intent_keys
             OR (
               SELECT array_agg(key ORDER BY key)
                 FROM jsonb_object_keys(p_receipt) AS key
             ) <> expected_keys
             OR p_receipt->>'schema_version'
                <> 'preview-object-receipt.v1'
             OR p_intent->>'schema_version'
                <> 'preview-publication-intent.v1'
             OR jsonb_typeof(p_intent->'site_id') <> 'string'
             OR jsonb_typeof(p_intent->'event_id') <> 'string'
             OR jsonb_typeof(p_intent->'evidence_id') <> 'string'
             OR jsonb_typeof(p_intent->'object_key') <> 'string'
             OR jsonb_typeof(p_intent->'sha256') <> 'string'
             OR jsonb_typeof(p_intent->'configuration_sha256') <> 'string'
             OR jsonb_typeof(p_intent->'runtime_session_id') <> 'string'
             OR jsonb_typeof(
                  p_intent->'runtime_writer_generation'
                ) <> 'number'
             OR jsonb_typeof(
                  p_intent->'configuration_activation_generation'
                ) <> 'number'
             OR jsonb_typeof(p_intent->'source_epoch') <> 'string'
             OR jsonb_typeof(
                  p_intent->'rule_revision_sha256'
                ) <> 'string'
             OR jsonb_typeof(
                  p_intent->'candidate_body_sha256'
                ) <> 'string'
             OR jsonb_typeof(p_intent->'created_at') <> 'string'
             OR jsonb_typeof(p_intent->'expires_at') <> 'string'
             OR (p_intent->>'runtime_writer_generation')
                !~ '^[1-9][0-9]*$'
             OR (p_intent->>'configuration_activation_generation')
                !~ '^[1-9][0-9]*$'
             OR jsonb_typeof(p_receipt->'site_id') <> 'string'
             OR jsonb_typeof(p_receipt->'event_id') <> 'string'
             OR jsonb_typeof(p_receipt->'evidence_id') <> 'string'
             OR jsonb_typeof(p_receipt->'object_key') <> 'string'
             OR jsonb_typeof(p_receipt->'sha256') <> 'string'
             OR jsonb_typeof(
                  p_receipt->'checksum_sha256'
                ) <> 'string'
             OR jsonb_typeof(p_receipt->'size_bytes') <> 'number'
             OR jsonb_typeof(p_receipt->'media_type') <> 'string'
             OR jsonb_typeof(p_receipt->'etag') <> 'string'
             OR jsonb_typeof(p_receipt->'version_id') <> 'string'
             OR jsonb_typeof(
                  p_receipt->'server_side_encryption'
                ) <> 'string'
             OR jsonb_typeof(
                  p_receipt->'configuration_sha256'
                ) <> 'string'
             OR jsonb_typeof(
                  p_receipt->'runtime_session_id'
                ) <> 'string'
             OR jsonb_typeof(
                  p_receipt->'runtime_writer_generation'
                ) <> 'number'
             OR jsonb_typeof(
                  p_receipt->'configuration_activation_generation'
                ) <> 'number'
             OR jsonb_typeof(p_receipt->'source_epoch') <> 'string'
             OR jsonb_typeof(
                  p_receipt->'rule_revision_sha256'
                ) <> 'string'
             OR jsonb_typeof(
                  p_receipt->'candidate_body_sha256'
                ) <> 'string'
             OR jsonb_typeof(p_receipt->'created_at') <> 'string'
             OR jsonb_typeof(
                  p_receipt->'receipt_sha256'
                ) <> 'string'
             OR jsonb_typeof(
                  p_receipt->'receipt_canonical_json'
                ) <> 'string'
             OR (p_receipt->>'size_bytes') !~ '^[1-9][0-9]*$'
             OR (p_receipt->>'runtime_writer_generation')
                !~ '^[1-9][0-9]*$'
             OR (p_receipt->>'configuration_activation_generation')
                !~ '^[1-9][0-9]*$'
             OR (p_receipt->>'size_bytes')::bigint > 16777216
             OR p_receipt->>'media_type' <> 'video/mp4'
             OR p_receipt->>'sha256' !~ '^[a-f0-9]{64}$'
             OR p_receipt->>'receipt_sha256' !~ '^[a-f0-9]{64}$'
             OR p_intent->>'created_at'
                !~ '(Z|[+-][0-9]{2}:[0-9]{2})$'
             OR p_intent->>'expires_at'
                !~ '(Z|[+-][0-9]{2}:[0-9]{2})$'
             OR p_receipt->>'created_at'
                !~ '(Z|[+-][0-9]{2}:[0-9]{2})$'
             OR p_receipt->>'checksum_sha256' <>
                encode(decode(p_receipt->>'sha256', 'hex'), 'base64')
             OR p_receipt->>'receipt_sha256' <>
                encode(
                  sha256(
                    convert_to(
                      p_receipt->>'receipt_canonical_json',
                      'UTF8'
                    )
                  ),
                  'hex'
                ) THEN
            RAISE EXCEPTION USING
              ERRCODE = '22023',
              MESSAGE = 'preview receipt shape or digest is invalid';
          END IF;
          canonical_receipt :=
            (p_receipt->>'receipt_canonical_json')::jsonb;
          IF canonical_receipt IS DISTINCT FROM
             (p_receipt - 'receipt_sha256' - 'receipt_canonical_json') THEN
            RAISE EXCEPTION USING
              ERRCODE = '22023',
              MESSAGE = 'preview receipt canonical body is invalid';
          END IF;
          IF p_receipt->>'server_side_encryption'
                NOT IN ('AES256', 'aws:kms')
             OR (
               p_receipt->>'server_side_encryption' = 'AES256'
               AND jsonb_typeof(p_receipt->'kms_key_id') <> 'null'
             )
             OR (
               p_receipt->>'server_side_encryption' = 'aws:kms'
               AND (
                 jsonb_typeof(p_receipt->'kms_key_id') <> 'string'
                 OR length(p_receipt->>'kms_key_id') NOT BETWEEN 1 AND 2048
               )
             )
             OR length(p_receipt->>'etag') NOT BETWEEN 1 AND 512
             OR length(p_receipt->>'version_id') NOT BETWEEN 1 AND 1024
             OR p_receipt->>'etag' ~ '[[:cntrl:]]'
             OR p_receipt->>'version_id' ~ '[[:cntrl:]]'
             OR (
               p_receipt->>'kms_key_id' IS NOT NULL
               AND p_receipt->>'kms_key_id' ~ '[[:cntrl:]]'
             ) THEN
            RAISE EXCEPTION USING
              ERRCODE = '22023',
              MESSAGE = 'preview remote receipt identity is invalid';
          END IF;
          event_uuid := (p_receipt->>'event_id')::uuid;
          SELECT * INTO publication
            FROM public.preview_publications
           WHERE event_id = event_uuid::text
           FOR UPDATE;
          IF publication.event_id IS NULL THEN
            RAISE EXCEPTION USING
              ERRCODE = '23503',
              MESSAGE = 'preview publication intent is unavailable';
          END IF;
          IF publication.intent_schema_version IS DISTINCT FROM
                p_intent->>'schema_version'
             OR publication.site_id IS DISTINCT FROM p_intent->>'site_id'
             OR publication.event_id IS DISTINCT FROM p_intent->>'event_id'
             OR publication.evidence_id IS DISTINCT FROM
                p_intent->>'evidence_id'
             OR publication.object_key IS DISTINCT FROM
                p_intent->>'object_key'
             OR publication.sha256 IS DISTINCT FROM p_intent->>'sha256'
             OR publication.configuration_sha256 IS DISTINCT FROM
                p_intent->>'configuration_sha256'
             OR publication.runtime_session_id IS DISTINCT FROM
                p_intent->>'runtime_session_id'
             OR publication.runtime_writer_generation IS DISTINCT FROM
                (p_intent->>'runtime_writer_generation')::bigint
             OR publication.configuration_activation_generation
                IS DISTINCT FROM
                (p_intent->>'configuration_activation_generation')::bigint
             OR publication.source_epoch IS DISTINCT FROM
                p_intent->>'source_epoch'
             OR publication.rule_revision_sha256 IS DISTINCT FROM
                p_intent->>'rule_revision_sha256'
             OR publication.candidate_body_sha256 IS DISTINCT FROM
                p_intent->>'candidate_body_sha256'
             OR publication.intent_created_at IS DISTINCT FROM
                (p_intent->>'created_at')::timestamptz
             OR publication.intent_expires_at IS DISTINCT FROM
                (p_intent->>'expires_at')::timestamptz
             OR (p_receipt - 'receipt_sha256' - 'receipt_canonical_json')
                IS DISTINCT FROM canonical_receipt
             OR p_receipt->>'site_id' IS DISTINCT FROM publication.site_id
             OR p_receipt->>'event_id' IS DISTINCT FROM publication.event_id
             OR p_receipt->>'evidence_id' IS DISTINCT FROM
                publication.evidence_id
             OR p_receipt->>'object_key' IS DISTINCT FROM
                publication.object_key
             OR p_receipt->>'sha256' IS DISTINCT FROM publication.sha256
             OR p_receipt->>'configuration_sha256' IS DISTINCT FROM
                publication.configuration_sha256
             OR p_receipt->>'runtime_session_id' IS DISTINCT FROM
                publication.runtime_session_id
             OR (p_receipt->>'runtime_writer_generation')::bigint
                IS DISTINCT FROM publication.runtime_writer_generation
             OR (p_receipt->>'configuration_activation_generation')::bigint
                IS DISTINCT FROM
                publication.configuration_activation_generation
             OR p_receipt->>'source_epoch' IS DISTINCT FROM
                publication.source_epoch
             OR p_receipt->>'rule_revision_sha256' IS DISTINCT FROM
                publication.rule_revision_sha256
             OR p_receipt->>'candidate_body_sha256' IS DISTINCT FROM
                publication.candidate_body_sha256
             OR (p_receipt->>'created_at')::timestamptz IS DISTINCT FROM
                publication.intent_created_at THEN
            RAISE EXCEPTION USING
              ERRCODE = '23505',
              MESSAGE = 'preview receipt conflicts with immutable intent';
          END IF;
          IF publication.publication_state = 'ready' THEN
            IF publication.receipt_sha256 IS DISTINCT FROM
                 p_receipt->>'receipt_sha256'
               OR publication.version_id IS DISTINCT FROM
                 p_receipt->>'version_id'
               OR publication.etag IS DISTINCT FROM p_receipt->>'etag' THEN
              RAISE EXCEPTION USING
                ERRCODE = '23505',
                MESSAGE = 'preview receipt replay changed remote identity';
            END IF;
            RETURN true;
          END IF;
          IF publication.publication_state <> 'reserved'
             OR clock_timestamp() >= publication.intent_expires_at THEN
            RAISE EXCEPTION USING
              ERRCODE = '23514',
              MESSAGE = 'expired or terminal preview cannot be finalized';
          END IF;
          UPDATE public.preview_publications
             SET receipt_schema_version = p_receipt->>'schema_version',
                 checksum_sha256 = p_receipt->>'checksum_sha256',
                 size_bytes = (p_receipt->>'size_bytes')::bigint,
                 media_type = p_receipt->>'media_type',
                 etag = p_receipt->>'etag',
                 version_id = p_receipt->>'version_id',
                 server_side_encryption =
                   p_receipt->>'server_side_encryption',
                 kms_key_id = p_receipt->>'kms_key_id',
                 receipt_sha256 = p_receipt->>'receipt_sha256',
                 receipt_created_at =
                   (p_receipt->>'created_at')::timestamptz,
                 publication_state = 'ready'
           WHERE event_id = publication.event_id;
          RETURN true;
        END;
        $$
        """
    )


def _create_postgresql_api_functions() -> None:
    op.execute(
        """
        CREATE FUNCTION pilot_get_preview_receipt(
          p_site_id text,
          p_event_id uuid
        )
        RETURNS jsonb
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
          SELECT jsonb_build_object(
            'schema_version', publication.receipt_schema_version,
            'site_id', publication.site_id,
            'event_id', publication.event_id,
            'evidence_id', publication.evidence_id,
            'object_key', publication.object_key,
            'sha256', publication.sha256,
            'checksum_sha256', publication.checksum_sha256,
            'size_bytes', publication.size_bytes,
            'media_type', publication.media_type,
            'etag', publication.etag,
            'version_id', publication.version_id,
            'server_side_encryption',
              publication.server_side_encryption,
            'kms_key_id', publication.kms_key_id,
            'configuration_sha256', publication.configuration_sha256,
            'runtime_session_id', publication.runtime_session_id,
            'runtime_writer_generation',
              publication.runtime_writer_generation,
            'configuration_activation_generation',
              publication.configuration_activation_generation,
            'source_epoch', publication.source_epoch,
            'rule_revision_sha256', publication.rule_revision_sha256,
            'candidate_body_sha256', publication.candidate_body_sha256,
            'created_at', publication.receipt_created_at,
            'receipt_sha256', publication.receipt_sha256
          )
            FROM public.preview_publications AS publication
            JOIN public.candidate_events AS candidate
              ON candidate.event_id = publication.event_id
            JOIN public.cameras AS camera
              ON camera.camera_id = candidate.camera_id
            JOIN public.evidence AS evidence
              ON evidence.evidence_id = publication.evidence_id
             AND evidence.event_id = publication.event_id
           WHERE publication.site_id = p_site_id
             AND publication.event_id = p_event_id::text
             AND publication.publication_state = 'ready'
             AND camera.site_id = p_site_id
             AND candidate.evidence_status = 'ready'
             AND evidence.status = 'ready'
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION pilot_commit_preview_access(p_access jsonb)
        RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
          publication public.preview_publications%ROWTYPE;
          candidate public.candidate_events%ROWTYPE;
          evidence public.evidence%ROWTYPE;
          actor public.users%ROWTYPE;
          prior_access public.preview_access_receipts%ROWTYPE;
          prior_audit public.audit_entries%ROWTYPE;
          access_uuid uuid;
          event_uuid uuid;
          access_time timestamptz;
          requested_time timestamptz;
          audit_key text;
          audit_payload jsonb;
          expected_keys text[] := ARRAY[
            'access_id',
            'actor_id',
            'event_id',
            'occurred_at',
            'receipt_sha256',
            'schema_version',
            'site_id'
          ];
        BEGIN
          IF jsonb_typeof(p_access) <> 'object'
             OR (
               SELECT array_agg(key ORDER BY key)
                 FROM jsonb_object_keys(p_access) AS key
             ) <> expected_keys
             OR p_access->>'schema_version' <> 'preview-access-receipt.v1'
             OR jsonb_typeof(p_access->'access_id') <> 'string'
             OR jsonb_typeof(p_access->'site_id') <> 'string'
             OR jsonb_typeof(p_access->'event_id') <> 'string'
             OR jsonb_typeof(p_access->'actor_id') <> 'string'
             OR jsonb_typeof(
                  p_access->'receipt_sha256'
                ) <> 'string'
             OR jsonb_typeof(p_access->'occurred_at') <> 'string'
             OR p_access->>'site_id'
                !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
             OR p_access->>'actor_id'
                !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
             OR p_access->>'receipt_sha256' !~ '^[a-f0-9]{64}$'
             OR p_access->>'occurred_at'
                !~ '(Z|[+-][0-9]{2}:[0-9]{2})$' THEN
            RAISE EXCEPTION USING
              ERRCODE = '22023',
              MESSAGE = 'preview access receipt is invalid';
          END IF;
          access_uuid := (p_access->>'access_id')::uuid;
          event_uuid := (p_access->>'event_id')::uuid;
          requested_time := (p_access->>'occurred_at')::timestamptz;
          IF requested_time > clock_timestamp() + interval '5 minutes'
             OR requested_time < clock_timestamp() - interval '5 minutes' THEN
            RAISE EXCEPTION USING
              ERRCODE = '22023',
              MESSAGE = 'preview access time is outside server clock bounds';
          END IF;
          access_time := clock_timestamp();
          SELECT * INTO actor
            FROM public.users
           WHERE user_id = p_access->>'actor_id'
           FOR UPDATE;
          SELECT * INTO publication
            FROM public.preview_publications
           WHERE site_id = p_access->>'site_id'
             AND event_id = event_uuid::text
           FOR UPDATE;
          IF actor.user_id IS NULL
             OR NOT actor.is_active
             OR publication.event_id IS NULL
             OR publication.publication_state <> 'ready'
             OR publication.receipt_sha256 IS DISTINCT FROM
                p_access->>'receipt_sha256' THEN
            RETURN false;
          END IF;
          SELECT * INTO candidate
            FROM public.candidate_events
           WHERE event_id = publication.event_id
           FOR UPDATE;
          SELECT * INTO evidence
            FROM public.evidence
           WHERE evidence_id = publication.evidence_id
           FOR UPDATE;
          IF candidate.evidence_status IS DISTINCT FROM 'ready'
             OR evidence.evidence_id IS NULL
             OR evidence.event_id IS DISTINCT FROM publication.event_id
             OR evidence.status IS DISTINCT FROM 'ready' THEN
            RETURN false;
          END IF;
          audit_key := 'preview-access:' || access_uuid::text;
          audit_payload := jsonb_build_object(
            'schema_version', p_access->>'schema_version',
            'access_id', access_uuid::text,
            'receipt_sha256', p_access->>'receipt_sha256',
            'requested_at', p_access->>'occurred_at'
          );
          SELECT * INTO prior_access
            FROM public.preview_access_receipts
           WHERE access_id = access_uuid::text
           FOR SHARE;
          SELECT * INTO prior_audit
            FROM public.audit_entries
           WHERE idempotency_key = audit_key
           FOR SHARE;
          IF prior_access.access_id IS NOT NULL
             OR prior_audit.audit_id IS NOT NULL THEN
            IF prior_access.access_id IS NULL
               OR prior_audit.audit_id IS NULL
               OR prior_access.schema_version IS DISTINCT FROM
                  p_access->>'schema_version'
               OR prior_access.site_id IS DISTINCT FROM p_access->>'site_id'
               OR prior_access.event_id IS DISTINCT FROM event_uuid::text
               OR prior_access.actor_id IS DISTINCT FROM p_access->>'actor_id'
               OR prior_access.receipt_sha256 IS DISTINCT FROM
                  p_access->>'receipt_sha256'
               OR prior_audit.site_id IS DISTINCT FROM p_access->>'site_id'
               OR prior_audit.actor_user_id IS DISTINCT FROM
                  p_access->>'actor_id'
               OR prior_audit.action IS DISTINCT FROM 'preview.accessed'
               OR prior_audit.entity_type IS DISTINCT FROM 'candidate_event'
               OR prior_audit.entity_id IS DISTINCT FROM event_uuid::text
               OR prior_audit.payload IS DISTINCT FROM audit_payload
               OR prior_audit.occurred_at IS DISTINCT FROM
                  prior_access.occurred_at THEN
              RAISE EXCEPTION USING
                ERRCODE = '23505',
                MESSAGE = 'preview access identity conflicts with prior audit';
            END IF;
            RETURN true;
          END IF;
          INSERT INTO public.preview_access_receipts (
            access_id, schema_version, site_id, event_id, actor_id,
            receipt_sha256, occurred_at
          ) VALUES (
            access_uuid::text, p_access->>'schema_version',
            p_access->>'site_id', event_uuid::text, p_access->>'actor_id',
            p_access->>'receipt_sha256', access_time
          );
          INSERT INTO public.audit_entries (
            audit_id, site_id, occurred_at, actor_user_id, action,
            entity_type, entity_id, payload, idempotency_key
          ) VALUES (
            access_uuid::text, p_access->>'site_id', access_time,
            p_access->>'actor_id', 'preview.accessed', 'candidate_event',
            event_uuid::text, audit_payload, audit_key
          );
          RETURN true;
        END;
        $$
        """
    )


def _create_postgresql_retention_functions() -> None:
    op.execute(
        """
        CREATE FUNCTION pilot_claim_preview_receipts_for_retention(
          p_site_id text,
          p_cutoff_at timestamptz,
          p_limit integer
        )
        RETURNS jsonb
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
          publication public.preview_publications%ROWTYPE;
          result jsonb := '[]'::jsonb;
          retention_days integer;
          effective_cutoff timestamptz;
        BEGIN
          IF p_site_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
             OR p_cutoff_at IS NULL
             OR p_limit IS NULL
             OR NOT (p_limit BETWEEN 1 AND 1000) THEN
            RAISE EXCEPTION USING
              ERRCODE = '22023',
              MESSAGE = 'preview retention claim is invalid';
          END IF;
          SELECT (
                   config.canonical_config #>>
                   '{storage,retention,evidence_retention_days}'
                 )::integer
            INTO retention_days
            FROM public.active_pilot_configurations AS active
            JOIN public.site_config_revisions AS config
              ON config.config_revision_id = active.config_revision_id
             AND config.site_id = active.site_id
           WHERE active.site_id = p_site_id
           FOR SHARE OF config;
          IF retention_days IS NULL
             OR NOT (retention_days BETWEEN 1 AND 90) THEN
            RAISE EXCEPTION USING
              ERRCODE = '23514',
              MESSAGE = 'active evidence retention policy is unavailable';
          END IF;
          effective_cutoff := LEAST(
            p_cutoff_at,
            clock_timestamp() - make_interval(days => retention_days)
          );
          FOR publication IN
            SELECT *
              FROM public.preview_publications
             WHERE site_id = p_site_id
               AND (
                 publication_state = 'retiring'
                 OR (
                   publication_state = 'ready'
                   AND receipt_created_at <= effective_cutoff
                 )
               )
             ORDER BY publication_state DESC, receipt_created_at, event_id
             LIMIT p_limit
             FOR UPDATE SKIP LOCKED
          LOOP
            IF publication.publication_state = 'ready' THEN
              UPDATE public.preview_publications
                 SET publication_state = 'retiring',
                     retiring_at = GREATEST(
                       clock_timestamp(),
                       publication.receipt_created_at
                     )
               WHERE event_id = publication.event_id;
            END IF;
            result := result || jsonb_build_array(
              jsonb_build_object(
                'schema_version', publication.receipt_schema_version,
                'site_id', publication.site_id,
                'event_id', publication.event_id,
                'evidence_id', publication.evidence_id,
                'object_key', publication.object_key,
                'sha256', publication.sha256,
                'checksum_sha256', publication.checksum_sha256,
                'size_bytes', publication.size_bytes,
                'media_type', publication.media_type,
                'etag', publication.etag,
                'version_id', publication.version_id,
                'server_side_encryption',
                  publication.server_side_encryption,
                'kms_key_id', publication.kms_key_id,
                'configuration_sha256', publication.configuration_sha256,
                'runtime_session_id', publication.runtime_session_id,
                'runtime_writer_generation',
                  publication.runtime_writer_generation,
                'configuration_activation_generation',
                  publication.configuration_activation_generation,
                'source_epoch', publication.source_epoch,
                'rule_revision_sha256',
                  publication.rule_revision_sha256,
                'candidate_body_sha256',
                  publication.candidate_body_sha256,
                'created_at', publication.receipt_created_at,
                'receipt_sha256', publication.receipt_sha256
              )
            );
          END LOOP;
          RETURN result;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION pilot_finalize_preview_retirement(
          p_site_id text,
          p_event_id uuid,
          p_receipt_sha256 text,
          p_retired_at timestamptz
        )
        RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
          publication public.preview_publications%ROWTYPE;
        BEGIN
          IF p_site_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
             OR p_receipt_sha256 !~ '^[a-f0-9]{64}$'
             OR p_retired_at IS NULL THEN
            RAISE EXCEPTION USING
              ERRCODE = '22023',
              MESSAGE = 'preview retirement identity is invalid';
          END IF;
          SELECT * INTO publication
            FROM public.preview_publications
           WHERE event_id = p_event_id::text
           FOR UPDATE;
          IF publication.event_id IS NULL
             OR publication.site_id IS DISTINCT FROM p_site_id
             OR publication.receipt_sha256 IS DISTINCT FROM
                p_receipt_sha256 THEN
            RETURN false;
          END IF;
          IF publication.publication_state = 'retired' THEN
            RETURN true;
          END IF;
          IF publication.publication_state <> 'retiring'
             OR p_retired_at < publication.retiring_at THEN
            RETURN false;
          END IF;
          UPDATE public.preview_publications
             SET publication_state = 'retired',
                 retired_at = GREATEST(
                   clock_timestamp(),
                   publication.retiring_at
                 )
           WHERE event_id = publication.event_id;
          RETURN true;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION pilot_preview_version_is_protected(
          p_site_id text,
          p_object_key text,
          p_version_id text,
          p_observed_at timestamptz
        )
        RETURNS boolean
        LANGUAGE sql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
          SELECT CASE WHEN p_observed_at IS NULL THEN true ELSE EXISTS (
              SELECT 1
                FROM public.preview_publications AS publication
               WHERE publication.site_id = p_site_id
                 AND publication.object_key = p_object_key
                 AND (
                   (
                     publication.publication_state = 'reserved'
                     AND publication.intent_expires_at >
                         LEAST(p_observed_at, clock_timestamp())
                   )
                   OR (
                     publication.publication_state IN ('ready', 'retiring')
                     AND publication.version_id = p_version_id
                   )
                 )
            )
          END
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION pilot_prune_preview_access_receipts(
          p_site_id text,
          p_cutoff_at timestamptz,
          p_limit integer
        )
        RETURNS integer
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
          deleted_count integer;
          metadata_retention_days integer;
          effective_cutoff timestamptz;
        BEGIN
          IF p_site_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
             OR p_cutoff_at IS NULL
             OR p_limit IS NULL
             OR NOT (p_limit BETWEEN 1 AND 1000) THEN
            RAISE EXCEPTION USING
              ERRCODE = '22023',
              MESSAGE = 'preview access prune is invalid';
          END IF;
          SELECT (
                   config.canonical_config #>>
                   '{storage,retention,metadata_retention_days}'
                 )::integer
            INTO metadata_retention_days
            FROM public.active_pilot_configurations AS active
            JOIN public.site_config_revisions AS config
              ON config.config_revision_id = active.config_revision_id
             AND config.site_id = active.site_id
           WHERE active.site_id = p_site_id
           FOR SHARE OF config;
          IF metadata_retention_days IS NULL
             OR NOT (metadata_retention_days BETWEEN 1 AND 365) THEN
            RAISE EXCEPTION USING
              ERRCODE = '23514',
              MESSAGE = 'active metadata retention policy is unavailable';
          END IF;
          effective_cutoff := LEAST(
            p_cutoff_at,
            clock_timestamp() - make_interval(days => metadata_retention_days)
          );
          WITH selected AS (
            SELECT access_id
              FROM public.preview_access_receipts
             WHERE site_id = p_site_id
               AND occurred_at < effective_cutoff
             ORDER BY occurred_at, access_id
             LIMIT p_limit
             FOR UPDATE SKIP LOCKED
          ),
          deleted AS (
            DELETE FROM public.preview_access_receipts AS access
             USING selected
             WHERE access.access_id = selected.access_id
             RETURNING access.access_id
          )
          SELECT count(*)::integer INTO deleted_count FROM deleted;
          RETURN deleted_count;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION pilot_retire_expired_preview_intents(
          p_site_id text,
          p_observed_at timestamptz,
          p_limit integer
        )
        RETURNS integer
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
          retired_count integer;
          effective_observed_at timestamptz;
        BEGIN
          IF p_site_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
             OR p_observed_at IS NULL
             OR p_limit IS NULL
             OR NOT (p_limit BETWEEN 1 AND 1000) THEN
            RAISE EXCEPTION USING
              ERRCODE = '22023',
              MESSAGE = 'expired preview intent retirement is invalid';
          END IF;
          effective_observed_at := LEAST(
            p_observed_at,
            clock_timestamp()
          );
          WITH selected AS (
            SELECT event_id
              FROM public.preview_publications
             WHERE site_id = p_site_id
               AND publication_state = 'reserved'
               AND intent_expires_at <= effective_observed_at
             ORDER BY intent_expires_at, event_id
             LIMIT p_limit
             FOR UPDATE SKIP LOCKED
          ),
          retired AS (
            UPDATE public.preview_publications AS publication
               SET publication_state = 'retired',
                   retired_at = effective_observed_at
              FROM selected
             WHERE publication.event_id = selected.event_id
             RETURNING publication.event_id
          )
          SELECT count(*)::integer INTO retired_count FROM retired;
          RETURN retired_count;
        END;
        $$
        """
    )


def _restrict_postgresql_roles() -> None:
    functions = (
        "pilot_get_active_site_config_sha256(text)",
        "pilot_get_preview_object_context(text, uuid, uuid, uuid)",
        "pilot_prepare_preview_publication(jsonb)",
        "pilot_finalize_preview_receipt(jsonb, jsonb)",
        "pilot_get_preview_receipt(text, uuid)",
        "pilot_commit_preview_access(jsonb)",
        "pilot_claim_preview_receipts_for_retention(text, timestamptz, integer)",
        "pilot_finalize_preview_retirement(text, uuid, text, timestamptz)",
        "pilot_preview_version_is_protected(text, text, text, timestamptz)",
        "pilot_prune_preview_access_receipts(text, timestamptz, integer)",
        "pilot_retire_expired_preview_intents(text, timestamptz, integer)",
    )
    op.execute(
        "REVOKE ALL ON TABLE preview_publications FROM PUBLIC"
    )
    op.execute(
        "REVOKE ALL ON TABLE preview_access_receipts FROM PUBLIC"
    )
    for function in functions:
        op.execute(f"REVOKE ALL ON FUNCTION {function} FROM PUBLIC")
    op.execute(
        """
        DO $$
        DECLARE
          role_name text;
          role_owner boolean;
        BEGIN
          FOREACH role_name IN ARRAY
            ARRAY['kuzet_runtime', 'kuzet_api', 'kuzet_retention']
          LOOP
            IF EXISTS (
              SELECT 1 FROM pg_roles WHERE rolname = role_name
            ) THEN
              SELECT role.rolsuper
                     OR role.rolbypassrls
                     OR role.oid IN (
                       SELECT table_class.relowner
                         FROM pg_class AS table_class
                        WHERE table_class.oid IN (
                          'public.preview_publications'::regclass,
                          'public.preview_access_receipts'::regclass
                        )
                     )
                INTO role_owner
                FROM pg_roles AS role
               WHERE role.rolname = role_name;
              IF role_owner THEN
                RAISE EXCEPTION
                  '% must be a non-owner, non-superuser bounded role',
                  role_name;
              END IF;
              EXECUTE format(
                'REVOKE ALL ON TABLE public.preview_publications, '
                'public.preview_access_receipts FROM %I',
                role_name
              );
            END IF;
          END LOOP;
          IF EXISTS (
            SELECT 1 FROM pg_roles WHERE rolname = 'kuzet_runtime'
          ) THEN
            GRANT EXECUTE ON FUNCTION
              pilot_get_active_site_config_sha256(text),
              pilot_get_preview_object_context(text, uuid, uuid, uuid),
              pilot_prepare_preview_publication(jsonb),
              pilot_finalize_preview_receipt(jsonb, jsonb)
              TO kuzet_runtime;
          END IF;
          IF EXISTS (
            SELECT 1 FROM pg_roles WHERE rolname = 'kuzet_api'
          ) THEN
            GRANT EXECUTE ON FUNCTION
              pilot_get_active_site_config_sha256(text),
              pilot_get_preview_receipt(text, uuid),
              pilot_commit_preview_access(jsonb)
              TO kuzet_api;
          END IF;
          IF EXISTS (
            SELECT 1 FROM pg_roles WHERE rolname = 'kuzet_retention'
          ) THEN
            GRANT EXECUTE ON FUNCTION
              pilot_claim_preview_receipts_for_retention(
                text, timestamptz, integer
              ),
              pilot_finalize_preview_retirement(
                text, uuid, text, timestamptz
              ),
              pilot_preview_version_is_protected(
                text, text, text, timestamptz
              ),
              pilot_prune_preview_access_receipts(
                text, timestamptz, integer
              ),
              pilot_retire_expired_preview_intents(
                text, timestamptz, integer
              )
              TO kuzet_retention;
          END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    connection = op.get_bind()
    publication_count = connection.execute(
        sa.text("SELECT COUNT(*) FROM preview_publications")
    ).scalar_one()
    access_count = connection.execute(
        sa.text("SELECT COUNT(*) FROM preview_access_receipts")
    ).scalar_one()
    if publication_count or access_count:
        raise RuntimeError(
            "0007 downgrade refused: preview publication or access history exists"
        )

    if connection.dialect.name == "postgresql":
        for signature in (
            "pilot_retire_expired_preview_intents(text, timestamptz, integer)",
            "pilot_prune_preview_access_receipts(text, timestamptz, integer)",
            "pilot_preview_version_is_protected(text, text, text, timestamptz)",
            "pilot_finalize_preview_retirement(text, uuid, text, timestamptz)",
            "pilot_claim_preview_receipts_for_retention(text, timestamptz, integer)",
            "pilot_commit_preview_access(jsonb)",
            "pilot_get_preview_receipt(text, uuid)",
            "pilot_finalize_preview_receipt(jsonb, jsonb)",
            "pilot_prepare_preview_publication(jsonb)",
            "pilot_get_preview_object_context(text, uuid, uuid, uuid)",
            "pilot_get_active_site_config_sha256(text)",
        ):
            op.execute(f"DROP FUNCTION IF EXISTS {signature}")

    op.drop_index(
        "ix_preview_access_site_occurred",
        table_name="preview_access_receipts",
    )
    op.drop_table("preview_access_receipts")
    op.drop_index(
        "ix_preview_intent_expiry",
        table_name="preview_publications",
    )
    op.drop_index(
        "ix_preview_retention_claim",
        table_name="preview_publications",
    )
    op.drop_table("preview_publications")
    if connection.dialect.name == "postgresql":
        op.execute(
            "DROP FUNCTION IF EXISTS pilot_guard_preview_access_mutation()"
        )
        op.execute(
            "DROP FUNCTION IF EXISTS pilot_guard_preview_publication_mutation()"
        )
        op.execute(
            "DROP FUNCTION IF EXISTS pilot_validate_preview_publication_insert()"
        )
    op.drop_index(
        "uq_candidate_provenance_preview_authority",
        table_name="candidate_event_provenance",
    )
    op.drop_index(
        "uq_camera_epoch_history_site_identity",
        table_name="camera_epoch_history",
    )
