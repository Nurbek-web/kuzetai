"""Add runtime epochs and receipt-bound audit retention.

Revision ID: 0004_operational_retention
Revises: 0003_notification_delivery
Create Date: 2026-07-29
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004_operational_retention"
down_revision: Union[str, Sequence[str], None] = "0003_notification_delivery"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "camera_health_samples",
        sa.Column(
            "runtime_session_id",
            sa.String(length=128),
            nullable=False,
            server_default="legacy",
        ),
    )
    op.add_column(
        "audit_entries",
        sa.Column("site_id", sa.String(length=128), nullable=True),
    )
    if op.get_bind().dialect.name == "postgresql":
        op.create_foreign_key(
            "fk_audit_entries_site_id_sites",
            "audit_entries",
            "sites",
            ["site_id"],
            ["site_id"],
            ondelete="RESTRICT",
        )
    op.create_index(
        "ix_audit_entries_site_occurred",
        "audit_entries",
        ["site_id", "occurred_at", "audit_id"],
        unique=False,
    )
    op.create_table(
        "audit_archive_receipts",
        sa.Column("receipt_id", sa.String(length=36), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("cutoff_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("archive_object_key", sa.String(length=2048), nullable=False),
        sa.Column("archive_sha256", sa.String(length=64), nullable=False),
        sa.Column("detached_signature", sa.Text(), nullable=False),
        sa.Column("signing_key_id", sa.String(length=128), nullable=False),
        sa.Column("canonical_receipt", sa.Text(), nullable=False),
        sa.Column("row_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("pruned_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "length(archive_sha256) = 64",
            name="ck_audit_archive_sha256",
        ),
        sa.CheckConstraint("row_count > 0", name="ck_audit_archive_row_count"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.site_id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("receipt_id"),
        sa.UniqueConstraint(
            "archive_object_key",
            name="uq_audit_archive_object_key",
        ),
    )
    op.create_table(
        "audit_archive_items",
        sa.Column("receipt_id", sa.String(length=36), nullable=False),
        sa.Column("audit_id", sa.String(length=36), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_sha256", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(
            ["receipt_id"],
            ["audit_archive_receipts.receipt_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("receipt_id", "audit_id"),
        sa.UniqueConstraint("audit_id", name="uq_audit_archive_item_audit"),
    )
    op.create_index(
        "ix_audit_archive_items_receipt",
        "audit_archive_items",
        ["receipt_id", "audit_id"],
        unique=False,
    )
    op.create_table(
        "audit_prune_authorizations",
        sa.Column("backend_pid", sa.Integer(), nullable=False),
        sa.Column("transaction_id", sa.BigInteger(), nullable=False),
        sa.Column("audit_id", sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint("backend_pid", "transaction_id", "audit_id"),
    )

    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute("REVOKE ALL ON TABLE audit_prune_authorizations FROM PUBLIC")
    op.execute(
        """
        CREATE OR REPLACE FUNCTION pilot_reject_audit_archive_receipt_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF TG_TABLE_NAME = 'audit_archive_receipts'
               AND TG_OP = 'UPDATE'
               AND current_user = 'kuzet_owner'
               AND OLD.receipt_id = NEW.receipt_id
               AND OLD.site_id = NEW.site_id
               AND OLD.cutoff_at = NEW.cutoff_at
               AND OLD.archive_object_key = NEW.archive_object_key
               AND OLD.archive_sha256 = NEW.archive_sha256
               AND OLD.detached_signature = NEW.detached_signature
               AND OLD.signing_key_id = NEW.signing_key_id
               AND OLD.canonical_receipt = NEW.canonical_receipt
               AND OLD.row_count = NEW.row_count
               AND OLD.created_at = NEW.created_at
               AND OLD.pruned_at IS NULL
               AND NEW.pruned_at IS NOT NULL THEN
                RETURN NEW;
            END IF;
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'audit archive receipts and items are append-only';
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_audit_archive_receipts_append_only
        BEFORE UPDATE OR DELETE ON audit_archive_receipts
        FOR EACH ROW EXECUTE FUNCTION pilot_reject_audit_archive_receipt_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_audit_archive_items_append_only
        BEFORE UPDATE OR DELETE ON audit_archive_items
        FOR EACH ROW EXECUTE FUNCTION pilot_reject_audit_archive_receipt_mutation()
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION pilot_reject_audit_archive_receipt_mutation() FROM PUBLIC"
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION pilot_reject_audit_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF TG_OP = 'DELETE' AND EXISTS (
                SELECT 1
                FROM public.audit_prune_authorizations AS authorization
                WHERE authorization.backend_pid = pg_backend_pid()
                  AND authorization.transaction_id = txid_current()
                  AND authorization.audit_id = OLD.audit_id
            ) THEN
                RETURN OLD;
            END IF;
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'audit entries are append-only';
        END;
        $$;
        """
    )
    op.execute("REVOKE ALL ON FUNCTION pilot_reject_audit_mutation() FROM PUBLIC")
    op.execute(
        """
        CREATE OR REPLACE FUNCTION pilot_prune_archived_audit(p_receipt_id text)
        RETURNS integer
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
            expected_count integer;
            deleted_count integer;
            receipt_site_id text;
            receipt_cutoff timestamptz;
            site_count integer;
        BEGIN
            SELECT receipt.row_count, receipt.site_id, receipt.cutoff_at
              INTO expected_count, receipt_site_id, receipt_cutoff
              FROM public.audit_archive_receipts AS receipt
             WHERE receipt.receipt_id = p_receipt_id
             FOR UPDATE;
            IF expected_count IS NULL THEN
                RAISE EXCEPTION 'unknown audit archive receipt';
            END IF;
            IF (
                SELECT receipt.pruned_at IS NOT NULL
                  FROM public.audit_archive_receipts AS receipt
                 WHERE receipt.receipt_id = p_receipt_id
            ) THEN
                RETURN expected_count;
            END IF;
            IF (
                SELECT count(*)
                  FROM public.audit_archive_items AS item
                 WHERE item.receipt_id = p_receipt_id
            ) <> expected_count THEN
                RAISE EXCEPTION 'audit archive receipt item count is inconsistent';
            END IF;
            SELECT count(*) INTO site_count FROM public.sites;
            IF EXISTS (
                SELECT 1
                  FROM public.audit_archive_items AS item
                  LEFT JOIN public.audit_entries AS audit
                    ON audit.audit_id = item.audit_id
                 WHERE item.receipt_id = p_receipt_id
                   AND (
                     audit.audit_id IS NULL
                     OR audit.occurred_at IS DISTINCT FROM item.occurred_at
                     OR audit.occurred_at >= receipt_cutoff
                     OR (
                       audit.site_id IS DISTINCT FROM receipt_site_id
                       AND NOT (
                         audit.site_id IS NULL
                         AND site_count = 1
                         AND EXISTS (
                           SELECT 1 FROM public.sites AS sole_site
                            WHERE sole_site.site_id = receipt_site_id
                         )
                       )
                     )
                   )
            ) THEN
                RAISE EXCEPTION 'audit archive receipt scope is inconsistent';
            END IF;

            INSERT INTO public.audit_prune_authorizations (
                backend_pid,
                transaction_id,
                audit_id
            )
            SELECT pg_backend_pid(), txid_current(), item.audit_id
              FROM public.audit_archive_items AS item
             WHERE item.receipt_id = p_receipt_id;

            DELETE FROM public.audit_entries AS audit
             USING public.audit_archive_items AS item
             WHERE item.receipt_id = p_receipt_id
               AND audit.audit_id = item.audit_id;
            GET DIAGNOSTICS deleted_count = ROW_COUNT;
            IF deleted_count <> expected_count THEN
                RAISE EXCEPTION 'receipt-bound audit prune was incomplete';
            END IF;

            DELETE FROM public.audit_prune_authorizations AS authorization
             WHERE authorization.backend_pid = pg_backend_pid()
               AND authorization.transaction_id = txid_current();
            UPDATE public.audit_archive_receipts
               SET pruned_at = transaction_timestamp()
             WHERE receipt_id = p_receipt_id;
            RETURN deleted_count;
        EXCEPTION WHEN OTHERS THEN
            DELETE FROM public.audit_prune_authorizations AS authorization
             WHERE authorization.backend_pid = pg_backend_pid()
               AND authorization.transaction_id = txid_current();
            RAISE;
        END;
        $$;
        """
    )
    op.execute("REVOKE ALL ON FUNCTION pilot_prune_archived_audit(text) FROM PUBLIC")
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_roles WHERE rolname = 'kuzet_retention'
            ) THEN
                REVOKE ALL ON TABLE audit_prune_authorizations FROM kuzet_retention;
                GRANT EXECUTE ON FUNCTION pilot_prune_archived_audit(text)
                  TO kuzet_retention;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP FUNCTION IF EXISTS pilot_prune_archived_audit(text)")
        op.execute(
            "DROP FUNCTION IF EXISTS pilot_reject_audit_archive_receipt_mutation() CASCADE"
        )
        op.execute(
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
        )
    op.drop_table("audit_prune_authorizations")
    op.drop_index(
        "ix_audit_archive_items_receipt",
        table_name="audit_archive_items",
    )
    op.drop_table("audit_archive_items")
    op.drop_table("audit_archive_receipts")
    op.drop_index("ix_audit_entries_site_occurred", table_name="audit_entries")
    if op.get_bind().dialect.name == "postgresql":
        op.drop_constraint(
            "fk_audit_entries_site_id_sites",
            "audit_entries",
            type_="foreignkey",
        )
    with op.batch_alter_table("audit_entries") as batch_op:
        batch_op.drop_column("site_id")
    with op.batch_alter_table("camera_health_samples") as batch_op:
        batch_op.drop_column("runtime_session_id")
