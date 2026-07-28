"""Persist TOTP replay protection state.

Revision ID: 0002_api_security
Revises: 0001_pilot_core
Create Date: 2026-07-28
"""

import os
from pathlib import Path
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import context, op

from protector.pilot.totp_envelope import (
    PORTABLE_TOTP_ENVELOPE_CHECK,
    POSTGRESQL_TOTP_ENVELOPE_PREDICATE,
    SQLITE_TOTP_ENVELOPE_PREDICATE,
    TOTP_MIGRATION_KEY_INSTRUCTION,
    TOTP_ROTATION_INSTRUCTION,
    TotpEnvelopeProtector,
)

revision: str = "0002_api_security"
down_revision: Union[str, Sequence[str], None] = "0001_pilot_core"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None
TOTP_SECRET_PATH = Path("/run/secrets/totp_encryption_key")


def _configured_totp_key() -> str:
    configured = context.config.attributes.get("totp_encryption_key")
    if configured is None:
        configured = os.getenv("PILOT_TOTP_ENCRYPTION_KEY")
    if configured is None:
        try:
            configured = TOTP_SECRET_PATH.read_text(encoding="utf-8").strip()
        except FileNotFoundError as exc:
            raise RuntimeError(TOTP_MIGRATION_KEY_INSTRUCTION) from exc
        except OSError as exc:
            raise RuntimeError(
                f"unable to read {TOTP_SECRET_PATH} for authenticated TOTP migration"
            ) from exc
    if hasattr(configured, "get_secret_value"):
        configured = configured.get_secret_value()
    if not isinstance(configured, str) or not configured:
        raise RuntimeError(TOTP_MIGRATION_KEY_INSTRUCTION)
    return configured


def _constraint_sql(dialect_name: str) -> str:
    if dialect_name == "postgresql":
        return (
            "totp_secret_encrypted IS NULL OR "
            f"({POSTGRESQL_TOTP_ENVELOPE_PREDICATE})"
        )
    if dialect_name == "sqlite":
        return (
            "totp_secret_encrypted IS NULL OR "
            f"({SQLITE_TOTP_ENVELOPE_PREDICATE})"
        )
    return PORTABLE_TOTP_ENVELOPE_CHECK


def upgrade() -> None:
    dialect_name = context.get_context().dialect.name
    if context.is_offline_mode():
        op.execute(
            sa.text(
                f"""
                DO $$
                BEGIN
                    IF EXISTS (
                        SELECT 1
                        FROM users
                        WHERE totp_secret_encrypted IS NOT NULL
                          AND NOT ({POSTGRESQL_TOTP_ENVELOPE_PREDICATE})
                    ) THEN
                        RAISE EXCEPTION USING
                            ERRCODE = '23514',
                            MESSAGE = '{TOTP_ROTATION_INSTRUCTION}';
                    END IF;
                END
                $$;
                """
            )
        )
    else:
        encrypted_seeds = op.get_bind().execute(
            sa.text(
                "SELECT totp_secret_encrypted FROM users "
                "WHERE totp_secret_encrypted IS NOT NULL"
            )
        ).scalars().all()
        if encrypted_seeds:
            try:
                protector = TotpEnvelopeProtector(_configured_totp_key())
                for encrypted_seed in encrypted_seeds:
                    protector.authenticate(encrypted_seed)
            except ValueError as exc:
                raise RuntimeError(TOTP_ROTATION_INSTRUCTION) from exc

    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("totp_last_accepted_counter", sa.BigInteger(), nullable=True))
        batch_op.create_check_constraint(
            "ck_users_totp_encrypted_envelope",
            _constraint_sql(dialect_name),
        )


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_constraint("ck_users_totp_encrypted_envelope", type_="check")
        batch_op.drop_column("totp_last_accepted_counter")
