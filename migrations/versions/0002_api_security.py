"""Persist TOTP replay protection state.

Revision ID: 0002_api_security
Revises: 0001_pilot_core
Create Date: 2026-07-28
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import context, op

from protector.pilot.totp_envelope import (
    TOTP_ENVELOPE_PREFIX,
    TOTP_ROTATION_INSTRUCTION,
    validate_totp_envelope,
)

revision: str = "0002_api_security"
down_revision: Union[str, Sequence[str], None] = "0001_pilot_core"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
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
                          AND NOT (
                              totp_secret_encrypted LIKE '{TOTP_ENVELOPE_PREFIX}%'
                              AND length(totp_secret_encrypted) >= 76
                          )
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
        )
        for encrypted_seed in encrypted_seeds.scalars():
            try:
                validate_totp_envelope(encrypted_seed)
            except ValueError as exc:
                raise RuntimeError(TOTP_ROTATION_INSTRUCTION) from exc

    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("totp_last_accepted_counter", sa.BigInteger(), nullable=True))
        batch_op.create_check_constraint(
            "ck_users_totp_encrypted_envelope",
            "totp_secret_encrypted IS NULL OR "
            "(totp_secret_encrypted LIKE 'totp:v1:%' "
            "AND length(totp_secret_encrypted) >= 76)",
        )


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_constraint("ck_users_totp_encrypted_envelope", type_="check")
        batch_op.drop_column("totp_last_accepted_counter")
