"""Add canonical username identity and durable auth generations.

Revision ID: 0005_auth_lifecycle
Revises: 0004_operational_retention
Create Date: 2026-07-31
"""

from __future__ import annotations

import unicodedata
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import context, op

revision: str = "0005_auth_lifecycle"
down_revision: Union[str, Sequence[str], None] = "0004_operational_retention"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _identity(username: str) -> tuple[str, str]:
    display = unicodedata.normalize("NFKC", username).strip()
    normalized = display.casefold()
    if not display or not normalized or len(display) > 255 or len(normalized) > 255:
        raise RuntimeError("existing username cannot be normalized")
    return display, normalized


def upgrade() -> None:
    if context.is_offline_mode():
        op.execute(
            """
            DO $$
            BEGIN
                RAISE EXCEPTION
                    'migration 0005 requires an online canonical username backfill';
            END
            $$;
            """
        )
        return
    connection = op.get_bind()
    users = list(
        connection.execute(
            sa.text("SELECT user_id, username FROM users ORDER BY user_id")
        ).mappings()
    )
    prepared: list[tuple[str, str, str]] = []
    identities: dict[str, str] = {}
    for user in users:
        display, normalized = _identity(str(user["username"]))
        existing = identities.get(normalized)
        if existing is not None:
            raise RuntimeError(
                f"normalized username collision between {existing!r} and {str(user['user_id'])!r}"
            )
        identities[normalized] = str(user["user_id"])
        prepared.append((str(user["user_id"]), display, normalized))

    op.add_column(
        "users",
        sa.Column("normalized_username", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column(
            "auth_generation",
            sa.BigInteger(),
            nullable=False,
            server_default="1",
        ),
    )
    for user_id, display, normalized in prepared:
        connection.execute(
            sa.text(
                """
                UPDATE users
                   SET username = :display,
                       normalized_username = :normalized
                 WHERE user_id = :user_id
                """
            ),
            {
                "display": display,
                "normalized": normalized,
                "user_id": user_id,
            },
        )
    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column(
            "normalized_username",
            existing_type=sa.String(length=255),
            nullable=False,
        )
        batch_op.create_unique_constraint(
            "uq_users_normalized_username",
            ["normalized_username"],
        )
        batch_op.create_check_constraint(
            "ck_users_auth_generation",
            "auth_generation > 0",
        )


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_constraint("ck_users_auth_generation", type_="check")
        batch_op.drop_constraint("uq_users_normalized_username", type_="unique")
        batch_op.drop_column("auth_generation")
        batch_op.drop_column("normalized_username")
