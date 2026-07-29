"""Add durable notification delivery leases.

Revision ID: 0003_notification_delivery
Revises: 0002_api_security
Create Date: 2026-07-29
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003_notification_delivery"
down_revision: Union[str, Sequence[str], None] = "0002_api_security"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "notification_outbox",
        sa.Column("lease_token", sa.String(length=36), nullable=True),
    )
    op.add_column(
        "notification_outbox",
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_notification_outbox_claim",
        "notification_outbox",
        ["status", "available_at", "lease_expires_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_notification_outbox_claim", table_name="notification_outbox")
    with op.batch_alter_table("notification_outbox") as batch_op:
        batch_op.drop_column("lease_expires_at")
        batch_op.drop_column("lease_token")
