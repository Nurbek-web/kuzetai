"""Persist TOTP replay protection state.

Revision ID: 0002_api_security
Revises: 0001_pilot_core
Create Date: 2026-07-28
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002_api_security"
down_revision: Union[str, Sequence[str], None] = "0001_pilot_core"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("totp_last_accepted_counter", sa.BigInteger(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("totp_last_accepted_counter")
