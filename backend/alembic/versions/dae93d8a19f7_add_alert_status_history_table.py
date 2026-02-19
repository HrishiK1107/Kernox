"""add alert_status_history table

Revision ID: dae93d8a19f7
Revises: 9075a3ee166f
Create Date: 2026-02-19 01:36:10.564328
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers
revision: str = "dae93d8a19f7"
down_revision: Union[str, Sequence[str], None] = "9075a3ee166f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""

    op.create_table(
        "alert_status_history",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("alert_id", sa.Integer(), nullable=False),
        sa.Column("previous_status", sa.String(length=50), nullable=False),
        sa.Column("new_status", sa.String(length=50), nullable=False),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(
        "idx_alert_status_alert_id",
        "alert_status_history",
        ["alert_id"],
        unique=False,
    )

    op.create_index(
        "idx_alert_status_changed_at",
        "alert_status_history",
        ["changed_at"],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade schema."""

    op.drop_index(
        "idx_alert_status_changed_at",
        table_name="alert_status_history",
    )

    op.drop_index(
        "idx_alert_status_alert_id",
        table_name="alert_status_history",
    )

    op.drop_table("alert_status_history")
