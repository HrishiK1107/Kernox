"""add campaigns and campaign_alerts tables

Revision ID: 9075a3ee166f
Revises: c93a7e01de10
Create Date: 2026-02-19
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = "9075a3ee166f"
down_revision: Union[str, Sequence[str], None] = "c93a7e01de10"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "campaigns",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("endpoint_id", sa.Integer(), nullable=False),
        sa.Column("chain_length", sa.Integer(), nullable=False),
        sa.Column("campaign_risk_score", sa.Integer(), nullable=False),
        sa.Column("first_alert_id", sa.Integer(), nullable=False),
        sa.Column("last_alert_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["endpoint_id"], ["endpoints.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["first_alert_id"], ["alerts.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["last_alert_id"], ["alerts.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(
        "idx_campaigns_endpoint_id",
        "campaigns",
        ["endpoint_id"],
        unique=False,
    )

    op.create_index(
        "idx_campaigns_created_at",
        "campaigns",
        ["created_at"],
        unique=False,
    )

    op.create_table(
        "campaign_alerts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("campaign_id", sa.Integer(), nullable=False),
        sa.Column("alert_id", sa.Integer(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(
        "idx_campaign_alerts_campaign_id",
        "campaign_alerts",
        ["campaign_id"],
        unique=False,
    )

    op.create_index(
        "idx_campaign_alerts_alert_id",
        "campaign_alerts",
        ["alert_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("idx_campaign_alerts_alert_id", table_name="campaign_alerts")
    op.drop_index("idx_campaign_alerts_campaign_id", table_name="campaign_alerts")
    op.drop_table("campaign_alerts")

    op.drop_index("idx_campaigns_created_at", table_name="campaigns")
    op.drop_index("idx_campaigns_endpoint_id", table_name="campaigns")
    op.drop_table("campaigns")
