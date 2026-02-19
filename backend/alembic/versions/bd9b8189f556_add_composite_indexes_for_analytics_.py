"""add composite indexes for analytics performance

Revision ID: 216976a550b6
Revises: dae93d8a19f7
Create Date: 2026-02-19
"""

from typing import Sequence, Union
from alembic import op


# revision identifiers
revision: str = "216976a550b6"
down_revision: Union[str, Sequence[str], None] = "0c550cea9fe2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Composite index for rolling alert queries
    op.create_index(
        "idx_alerts_endpoint_created_at",
        "alerts",
        ["endpoint_id", "created_at"],
        unique=False,
    )

    # Composite index for rolling campaign queries
    op.create_index(
        "idx_campaigns_endpoint_updated_at",
        "campaigns",
        ["endpoint_id", "updated_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "idx_campaigns_endpoint_updated_at",
        table_name="campaigns",
    )

    op.drop_index(
        "idx_alerts_endpoint_created_at",
        table_name="alerts",
    )
