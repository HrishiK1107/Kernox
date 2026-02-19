"""add status column to alerts

Revision ID: 0c550cea9fe2
Revises: dae93d8a19f7
Create Date: 2026-02-19 01:41:39.340825
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers
revision: str = "0c550cea9fe2"
down_revision: Union[str, Sequence[str], None] = "dae93d8a19f7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""

    # 1️⃣ Add column with server default for safe migration
    op.add_column(
        "alerts",
        sa.Column(
            "status",
            sa.String(length=50),
            nullable=False,
            server_default="open",
        ),
    )

    # 2️⃣ Create index for filtering
    op.create_index(
        "idx_alerts_status",
        "alerts",
        ["status"],
        unique=False,
    )

    # 3️⃣ Remove server default (application handles default now)
    op.alter_column(
        "alerts",
        "status",
        server_default=None,
    )


def downgrade() -> None:
    """Downgrade schema."""

    op.drop_index(
        "idx_alerts_status",
        table_name="alerts",
    )

    op.drop_column(
        "alerts",
        "status",
    )
