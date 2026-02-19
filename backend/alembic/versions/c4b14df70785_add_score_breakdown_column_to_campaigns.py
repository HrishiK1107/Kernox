from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "NEW_REVISION_ID"
down_revision: Union[str, Sequence[str], None] = "0c550cea9fe2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "campaigns",
        sa.Column(
            "score_breakdown",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'::json"),
        ),
    )

    op.alter_column(
        "campaigns",
        "score_breakdown",
        server_default=None,
    )


def downgrade() -> None:
    op.drop_column("campaigns", "score_breakdown")
