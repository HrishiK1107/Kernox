"""merge analytics index branch

Revision ID: bac7b488fcb5
Revises: 216976a550b6, c4b14df70785
Create Date: 2026-02-19 15:56:40.666102

"""

from typing import Sequence, Union


# revision identifiers, used by Alembic.
revision: str = "bac7b488fcb5"
down_revision: Union[str, Sequence[str], None] = ("216976a550b6", "c4b14df70785")
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
