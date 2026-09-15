"""tool.position: stored listing order, replacing (first_seen_at, id) reconstruction

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-15 19:30:00.000000

Backfill ranks existing rows the way the read path used to order them, so
nothing already on record changes meaning; new rows get the index the scan
runner saw.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0007'
down_revision: Union[str, Sequence[str], None] = '0006'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('tool', sa.Column('position', sa.Integer(), nullable=True))
    # Window functions: Postgres, and sqlite >= 3.25 (2018).
    op.execute(
        """
        UPDATE tool SET position = ranked.rn
        FROM (
            SELECT id, ROW_NUMBER() OVER (
                PARTITION BY scan_id ORDER BY first_seen_at, id
            ) AS rn
            FROM tool
        ) AS ranked
        WHERE tool.id = ranked.id
        """
    )
    op.alter_column('tool', 'position', existing_type=sa.Integer(), nullable=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('tool', 'position')
