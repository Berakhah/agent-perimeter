"""scan.listing_complete: whether tools/list was read to the end

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-04 12:00:00.000000

A scan whose tools/list stopped early (repeat cursor, page cap, later-page
failure) would make the next full scan report every tool it missed as
added. Baseline selection excludes rows with false. Existing rows were
written before pagination was followed and are kept as true: the server
default backfills them, so nothing already on record changes meaning.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0008'
down_revision: Union[str, Sequence[str], None] = '0007'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        'scan',
        sa.Column(
            'listing_complete', sa.Boolean(), nullable=False, server_default=sa.true()
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('scan', 'listing_complete')
