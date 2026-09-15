"""drift: description text on tool; scan/baseline FKs and nullable hashes on drift_event

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-15 12:00:00.000000

No retention purge exists for scan/tool today; if one is ever added,
drift_event rows must be deleted before the scans they reference.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0006'
down_revision: Union[str, Sequence[str], None] = '0005'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('tool', sa.Column('description', sa.Text(), nullable=True))
    # drift_event has never been written to (0001 created it, nothing
    # inserts), so NOT NULL needs no backfill.
    op.add_column('drift_event', sa.Column('scan_id', sa.String(length=36), nullable=False))
    op.add_column(
        'drift_event', sa.Column('baseline_scan_id', sa.String(length=36), nullable=False)
    )
    op.create_foreign_key('fk_drift_event_scan', 'drift_event', 'scan', ['scan_id'], ['id'])
    op.create_foreign_key(
        'fk_drift_event_baseline_scan', 'drift_event', 'scan', ['baseline_scan_id'], ['id']
    )
    op.alter_column('drift_event', 'old_hash', existing_type=sa.String(length=64), nullable=True)
    op.alter_column('drift_event', 'new_hash', existing_type=sa.String(length=64), nullable=True)
    op.create_index('ix_drift_event_scan_id', 'drift_event', ['scan_id'])
    op.create_index('ix_scan_target_finished', 'scan', ['target_ref', 'finished_at'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_scan_target_finished', table_name='scan')
    op.drop_index('ix_drift_event_scan_id', table_name='drift_event')
    op.alter_column('drift_event', 'new_hash', existing_type=sa.String(length=64), nullable=False)
    op.alter_column('drift_event', 'old_hash', existing_type=sa.String(length=64), nullable=False)
    op.drop_constraint('fk_drift_event_baseline_scan', 'drift_event', type_='foreignkey')
    op.drop_constraint('fk_drift_event_scan', 'drift_event', type_='foreignkey')
    op.drop_column('drift_event', 'baseline_scan_id')
    op.drop_column('drift_event', 'scan_id')
    op.drop_column('tool', 'description')
