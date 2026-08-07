"""initial schema

Revision ID: 66b1e27d6667
Revises: 
Create Date: 2026-08-07 15:02:55.199621

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '66b1e27d6667'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the GASC Governor Postgres schema."""
    op.create_table(
        'nodes',
        sa.Column('node_id', sa.Text(), primary_key=True),
        sa.Column('payload_json', postgresql.JSONB(), nullable=False),
        sa.Column('content_hash', sa.Text(), nullable=True),
        sa.Column('commitment', sa.Text(), nullable=True),
    )

    op.create_table(
        'edges',
        sa.Column('child_id', sa.Text(), nullable=False),
        sa.Column('parent_id', sa.Text(), nullable=False),
        sa.Column('edge_class', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('child_id', 'parent_id'),
    )
    op.create_index('idx_edges_parent_id', 'edges', ['parent_id'])

    op.create_table(
        'quarantine_ledger',
        sa.Column('node_id', sa.Text(), primary_key=True),
    )

    op.create_table(
        'quarantine_events',
        sa.Column('event_id', sa.Text(), primary_key=True),
        sa.Column('event_json', postgresql.JSONB(), nullable=False),
    )

    op.create_table(
        'repair_candidates',
        sa.Column('node_id', sa.Text(), primary_key=True),
        sa.Column('candidate_json', postgresql.JSONB(), nullable=False),
    )

    op.create_table(
        'checkpoints',
        sa.Column('checkpoint_id', sa.Text(), primary_key=True),
        sa.Column('checkpoint_json', postgresql.JSONB(), nullable=False),
    )

    op.create_table(
        'external_effects',
        sa.Column('idempotency_key', sa.Text(), primary_key=True),
        sa.Column('node_id', sa.Text(), nullable=False),
        sa.Column('effect_type', sa.Text(), nullable=False),
        sa.Column('recorded_at_utc', sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        'reintegration_horizon',
        sa.Column('node_id', sa.Text(), primary_key=True),
        sa.Column('admitted_at_utc', sa.DateTime(timezone=True), nullable=False),
        sa.Column('trust_expires_utc', sa.DateTime(timezone=True), nullable=False),
        sa.Column('predecessor_id', sa.Text(), nullable=False),
        sa.Column('renewal_count', sa.Integer(), nullable=False, server_default='0'),
    )
    op.create_index('idx_horizon_expiry', 'reintegration_horizon', ['trust_expires_utc'])

    op.create_table(
        'recurrence_events',
        sa.Column('event_id', sa.Text(), primary_key=True),
        sa.Column('node_id', sa.Text(), nullable=False),
        sa.Column('recurrence_class', sa.Text(), nullable=False),
        sa.Column('detected_at_utc', sa.DateTime(timezone=True), nullable=False),
        sa.Column('signal_source', sa.Text(), nullable=False),
        sa.Column('outcome', sa.Text(), nullable=False, server_default='PROCESSED'),
        sa.Column('event_json', postgresql.JSONB(), nullable=False),
    )

    op.create_table(
        'signal_attempts',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('signal_source', sa.Text(), nullable=False),
        sa.Column('node_id', sa.Text(), nullable=False),
        sa.Column('signal_kind', sa.Text(), nullable=False),
        sa.Column('outcome', sa.Text(), nullable=False),
        sa.Column('recorded_at_utc', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('idx_signal_attempts_source', 'signal_attempts', ['signal_source', 'recorded_at_utc'])
    op.create_index('idx_signal_attempts_time', 'signal_attempts', ['recorded_at_utc'])

    op.create_table(
        'withdrawal_ledger',
        sa.Column('node_id', sa.Text(), primary_key=True),
        sa.Column('withdrawn_at_utc', sa.DateTime(timezone=True), nullable=False),
        sa.Column('triggering_event_id', sa.Text(), nullable=False),
        sa.Column('withdrawal_reason', sa.Text(), nullable=False),
    )

    op.create_table(
        'calibration_runs',
        sa.Column('run_id', sa.Text(), primary_key=True),
        sa.Column('run_at_utc', sa.DateTime(timezone=True), nullable=False),
        sa.Column('seeded_count', sa.Integer(), nullable=False),
        sa.Column('detected_count', sa.Integer(), nullable=False),
        sa.Column('sensitivity_floor', sa.Float(), nullable=False),
        sa.Column('monitored_period_json', postgresql.JSONB(), nullable=False),
    )

    op.create_table(
        'shadow_decisions',
        sa.Column('decision_id', sa.Text(), primary_key=True),
        sa.Column('node_id', sa.Text(), nullable=False),
        sa.Column('evaluated_at_utc', sa.DateTime(timezone=True), nullable=False),
        sa.Column('would_have_blocked', sa.Boolean(), nullable=False),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('parent_status_json', postgresql.JSONB(), nullable=False),
        sa.Column('policy_bundle_digest', sa.Text(), nullable=False),
        sa.Column('writer_identity', sa.Text(), nullable=True),
    )
    op.create_index('idx_shadow_evaluated', 'shadow_decisions', ['evaluated_at_utc'])
    op.create_index('idx_shadow_blocked', 'shadow_decisions', ['would_have_blocked'])


def downgrade() -> None:
    """Drop the GASC Governor Postgres schema."""
    op.drop_table('shadow_decisions')
    op.drop_table('calibration_runs')
    op.drop_table('withdrawal_ledger')
    op.drop_table('signal_attempts')
    op.drop_table('recurrence_events')
    op.drop_table('reintegration_horizon')
    op.drop_table('external_effects')
    op.drop_table('checkpoints')
    op.drop_table('repair_candidates')
    op.drop_table('quarantine_events')
    op.drop_table('quarantine_ledger')
    op.drop_index('idx_edges_parent_id', table_name='edges')
    op.drop_table('edges')
    op.drop_table('nodes')
