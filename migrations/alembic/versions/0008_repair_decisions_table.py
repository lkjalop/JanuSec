"""repair decisions tables for container databases

Revision ID: 0008_repair_decisions_table
Revises: 0007_factor_weights
Create Date: 2026-05-06 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0008_repair_decisions_table'
down_revision = '0007_factor_weights'
branch_labels = None
depends_on = None


def _has_table(bind, name: str) -> bool:
    try:
        return sa.inspect(bind).has_table(name)
    except Exception:
        return False


def _has_column(bind, table: str, column: str) -> bool:
    try:
        return any(col.get('name') == column for col in sa.inspect(bind).get_columns(table))
    except Exception:
        return False


def _has_index(bind, table: str, index_name: str) -> bool:
    try:
        return any(idx.get('name') == index_name for idx in sa.inspect(bind).get_indexes(table))
    except Exception:
        return False


def upgrade():
    bind = op.get_bind()
    is_pg = getattr(bind.dialect, 'name', '') == 'postgresql'
    json_type = postgresql.JSONB if is_pg else sa.JSON
    ts_type = sa.DateTime(timezone=True)

    if not _has_table(bind, 'events'):
        op.create_table(
            'events',
            sa.Column('id', sa.Text(), primary_key=True),
            sa.Column('source', sa.Text()),
            sa.Column('event_type', sa.Text()),
            sa.Column('severity', sa.Text()),
            sa.Column('ts_ingested', ts_type, server_default=sa.func.now()),
            sa.Column('ts_original', ts_type, nullable=True),
            sa.Column('raw_payload', json_type),
            sa.Column('tenant_id', sa.Text(), nullable=True),
        )
    elif not _has_column(bind, 'events', 'tenant_id'):
        op.add_column('events', sa.Column('tenant_id', sa.Text(), nullable=True))

    if not _has_table(bind, 'decisions'):
        op.create_table(
            'decisions',
            sa.Column('event_id', sa.Text(), sa.ForeignKey('events.id', ondelete='CASCADE'), primary_key=True),
            sa.Column('verdict', sa.Text(), nullable=False),
            sa.Column('confidence', sa.Float(), nullable=False),
            sa.Column('processing_ms', sa.Float()),
            sa.Column('factors', json_type),
            sa.Column('stage_timings', json_type),
            sa.Column('custody_hash', sa.Text()),
            sa.Column('tenant_id', sa.Text(), nullable=True),
            sa.Column('created_at', ts_type, server_default=sa.func.now()),
        )
    else:
        columns = {
            'verdict': sa.Column('verdict', sa.Text(), nullable=True),
            'confidence': sa.Column('confidence', sa.Float(), nullable=True),
            'processing_ms': sa.Column('processing_ms', sa.Float()),
            'factors': sa.Column('factors', json_type),
            'stage_timings': sa.Column('stage_timings', json_type),
            'custody_hash': sa.Column('custody_hash', sa.Text()),
            'tenant_id': sa.Column('tenant_id', sa.Text(), nullable=True),
            'created_at': sa.Column('created_at', ts_type, server_default=sa.func.now()),
        }
        for name, column in columns.items():
            if not _has_column(bind, 'decisions', name):
                op.add_column('decisions', column)

    if not _has_table(bind, 'decision_labels'):
        op.create_table(
            'decision_labels',
            sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
            sa.Column('event_id', sa.Text(), nullable=False),
            sa.Column('decision_id', sa.Text(), nullable=True),
            sa.Column('label', sa.Text(), nullable=False),
            sa.Column('tenant_id', sa.Text(), nullable=True),
            sa.Column('test_id', sa.Text(), nullable=True),
            sa.Column('variant', sa.Text(), nullable=True),
            sa.Column('evidence', sa.Text(), nullable=True),
            sa.Column('query_template', sa.Text(), nullable=True),
            sa.Column('created_at', ts_type, server_default=sa.func.now()),
        )
    else:
        for name in ('evidence', 'query_template'):
            if not _has_column(bind, 'decision_labels', name):
                op.add_column('decision_labels', sa.Column(name, sa.Text(), nullable=True))

    if not _has_table(bind, 'decisions_dlq'):
        op.create_table(
            'decisions_dlq',
            sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
            sa.Column('event_id', sa.Text(), nullable=False),
            sa.Column('payload', json_type),
            sa.Column('error', sa.Text()),
            sa.Column('attempts', sa.Integer(), server_default='0'),
            sa.Column('last_attempt', ts_type, nullable=True),
            sa.Column('created_at', ts_type, server_default=sa.func.now()),
        )

    if not _has_index(bind, 'events', 'idx_events_source'):
        op.create_index('idx_events_source', 'events', ['source'])
    if not _has_index(bind, 'events', 'idx_events_type'):
        op.create_index('idx_events_type', 'events', ['event_type'])
    if not _has_index(bind, 'decisions', 'idx_decisions_verdict'):
        op.create_index('idx_decisions_verdict', 'decisions', ['verdict'])
    if not _has_index(bind, 'decisions', 'idx_decisions_tenant_created'):
        op.create_index('idx_decisions_tenant_created', 'decisions', ['tenant_id', 'created_at'])
    if not _has_index(bind, 'decision_labels', 'idx_decision_labels_tenant_created'):
        op.create_index('idx_decision_labels_tenant_created', 'decision_labels', ['tenant_id', 'created_at'])
    if not _has_index(bind, 'decisions_dlq', 'idx_decisions_dlq_event_id'):
        op.create_index('idx_decisions_dlq_event_id', 'decisions_dlq', ['event_id'])


def downgrade():
    bind = op.get_bind()
    if _has_index(bind, 'decisions_dlq', 'idx_decisions_dlq_event_id'):
        op.drop_index('idx_decisions_dlq_event_id', table_name='decisions_dlq')
    if _has_index(bind, 'decision_labels', 'idx_decision_labels_tenant_created'):
        op.drop_index('idx_decision_labels_tenant_created', table_name='decision_labels')
    if _has_index(bind, 'decisions', 'idx_decisions_tenant_created'):
        op.drop_index('idx_decisions_tenant_created', table_name='decisions')
