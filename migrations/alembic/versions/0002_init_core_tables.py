"""create core tables (events/decisions/alerts/audit_log)

Revision ID: 0002_init_core_tables
Revises: 0001_create_oauth_tokens
Create Date: 2026-01-19 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0002_init_core_tables'
down_revision = '0001_create_oauth_tokens'
branch_labels = None
depends_on = None


def _has_table(bind, name: str) -> bool:
    try:
        return sa.inspect(bind).has_table(name)
    except Exception:
        return False


def _has_index(bind, table: str, index_name: str) -> bool:
    try:
        for idx in sa.inspect(bind).get_indexes(table):
            if idx.get('name') == index_name:
                return True
    except Exception:
        return False
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
        )

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
            sa.Column('created_at', ts_type, server_default=sa.func.now()),
        )

    if not _has_table(bind, 'alerts'):
        op.create_table(
            'alerts',
            sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
            sa.Column('event_id', sa.Text(), sa.ForeignKey('events.id', ondelete='CASCADE')),
            sa.Column('verdict', sa.Text()),
            sa.Column('confidence', sa.Float()),
            sa.Column('severity', sa.Text()),
            sa.Column('factors', json_type),
            sa.Column('playbook_result', json_type),
            sa.Column('created_at', ts_type, server_default=sa.func.now()),
        )

    if not _has_table(bind, 'audit_log'):
        op.create_table(
            'audit_log',
            sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
            sa.Column('event_id', sa.Text()),
            sa.Column('action', sa.Text(), nullable=False),
            sa.Column('details', json_type),
            sa.Column('custody_hash', sa.Text()),
            sa.Column('prev_hash', sa.Text()),
            sa.Column('created_at', ts_type, server_default=sa.func.now()),
        )

    if not _has_index(bind, 'events', 'idx_events_source'):
        op.create_index('idx_events_source', 'events', ['source'])
    if not _has_index(bind, 'events', 'idx_events_type'):
        op.create_index('idx_events_type', 'events', ['event_type'])
    if not _has_index(bind, 'decisions', 'idx_decisions_verdict'):
        op.create_index('idx_decisions_verdict', 'decisions', ['verdict'])
    if not _has_index(bind, 'alerts', 'idx_alerts_event_id'):
        op.create_index('idx_alerts_event_id', 'alerts', ['event_id'])
    if not _has_index(bind, 'audit_log', 'idx_audit_event_id'):
        op.create_index('idx_audit_event_id', 'audit_log', ['event_id'])


def downgrade():
    bind = op.get_bind()
    if _has_table(bind, 'audit_log'):
        op.drop_table('audit_log')
    if _has_table(bind, 'alerts'):
        op.drop_table('alerts')
    if _has_table(bind, 'decisions'):
        op.drop_table('decisions')
    if _has_table(bind, 'events'):
        op.drop_table('events')
