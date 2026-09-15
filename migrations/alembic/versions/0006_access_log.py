"""add access_log table

Revision ID: 0006_access_log
Revises: 0005_factor_feedback
Create Date: 2026-01-19 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0006_access_log'
down_revision = '0005_factor_feedback'
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
    scopes_type = postgresql.ARRAY(sa.Text()) if is_pg else sa.JSON
    if not _has_table(bind, 'access_log'):
        op.create_table(
            'access_log',
            sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
            sa.Column('ts', sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column('subject', sa.Text()),
            sa.Column('method', sa.Text()),
            sa.Column('path', sa.Text()),
            sa.Column('status', sa.Integer()),
            sa.Column('scopes', scopes_type),
            sa.Column('ip', sa.Text()),
            sa.Column('user_agent', sa.Text()),
        )

    if not _has_index(bind, 'access_log', 'idx_access_log_subject'):
        op.create_index('idx_access_log_subject', 'access_log', ['subject'])
    if not _has_index(bind, 'access_log', 'idx_access_log_path'):
        op.create_index('idx_access_log_path', 'access_log', ['path'])
    if not _has_index(bind, 'access_log', 'idx_access_log_ts'):
        op.create_index('idx_access_log_ts', 'access_log', ['ts'])


def downgrade():
    bind = op.get_bind()
    if _has_table(bind, 'access_log'):
        op.drop_table('access_log')
