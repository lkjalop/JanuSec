"""add factor_feedback table

Revision ID: 0005_factor_feedback
Revises: 0004_pgvector_optional
Create Date: 2026-01-19 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0005_factor_feedback'
down_revision = '0004_pgvector_optional'
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
    if not _has_table(bind, 'factor_feedback'):
        op.create_table(
            'factor_feedback',
            sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
            sa.Column('event_id', sa.Text(), sa.ForeignKey('decisions.event_id', ondelete='CASCADE')),
            sa.Column('factor', sa.Text(), nullable=False),
            sa.Column('vote', sa.SmallInteger(), nullable=False),
            sa.Column('comment', sa.Text()),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        )

    if not _has_index(bind, 'factor_feedback', 'idx_factor_feedback_event'):
        op.create_index('idx_factor_feedback_event', 'factor_feedback', ['event_id'])
    if not _has_index(bind, 'factor_feedback', 'idx_factor_feedback_factor'):
        op.create_index('idx_factor_feedback_factor', 'factor_feedback', ['factor'])


def downgrade():
    bind = op.get_bind()
    if _has_table(bind, 'factor_feedback'):
        op.drop_table('factor_feedback')
