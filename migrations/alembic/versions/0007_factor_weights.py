"""add factor_weights table

Revision ID: 0007_factor_weights
Revises: 0006_access_log
Create Date: 2026-01-19 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0007_factor_weights'
down_revision = '0006_access_log'
branch_labels = None
depends_on = None


def _has_table(bind, name: str) -> bool:
    try:
        return sa.inspect(bind).has_table(name)
    except Exception:
        return False


def upgrade():
    bind = op.get_bind()
    if not _has_table(bind, 'factor_weights'):
        op.create_table(
            'factor_weights',
            sa.Column('factor', sa.Text(), primary_key=True),
            sa.Column('weight', sa.Float(), nullable=False),
            sa.Column('last_updated', sa.DateTime(timezone=True), server_default=sa.func.now()),
        )


def downgrade():
    bind = op.get_bind()
    if _has_table(bind, 'factor_weights'):
        op.drop_table('factor_weights')
