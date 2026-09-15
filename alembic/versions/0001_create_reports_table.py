"""create reports table

Revision ID: 0001_create_reports_table
Revises: 
Create Date: 2026-01-23 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0001_create_reports_table'
down_revision = '0001_baseline'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'reports',
        sa.Column('id', sa.Text(), primary_key=True),
        sa.Column('payload', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
    )


def downgrade():
    op.drop_table('reports')
