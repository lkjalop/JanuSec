"""create oauth_tokens table

Revision ID: 0001_create_oauth_tokens
Revises: 
Create Date: 2025-12-23 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0001_create_oauth_tokens'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'oauth_tokens',
        sa.Column('tenant_id', sa.String(length=255), primary_key=True),
        sa.Column('provider', sa.String(length=50), nullable=True),
        sa.Column('payload', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.func.now(), onupdate=sa.func.now()),
    )


def downgrade():
    op.drop_table('oauth_tokens')
