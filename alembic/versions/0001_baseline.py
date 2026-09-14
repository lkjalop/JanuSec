"""baseline migration

Revision ID: 0001_baseline
Revises: 
Create Date: 2026-01-24 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0001_baseline'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Baseline migration: no schema changes. This file marks the current DB
    # state as the baseline for future migrations. Use `alembic stamp head`
    # or keep this revision as the initial migration.
    pass


def downgrade() -> None:
    # Nothing to downgrade for baseline.
    pass
