"""create append-only evidence kernel ledger

Revision ID: 0009_evidence_kernel
Revises: 0002_repair_decisions_table
"""

from alembic import op
import sqlalchemy as sa

revision = "0009_evidence_kernel"
down_revision = "0002_repair_decisions_table"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    if not sa.inspect(bind).has_table("evidence_ledger"):
        op.create_table(
            "evidence_ledger",
            sa.Column("record_id", sa.Text(), primary_key=True),
            sa.Column("tenant_id", sa.Text(), nullable=False),
            sa.Column("case_id", sa.Text(), nullable=False),
            sa.Column("record_type", sa.Text(), nullable=False),
            sa.Column("content_hash", sa.Text(), nullable=False),
            sa.Column("record_json", sa.JSON(), nullable=False),
            sa.Column("appended_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("idx_evidence_ledger_scope", "evidence_ledger", ["tenant_id", "case_id", "appended_at"])
        op.create_index("idx_evidence_ledger_type", "evidence_ledger", ["tenant_id", "case_id", "record_type", "appended_at"])
    if bind.dialect.name == "postgresql":
        op.execute("""
        CREATE OR REPLACE FUNCTION janusec_reject_evidence_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'evidence_ledger is append-only'; END;
        $$;
        DROP TRIGGER IF EXISTS evidence_ledger_no_update ON evidence_ledger;
        CREATE TRIGGER evidence_ledger_no_update BEFORE UPDATE OR DELETE ON evidence_ledger
        FOR EACH ROW EXECUTE FUNCTION janusec_reject_evidence_mutation();
        REVOKE UPDATE, DELETE, TRUNCATE ON evidence_ledger FROM PUBLIC;
        """)


def downgrade():
    pass
