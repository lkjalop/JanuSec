"""create append-only outbound GRC dispatch receipts

Revision ID: 0013_grc_dispatch_receipts
Revises: 0012_grc_evidence_bridge
"""

from alembic import op
import sqlalchemy as sa


revision = "0013_grc_dispatch_receipts"
down_revision = "0012_grc_evidence_bridge"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    if not sa.inspect(bind).has_table("grc_dispatch_receipts"):
        op.create_table(
            "grc_dispatch_receipts",
            sa.Column("content_hash", sa.Text(), primary_key=True),
            sa.Column("tenant_id", sa.Text(), nullable=False),
            sa.Column("assessment_id", sa.Text(), nullable=False),
            sa.Column("case_id", sa.Text(), nullable=False),
            sa.Column("target", sa.Text(), nullable=False),
            sa.Column("idempotency_key", sa.Text(), nullable=False),
            sa.Column("record_json", sa.JSON(), nullable=False),
            sa.Column(
                "appended_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
        )
        op.create_index(
            "idx_grc_dispatch_scope",
            "grc_dispatch_receipts",
            ["tenant_id", "assessment_id", "case_id", "target", "appended_at"],
        )
        op.create_index(
            "uq_grc_dispatch_idempotency",
            "grc_dispatch_receipts",
            ["tenant_id", "assessment_id", "case_id", "target", "idempotency_key"],
            unique=True,
        )
    if bind.dialect.name == "postgresql":
        op.execute("""
        CREATE OR REPLACE FUNCTION janusec_reject_grc_dispatch_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'GRC dispatch receipts are append-only'; END;
        $$;
        DROP TRIGGER IF EXISTS grc_dispatch_receipts_no_update ON grc_dispatch_receipts;
        CREATE TRIGGER grc_dispatch_receipts_no_update
          BEFORE UPDATE OR DELETE ON grc_dispatch_receipts
          FOR EACH ROW EXECUTE FUNCTION janusec_reject_grc_dispatch_mutation();
        REVOKE UPDATE, DELETE, TRUNCATE ON grc_dispatch_receipts FROM PUBLIC;
        """)


def downgrade():
    pass
