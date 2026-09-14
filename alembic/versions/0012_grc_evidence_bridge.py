"""create append-only GRC evidence bridge events

Revision ID: 0012_grc_evidence_bridge
Revises: 0011_infrastructure_truth
"""

from alembic import op
import sqlalchemy as sa


revision = "0012_grc_evidence_bridge"
down_revision = "0011_infrastructure_truth"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    if not sa.inspect(bind).has_table("grc_workflow_events"):
        op.create_table(
            "grc_workflow_events",
            sa.Column("event_id", sa.Text(), primary_key=True),
            sa.Column("tenant_id", sa.Text(), nullable=False),
            sa.Column("assessment_id", sa.Text(), nullable=False),
            sa.Column("case_id", sa.Text(), nullable=False),
            sa.Column("finding_id", sa.Text(), nullable=False),
            sa.Column("event_type", sa.Text(), nullable=False),
            sa.Column("content_hash", sa.Text(), nullable=False),
            sa.Column("record_json", sa.JSON(), nullable=False),
            sa.Column("appended_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index(
            "idx_grc_workflow_scope", "grc_workflow_events",
            ["tenant_id", "assessment_id", "case_id", "finding_id", "appended_at"],
        )
    if bind.dialect.name == "postgresql":
        op.execute("""
        CREATE OR REPLACE FUNCTION janusec_reject_grc_workflow_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'GRC workflow events are append-only'; END;
        $$;
        DROP TRIGGER IF EXISTS grc_workflow_events_no_update ON grc_workflow_events;
        CREATE TRIGGER grc_workflow_events_no_update
          BEFORE UPDATE OR DELETE ON grc_workflow_events
          FOR EACH ROW EXECUTE FUNCTION janusec_reject_grc_workflow_mutation();
        REVOKE UPDATE, DELETE, TRUNCATE ON grc_workflow_events FROM PUBLIC;
        """)


def downgrade():
    pass
