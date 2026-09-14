"""create append-only signed infrastructure truth snapshots

Revision ID: 0011_infrastructure_truth
Revises: 0010_typed_graph_projection
"""

from alembic import op
import sqlalchemy as sa


revision = "0011_infrastructure_truth"
down_revision = "0010_typed_graph_projection"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("infrastructure_truth_snapshots"):
        op.create_table(
            "infrastructure_truth_snapshots",
            sa.Column("snapshot_id", sa.Text(), primary_key=True),
            sa.Column("tenant_id", sa.Text(), nullable=False),
            sa.Column("kind", sa.Text(), nullable=False),
            sa.Column("source", sa.Text(), nullable=False),
            sa.Column("version", sa.Text(), nullable=False),
            sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
            sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
            sa.Column("receipt_hash", sa.Text(), nullable=False),
            sa.Column("payload_hash", sa.Text(), nullable=False),
            sa.Column("record_json", sa.JSON(), nullable=False),
            sa.Column("appended_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index(
            "idx_infrastructure_truth_scope",
            "infrastructure_truth_snapshots",
            ["tenant_id", "kind", "appended_at"],
        )
    if bind.dialect.name == "postgresql":
        op.execute("""
        CREATE OR REPLACE FUNCTION janusec_reject_infrastructure_truth_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'infrastructure truth snapshots are append-only'; END;
        $$;
        DROP TRIGGER IF EXISTS infrastructure_truth_snapshots_no_update ON infrastructure_truth_snapshots;
        CREATE TRIGGER infrastructure_truth_snapshots_no_update
          BEFORE UPDATE OR DELETE ON infrastructure_truth_snapshots
          FOR EACH ROW EXECUTE FUNCTION janusec_reject_infrastructure_truth_mutation();
        REVOKE UPDATE, DELETE, TRUNCATE ON infrastructure_truth_snapshots FROM PUBLIC;
        """)


def downgrade():
    pass
