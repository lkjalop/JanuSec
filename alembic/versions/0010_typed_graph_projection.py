"""create append-only typed graph projections and graph-view receipts

Revision ID: 0010_typed_graph_projection
Revises: 0009_evidence_kernel
"""

from alembic import op
import sqlalchemy as sa

revision = "0010_typed_graph_projection"
down_revision = "0009_evidence_kernel"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    for table_name, id_name in (("evidence_graph_nodes", "node_record_id"), ("evidence_graph_edges", "edge_record_id")):
        if not inspector.has_table(table_name):
            op.create_table(
                table_name,
                sa.Column(id_name, sa.Text(), primary_key=True),
                sa.Column("tenant_id", sa.Text(), nullable=False),
                sa.Column("case_id", sa.Text(), nullable=False),
                sa.Column("projection_id", sa.Text(), nullable=False),
                sa.Column("semantic_id", sa.Text(), nullable=False),
                sa.Column("content_hash", sa.Text(), nullable=False),
                sa.Column("record_json", sa.JSON(), nullable=False),
                sa.Column("appended_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            )
            op.create_index(f"idx_{table_name}_scope", table_name, ["tenant_id", "case_id", "projection_id"])
    if not inspector.has_table("graph_view_receipts"):
        op.create_table(
            "graph_view_receipts",
            sa.Column("receipt_id", sa.Text(), primary_key=True),
            sa.Column("tenant_id", sa.Text(), nullable=False),
            sa.Column("case_id", sa.Text(), nullable=False),
            sa.Column("projection_id", sa.Text(), nullable=False),
            sa.Column("ledger_head_hash", sa.Text(), nullable=False),
            sa.Column("content_hash", sa.Text(), nullable=False),
            sa.Column("record_json", sa.JSON(), nullable=False),
            sa.Column("appended_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("idx_graph_view_receipts_scope", "graph_view_receipts", ["tenant_id", "case_id", "appended_at"])
    if bind.dialect.name == "postgresql":
        op.execute("""
        CREATE OR REPLACE FUNCTION janusec_reject_graph_projection_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'typed graph projections are append-only'; END;
        $$;
        DO $body$ DECLARE t text; BEGIN
          FOREACH t IN ARRAY ARRAY['evidence_graph_nodes','evidence_graph_edges','graph_view_receipts'] LOOP
            EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I', t || '_no_update', t);
            EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION janusec_reject_graph_projection_mutation()', t || '_no_update', t);
            EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON %I FROM PUBLIC', t);
          END LOOP;
        END $body$;
        """)


def downgrade():
    pass
