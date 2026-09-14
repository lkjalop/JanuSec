-- Immutable, versioned graph projections derived from the evidence ledger.
CREATE TABLE IF NOT EXISTS evidence_graph_nodes (
    node_record_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, case_id TEXT NOT NULL,
    projection_id TEXT NOT NULL, semantic_id TEXT NOT NULL, content_hash TEXT NOT NULL,
    record_json JSONB NOT NULL, appended_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS evidence_graph_edges (
    edge_record_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, case_id TEXT NOT NULL,
    projection_id TEXT NOT NULL, semantic_id TEXT NOT NULL, content_hash TEXT NOT NULL,
    record_json JSONB NOT NULL, appended_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS graph_view_receipts (
    receipt_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, case_id TEXT NOT NULL,
    projection_id TEXT NOT NULL, ledger_head_hash TEXT NOT NULL, content_hash TEXT NOT NULL,
    record_json JSONB NOT NULL, appended_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_evidence_graph_nodes_scope ON evidence_graph_nodes(tenant_id, case_id, projection_id);
CREATE INDEX IF NOT EXISTS idx_evidence_graph_edges_scope ON evidence_graph_edges(tenant_id, case_id, projection_id);
CREATE INDEX IF NOT EXISTS idx_graph_view_receipts_scope ON graph_view_receipts(tenant_id, case_id, appended_at);

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
