-- Evidence Contract v1: append-only tenant/case ledger.
CREATE TABLE IF NOT EXISTS evidence_ledger (
    record_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    record_type TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    record_json JSONB NOT NULL,
    appended_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT evidence_ledger_hash_not_empty CHECK (length(content_hash) = 64 OR record_type = 'assessment_dag')
);

CREATE INDEX IF NOT EXISTS idx_evidence_ledger_scope
    ON evidence_ledger (tenant_id, case_id, appended_at);
CREATE INDEX IF NOT EXISTS idx_evidence_ledger_type
    ON evidence_ledger (tenant_id, case_id, record_type, appended_at);

-- PostgreSQL append-only enforcement. Owners should be separate from the
-- runtime role so a compromised application cannot disable this trigger.
CREATE OR REPLACE FUNCTION janusec_reject_evidence_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'evidence_ledger is append-only';
END;
$$;

DROP TRIGGER IF EXISTS evidence_ledger_no_update ON evidence_ledger;
CREATE TRIGGER evidence_ledger_no_update
BEFORE UPDATE OR DELETE ON evidence_ledger
FOR EACH ROW EXECUTE FUNCTION janusec_reject_evidence_mutation();

REVOKE UPDATE, DELETE, TRUNCATE ON evidence_ledger FROM PUBLIC;
