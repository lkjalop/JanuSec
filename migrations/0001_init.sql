-- Initial schema for Threat Sifter Platform
-- idempotent-ish creates (use IF NOT EXISTS where supported)

CREATE TABLE IF NOT EXISTS events (
    id              TEXT PRIMARY KEY,
    source          TEXT,
    event_type      TEXT,
    severity        TEXT,
    ts_ingested     TIMESTAMPTZ DEFAULT NOW(),
    ts_original     TIMESTAMPTZ NULL,
    raw_payload     JSONB
);

CREATE TABLE IF NOT EXISTS decisions (
    event_id        TEXT REFERENCES events(id) ON DELETE CASCADE,
    verdict         TEXT NOT NULL,
    confidence      DOUBLE PRECISION NOT NULL,
    processing_ms   DOUBLE PRECISION,
    factors         JSONB,
    stage_timings   JSONB,
    custody_hash    TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (event_id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id              BIGSERIAL PRIMARY KEY,
    event_id        TEXT REFERENCES events(id) ON DELETE CASCADE,
    verdict         TEXT,
    confidence      DOUBLE PRECISION,
    severity        TEXT,
    factors         JSONB,
    playbook_result JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGSERIAL PRIMARY KEY,
    event_id        TEXT,
    action          TEXT NOT NULL,
    details         JSONB,
    custody_hash    TEXT,
    prev_hash       TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Helpful indexes
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_decisions_verdict ON decisions(verdict);
CREATE INDEX IF NOT EXISTS idx_alerts_event_id ON alerts(event_id);
CREATE INDEX IF NOT EXISTS idx_audit_event_id ON audit_log(event_id);
