-- Access log for API calls (authenticated)
CREATE TABLE IF NOT EXISTS access_log (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ DEFAULT NOW(),
    subject TEXT,
    method TEXT,
    path TEXT,
    status INT,
    scopes TEXT[],
    ip TEXT,
    user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_access_log_subject ON access_log(subject);
CREATE INDEX IF NOT EXISTS idx_access_log_path ON access_log(path);
CREATE INDEX IF NOT EXISTS idx_access_log_ts ON access_log(ts);
