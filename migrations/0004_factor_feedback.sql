-- Factor feedback table for analyst votes
CREATE TABLE IF NOT EXISTS factor_feedback (
    id BIGSERIAL PRIMARY KEY,
    event_id TEXT REFERENCES decisions(event_id) ON DELETE CASCADE,
    factor TEXT NOT NULL,
    vote SMALLINT NOT NULL, -- +1 thumbs-up, -1 thumbs-down
    comment TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_factor_feedback_event ON factor_feedback(event_id);
CREATE INDEX IF NOT EXISTS idx_factor_feedback_factor ON factor_feedback(factor);
