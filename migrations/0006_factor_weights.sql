-- Stores aggregated factor weights derived from feedback
CREATE TABLE IF NOT EXISTS factor_weights (
    factor TEXT PRIMARY KEY,
    weight DOUBLE PRECISION NOT NULL,
    last_updated TIMESTAMPTZ DEFAULT NOW()
);
