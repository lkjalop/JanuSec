-- Factor embeddings storage
CREATE TABLE IF NOT EXISTS factor_embeddings (
    id BIGSERIAL PRIMARY KEY,
    event_id TEXT REFERENCES decisions(event_id) ON DELETE CASCADE,
    factor TEXT NOT NULL,
    embedding VECTOR(384), -- if pgvector installed; else store as JSON
    embedding_json JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_factor_embeddings_event ON factor_embeddings(event_id);
CREATE INDEX IF NOT EXISTS idx_factor_embeddings_factor ON factor_embeddings(factor);
