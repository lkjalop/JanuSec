-- Optional pgvector enablement and ANN index
-- Run after installing the pgvector extension in the Postgres instance.
-- Safe to run multiple times.
CREATE EXTENSION IF NOT EXISTS vector;

-- Ensure embedding column exists (already created in 0002) but reinforce type where possible
-- (If originally created without pgvector installed, it may be NULL typed; adjust if needed.)
-- ALTER TABLE factor_embeddings ADD COLUMN IF NOT EXISTS embedding vector(384);

-- Create approximate index (IVFFlat) for cosine similarity
-- You must ANALYZE the table after populating some rows for best performance.
CREATE INDEX IF NOT EXISTS idx_factor_embeddings_embedding_cosine 
    ON factor_embeddings USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

-- Helpful: analyze to prime planner (optional)
-- ANALYZE factor_embeddings;
