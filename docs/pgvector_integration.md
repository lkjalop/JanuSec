# pgvector Integration Guide (Phase 1)

## 1. Enable Extension
```sql
CREATE EXTENSION IF NOT EXISTS vector;
```

## 2. Table Alterations
```sql
ALTER TABLE events ADD COLUMN event_semantic_vector vector(64); -- fallback hash dim
ALTER TABLE events ADD COLUMN factor_context_vector vector(64);
```
Later switch to real model dims (e.g. 384 / 768) after sentence-transformers adoption:
```sql
ALTER TABLE events ALTER COLUMN event_semantic_vector TYPE vector(384);
ALTER TABLE events ALTER COLUMN factor_context_vector TYPE vector(384);
```

## 3. Upsert Workflow
1. Insert raw event (vectors NULL).  
2. Async worker loads events WHERE event_semantic_vector IS NULL LIMIT N.  
3. Generate embeddings via `EmbeddingService` and `UPDATE` rows.  

```sql
UPDATE events SET
  event_semantic_vector = $1,
  factor_context_vector = $2
WHERE event_id = $3;
```

## 4. Similarity Queries
```sql
-- kNN search for similar events (cosine)
SELECT event_id, domain
FROM events
ORDER BY event_semantic_vector <=> '[0.1,0.2,...]'::vector
LIMIT 10;

-- Factor context clustering candidate
SELECT event_id
FROM events
WHERE domain = 'iam'
ORDER BY factor_context_vector <=> '[...]'::vector
LIMIT 25;
```

## 5. Kill Chain Gap Filling
- Retrieve last N events for principal.  
- Embed current partial chain factors; kNN to find semantically similar events older than sliding window.  
- If similarity < threshold (e.g. 0.25 distance) treat as candidate link to extend chain horizon beyond 72h.

## 6. Maintenance
- Periodic `VACUUM (ANALYZE)` partitions.  
- Rebuild clusters (optional): maintain materialized view `event_vector_centroids`.  

```sql
CREATE MATERIALIZED VIEW event_vector_centroids AS
SELECT domain,
       pgml_kmeans_centers(ARRAY_AGG(event_semantic_vector), 8) AS centers
FROM events
GROUP BY domain;
```
(If pgml extension not available, perform k-means offline.)

## 7. Monitoring
- Track NULL vector count vs total for backlog sizing.  
- Latency SLO: embedding completion < 2 minutes post-ingest (p95).  

## 8. Security & Isolation
- Per-tenant queries use `WHERE tenant_id = $tenant`.  
- Consider row-level security: attach embedding update role with restricted `UPDATE` rights only for vector columns.  

## 9. Fallback Mode
- If model unavailable, hash-based 64-dim vectors still provide deterministic grouping (exact duplicates, token overlap).  
- Mark fallback usage via `events_meta` flag (`embedding_mode = 'hash' | 'model'`).  

## 10. Future Neo4j Bridge
- Store `event_graph_node_id` after path enrichment.  
- Hybrid queries: candidate events via vector similarity → graph traversal for lateral context.  

## 11. Change Control
- On dimension change, create new columns (e.g., `_v2`) then backfill to avoid long table locks, drop old after migration.

## 12. Indexing
No B-tree index on vector columns; rely on `ivfflat` after enough rows:
```sql
CREATE INDEX ON events USING ivfflat (event_semantic_vector vector_cosine_ops) WITH (lists=100);
```
Prerequisites: populate > 1000 rows first (pgvector requirement).

## 13. Observability
- Prometheus counters: `embedding_queue_length`, `embedding_latency_seconds_bucket`, `embedding_mode`.  
- Alert if queue length > threshold or latency p95 breached.

---
Version: 1
Prepared for: Phase 1 (hash fallback) → Phase 2 (semantic model).
