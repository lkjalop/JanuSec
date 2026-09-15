# Deployment & Integration Options for Janusec

This document explains how customers can plug their own Postgres/pgvector and Neo4j instances, deploy Janusec on-premise, and control costs.

## 1. Connection Points
- `JNS_DB_DSN`: Postgres DSN used by pipeline & enrichment workers.
- `EMBED_MODEL`: optional sentence-transformers model name (if absent, hash fallback used).
- `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASS`: Neo4j connection for graph persistence.
- `FACTOR_SPECS_PATH`: path to factor specs YAML (allows per-tenant customization).

## 2. On-Premise vs Managed
- On-Premise: Customers deploy the stack (Postgres + pgvector + Neo4j) in their environment. Janusec components (collectors, runners, workers) run inside customer network. Benefits: minimal data egress, lower OpEx for provider, full control over logs/storage.
- Managed (SaaS): Customers provide ingestion endpoints or direct ship events via secure connectors. Provider may offer optional managed database hosting (chargeable). For cost control, prefer pushing only factor-enriched events rather than raw logs.

## 3. Integration Patterns
- Tenant-Hosted DB: Customers provide `JNS_DB_DSN` and set up DB user with RLS and permission for Janusec workers. Janusec writes events and creates embeddings in their DB.
- Tenant-Hosted Neo4j: Neo4j per customer recommended for large enterprises. Use `NEO4J_URI` to connect.
- Partial On-Prem: Host collectors and normalization on-prem; forward only normalized events (smaller) to managed backend.

## 4. Cost / FinOps Controls
- Data Minimization: Normalize & strip PII before sending to remote provider. Provide config `REDACT_FIELDS=['raw.payload','raw.body']`.
- Sampling: For high-throughput sources, enable sampling or priority-based forwarding (e.g., only forward events flagged with 'high' severity by local filter).
- Embedding Budgeting: Embedding is compute-heavy. Offer a toggle to disable embedding for low-priority tenants or schedule off-peak batch embedding windows.
- Retention Controls: Allow per-tenant retention policy via `events.retention_days` table.
  - API: `/api/v1/integrations/retention/config` accepts `{tenant_id, config:{retention_days, sampling_rate}}` and persists into `integration_configs` for operator automation.

## 5. Security Recommendations
- Use VPN or private links for managed DB connectivity. Use mutual TLS for Neo4j.
- Store credentials in secrets manager; rotate periodically.
- Use row-level security and separate DB roles for Janusec processes.

## 6. Operational Tips
- Run embedding worker as separate service with autoscaling for embedding throughput.
- Keep ivfflat indexes off until >1000 rows; tune `lists` param.
- Use `VACUUM` and partition pruning to keep query latency low.

## 7. Frontend Settings Page
- The frontend can expose a settings page to allow administrators to configure:
  - Postgres DSN and test connection
  - Neo4j endpoint test
  - Embedding mode toggle (model vs fallback)
  - Retention settings and sampling rate
- The settings page should not accept raw DB credentials in browser; instead, accept a connection test token that backend stores in secure config. The page can be `static/settings_integration.html` and call `/api/v1/integrations/{name}/config` to save.

## 8. Summary
- Best practice: give customers the option to host DB/graph; support normalization/local filtering to reduce cloud egress; provide UI toggles for embedding and retention to control cost.

