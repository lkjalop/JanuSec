# Threat Sifter Pilot Release Notes (Snapshot 2025-09-21)

## Overview
This pilot snapshot delivers an operational threat sifting platform with progressive analysis, semantic factor exploration, analyst feedback loop, and foundational observability. It is engineered for reliability via graceful degradation and explicit auditability.

## Key Capabilities
- Progressive pipeline (baseline → regex → deeper analysis path)
- Decision engine with confidence scoring + feedback-driven weighting
- Factor embeddings (transformer or hash fallback) + optional pgvector ANN
- Similarity search & NLP query endpoints (scoped auth)
- Analyst consoles: vanilla + React/Vite (stream, similarity, stats, weights, drift, feedback)
- Drift telemetry (factor frequency Jensen–Shannon divergence)
- SSE decision stream for near-real-time triage
- Access logging (scoped endpoints, sampling) + chain-of-custody audit log
- Metrics: latency histograms, embedding norms, drift gauge, feedback counters
- Slack alert integration (optional)

## Auth & Security
- API key & optional JWT with scope model: `nlp.query`, `factors.search`, `feedback.write`
- Access log with subject, path, status, scopes (sampled via `ACCESS_LOG_SAMPLE_RATE`)
- Custody hash chaining for audit trail
- Graceful failure isolation (database, embeddings, external dependencies)

## Observability
- Prometheus metrics endpoint `/metrics`
- Drift gauge `factor_freq_js_divergence`
- Embedding quality gauge `embedding_avg_norm`
- Feedback counters (up/down) and factor weight inspection endpoint `/api/v1/weights/factors`
- Decision streaming via `/stream/decisions`

## Feedback Weighting
- Aggregates analyst votes every 5 minutes
- Confidence adjustment: `conf *= (1 + Σ factor_weight)` (bounded)
- Factor weights persisted in `factor_weights` table

## New Endpoints (Pilot Increment)
- `GET /api/v1/weights/factors`
- `GET /api/v1/metrics/embedding`

## Deployment (Docker Compose)
1. `docker compose up -d --build`
2. Run migrations inside container if not auto-run: `docker compose exec app python scripts/run_migrations.py`
3. Access API: http://localhost:8080/health ; React console (if served separately) via Vite dev or copy assets.
4. Prometheus: http://localhost:9090 ; Grafana: http://localhost:3000 (admin/admin or configured password)

## Environment Variables (Core)
| Variable | Purpose |
|----------|---------|
| `APP_DB_DSN` | Postgres connection override |
| `API_KEYS_JSON` | Static API keys with scopes |
| `ACCESS_LOG_SAMPLE_RATE` | Sampling fraction (0..1) |
| `EVENT_QUEUE_MAX` | Ingestion queue capacity |
| `API_QUERY_KEY` | Simple NLP endpoint key (legacy option) |
| `JWT_SECRET` / `JWT_AUDIENCE` / `JWT_ISSUER` | JWT auth (optional) |
| `SLACK_WEBHOOK_URL` | Slack alerting (optional) |

## Known Limitations / Deferred Roadmap
| Area | Deferred Item |
|------|---------------|
| Similarity | Hybrid ANN + precise rerank (candidate overfetch + rerank) |
| UI | Full design polish, role-based layout, historical trend charts |
| Drift | Multivariate drift (embedding space) and threshold alerting |
| Security | Granular RBAC beyond scopes, signed audit export |
| Performance | High-volume load testing & horizontal scaling docs |
| Tuning | Active learning loop beyond static weight aggregation |

## Risk & Mitigation Summary
| Risk | Mitigation |
|------|------------|
| pgvector absence | Fallback to in-process cosine over sample |
| Embedding model missing | Hash-based pseudo-embeddings ensure continuity |
| Feedback abuse | Weight clamp ±0.25; sampling & logs for review |
| DB latency spikes | with_retry exponential backoff; non-blocking pipeline |
| High access log volume | Sampling knob `ACCESS_LOG_SAMPLE_RATE` |

## Validation Checklist (Executed Pre-Release)
- Migrations applied through 0006
- Sample events ingested; decisions produced
- Similarity & NLP endpoints respond with scoped key
- Feedback votes adjust factor weights (verified via endpoint)
- Drift gauge populates (after window duration)
- SSE stream emits decisions

## Next Milestones (Post-Pilot)
1. Hybrid vector rerank & precision evaluation
2. Advanced drift analytics (embedding distribution shift, actionable alerts)
3. React console enrichment (filters, pagination, drill-down views)
4. Role-based policy & authZ expansion
5. Production resilience hardening (load, failover, multi-node)

---
**Tag:** `pilot-2025-09-21` (recommended creation)
**Integrity Hash (optional)**: run `python scripts/integrity_hash.py`

For questions or change requests, capture via a structured ticket referencing this release tag to maintain reproducibility.
