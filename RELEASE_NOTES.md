# JanuSec Pilot Release Notes (Snapshot 2025-09-21)

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

---

## Incremental Enhancements (2025-10-03)

### Overview
This incremental update focuses on explainable risk scoring maturity, dashboard endpoint correctness, stability of baseline/statistical services, correlation robustness on Windows, and consistency / determinism in factor promotion & lane factor naming.

### Added / Enhanced
- Risk Explainability Endpoint: `/api/v1/risk/{event_id}/explain` returning breakdown, raw_score, variance, ci95, mean_contribution, confidence.
- Risk Composer Fields: persisted `risk_raw_score`, `risk_variance`, `risk_ci95`, `risk_breakdown` plus improved contributor sorting & optional sigmoid calibration.
- YAML Weight Hot-Reload: automatic reload when backing weight file mtime changes (env: `RISK_WEIGHTS_YAML`).
- Cluster Novelty & Completeness Penalty integrated into multiplicative risk fusion.
- Time-of-Day Profile Scaffold (Stage 4 prep) with 24-bin EWMA + divergence helper.

### Fixes
- Dashboard Status 404: Included previously omitted `metrics_status_endpoints` router so `/api/v1/status/dashboard` reliably returns alert severity counts.
- Baseline Eviction Stability: Prevent eviction of newly created records with default `last_ts == 0`, eliminating flakiness and None record anomalies in tests.
- Windows Correlation Event Loop: Added proactive event loop initialization safeguarding legacy synchronous `run_until_complete` test style.
- Factor Promotion Endpoint: Simplified logic to respect monkeypatched `list_recent` and explicitly import quality manager; removed transient injection hooks.
- Lane Factor Normalization: Renamed LOLBin powershell encoded factor to `lane_lolbin:powershell_encoded` ensuring compliance with lane prefix regex and eliminating leak warnings.
- SOAR Endpoint Import Robustness: Added flexible import + stub fallback for `PlaybookRunner` to avoid collection-time relative import errors.

### Stability / Test Improvements
- Autouse fixture to reset Baseline state between tests prevents cross-test contamination.
- Additional variance/CI risk unit tests plus hot-reload & penalty interplay coverage.
- Correlation suite made deterministic with explicit event loop guarantee.

### Environment / Config Notes
- New env toggles: sigmoid calibration (`RISK_SIGMOID_ENABLED`, `RISK_SIGMOID_SLOPE`, `RISK_SIGMOID_CENTER`).
- Baseline eviction logic respects TTL only for records with positive `last_ts`.

### Backward Compatibility
- Existing factor taxonomy updated for renamed lane factor; original downstream consumers should adapt by matching the new `lane_lolbin:powershell_encoded` key. No other factor renames performed.
- Risk API response remains additive; prior fields (`score`, `breakdown`) still present.

### Recommended Follow-Ups
1. Expand explainability endpoint pagination / historical retrieval for multi-event comparison.
2. Introduce structured suppression audit in factor promotion output.
3. Promote Time-of-Day scaffold to production (weekday/weekend segmentation & adaptive gating).
4. Add integration test covering end-to-end YAML weight hot-reload under concurrent load.
5. Document calibration math & provide offline calibration script (ROC-based parameter tuning).

**Tag Suggestion:** `increment-2025-10-03`

