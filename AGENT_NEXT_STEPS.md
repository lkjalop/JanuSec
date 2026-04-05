# Next Engineering Cycles – Actionable Guidance

## 1. Ingestion & UX
1. Add client-side progress + per-file row counts in upload zone.
2. Implement streaming pagination endpoint variant for >50MB CSV (chunked transfer / range).
3. Expose IoC enrichment toggles (hash lookup, passive DNS) per session.

## 2. Correlation & Graph
1. Migrate callers to `graph.unified.UG`; deprecate direct variant imports.
2. Add edge TTL + periodic decay for ephemeral variants (move to time-bucketed ring buffers).
3. Persist full HopGraph snapshots on size deltas (every N edges) instead of fixed interval.
4. Add `/api/v1/graph/trace?event_id=...` convenience wrapper performing node inference.

## 3. Temporal Modeling
1. Wire `GLOBAL_TEMPORAL_MODEL.update()` into event pipeline (post factor extraction).
2. Surface temporal score in decisions explain JSON and frontend modal.
3. Design feature vector schema (failed auth deltas, burst metrics, graph degree changes).
4. Evaluate lightweight Prophet / SARIMAX baseline before allocating GPU to TFT.

## 4. Feedback & Weight Adaptation
1. Persist factor outcome snapshots nightly; compute stability + drift metrics.
2. Add metric: factor_quality_weight_adjustments_total.
3. Implement safeguard caps: max +/- 20% weight shift per 24h.

## 5. Reliability & Backpressure
1. Add ingestion queue high-water alert webhook.
2. Implement adaptive sampling when queue utilization >95% (drop low severity factors first).
3. Add circuit breaker around external intel feeds (half-open retries).

## 6. Security Hardening
1. Enforce signed timestamps on admin endpoints (HMAC date window).
2. Add per-tenant RBAC scope claims to API key/JWT model.
3. Integrate basic anomaly detection on API usage (burst 4xx/5xx patterns).

## 7. Testing Strategy
1. Add property-based tests for CSV/Excel session pagination + artifact find.
2. Stress test HopGraph pruning with synthetic scale (100k edges) asserting latency bounds.
3. Add regression test for temporal model EWMA convergence.

## 8. Observability
1. New metrics: temporal_entities_total, temporal_avg_score, ingestion_file_failures_total{type}.
2. Structured log fields: graph_provider, temporal_score, queue_utilization.
3. Add /api/v1/diagnostics snapshot endpoint (aggregated subsystem stats JSON).

---
Short-Term Sequence (Weeks 1-2): 2.1, 3.1, 3.2, 8.1, 5.1

Medium-Term (Weeks 3-5): 2.2, 2.4, 3.3, 4.2, 5.2, 6.2

Foundation for TFT (Later): finalize feature registry + historical window persistence, then prototype TFT inference path behind feature flag.
