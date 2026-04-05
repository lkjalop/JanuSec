# Deep Code Review & Refactor Roadmap (Initial Pass)

Date: 2025-09-25
Scope: FAST_LIVE_MODE ingestion + live heuristics, enrichment, metrics, evidence persistence.

## 1. Architecture & Cohesion
- Current split between legacy orchestrator (`main.SecurityOrchestrator`) and FAST_LIVE_MODE lightweight path causes duplicated concepts (alerting, evidence persistence, metrics). 
- Live subsystem modules (`live/`) are cohesive (rules_engine, dns_agg, asn_stats, domain_baseline) but lack a unifying service object; functions are imported ad‑hoc which increases hidden coupling.
- Alert persistence logic currently embedded inside endpoint ingestion handler; should be extracted to `live/alerts.py` with an `AlertRecorder` class encapsulating ring buffer + JSONL + rotation.
- Evidence rotation separated (good) but generation triggered in multiple places (server + orchestrator). Consolidate via a single `append_evidence(alert_id, evidence)` helper.

## 2. Duplication / DRY Issues
| Area | Duplication | Recommendation |
|------|-------------|----------------|
| Evidence JSONL append | Implemented in orchestrator earlier; now routed through `evidence_store` | Remove any legacy direct file writes; ensure orchestrator also uses store (done). |
| Slack dispatch wrappers | Both live ingestion and orchestrator use different notifier abstractions | Introduce common `NotificationBus` interface with adapters (Slack, future: Teams/Webhook). |
| Metric registration stubs | Repeated guard boilerplate across modules | Add `metrics_util.get_counter(name, help, labels)` helper returning stub if unavailable. |
| Enrichment calls | Duplicated geo lookup within ingestion block | Wrap into `enrichment.apply(event)` to ensure single call and caching. |

## 3. Error Handling & Resilience
- Broad `except Exception` blocks silently swallow issues (risk: hidden data loss). Adopt pattern: catch Exception as e; log at debug with context key (e.g., `log.debug("evidence_persist_failed", exc_info=e)`).
- Rotation errors are ignored; add metric `evidence_rotation_failures_total` for observability.
- Alert log writes: no fsync or batching; acceptable for MVP but add periodic flush or buffered writer for higher volume.

## 4. Performance Hotspots (Potential)
- Alert search performs linear scan of full JSONL on each request. For growth beyond ~50k lines, introduce simple index (e.g., host -> byte offsets) updated append-only, or rotate alerts log similar to evidence to bound size.
- Domain baseline frequency requires scanning an internal map (check complexity). If map grows large, implement approximate counting via Count-Min Sketch or periodic decay.
- ASN rarity tracking could saturate memory if many ASNs observed. Add TTL/decay (e.g., exponential decay factor per hour) to bound state.

## 5. Data Integrity & Consistency
- No schema version stored in JSONL records; add `schema_version` field to future writes for forward compatibility.
- Evidence records lack linkage back to alert JSONL line offset; optional improvement: add `alert_ref` field if evidence tied to alert id.
- Potential race: two threads writing alerts (only ingestion endpoint currently) — fine, FastAPI handler single-threaded per worker; if scaled horizontally, need external store or append service.

## 6. Security Considerations
- User-provided fields (proc_name, host) written directly to JSONL; ensure downstream consumers sanitize before rendering in HTML contexts.
- Missing rate limiting on alerts/search endpoints (DoS risk). Add simple token bucket per client IP.
- Lack of signature or hash for alert records compared to custody chain for orchestrated malicious events; consider lightweight HMAC of alert JSON with server secret for tamper detection.

## 7. Testing Gaps
- Boundary tests added for ASN/NXDOMAIN; add tests for: evidence rotation triggers (mock small limit), alert search pagination & filters, metrics counters increments (prometheus_client REGISTRY inspection), dedup suppressing duplicate alerts.
- Introduce property-based test for domain_baseline ensuring suspicious TLD detection remains stable across random domain sets.

## 8. Observability Enhancements
- Add per-rule hit counter automatically via decorator to eliminate manual increments.
- Expose ring buffer utilization (current size / max) as gauge `alert_ring_utilization`.
- Track evidence rotation count metric and last rotation timestamp gauge.

## 9. Refactor Roadmap (Phased)
### Phase 1 (Low Risk)
- Introduce `metrics_util` helper.
- Extract alert persistence to `live/alert_store.py`.
- Centralize enrichment call.
### Phase 2 (Medium)
- Implement state decay for ASN and domain baselines.
- Add alert log rotation & indexed search (host->positions map JSON sidecar).
### Phase 3 (Higher Impact)
- Unify orchestrator & FAST_LIVE_MODE alert generation via shared interface (e.g., `AlertService`).
- Introduce structured event bus for rule hits -> scoring -> alert decision pipeline (reduces inline logic in endpoint handler).
### Phase 4 (Hardening)
- Add HMAC integrity for alert records.
- Implement rate limiting & auth scopes for alert search endpoint.
- Integrate simple bloom filter to suppress obviously repetitive evidence bundles.

## 10. Prioritized Recommendations
1. Extract alert/evidence persistence into coherent services (reduces duplication & error swallows).
2. Add targeted metrics (rotation failures, alert_ring_utilization).
3. Add decay/TTL for analytic state to bound memory footprint.
4. Optimize alert search via rotation + host/time index before volume grows.
5. Harden error handling with structured debug logging & optional sampling.
6. Plan unification of notification channels behind interface to avoid drift.

---
Prepared by: Automated Review Assistant
Next Steps: Approve Phase 1 tasks and create corresponding implementation tickets.
