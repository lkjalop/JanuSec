# Pipeline Stage Registry & Data Flow

This document describes the current detection pipeline stages executed via the `STAGE_REGISTRY` in `core/pipeline/stages.py` and how an event flows end-to-end.

## High-Level Flow
1. Ingestion (`/api/v1/events` or Zeek tail forwarder) queues raw events.
2. Event normalization & enrichment (fast path) occurs before pipeline invocation (basic host/user/proc/domain attributes).
3. Pipeline executes ordered stages from the registry. Each stage returns:
   - name
   - duration_ms
   - factors (list of factor strings)
   - confidence_delta (optional float)
   - terminal (bool) — if true, processing stops early
4. Confidence is blended (additive by default) and cumulative factors accumulate.
5. After terminal or completion, a `PipelineResult` is produced with timing list (attached dynamically) and factor list.
6. SSE decision stream publishes summary + stage timings; timeline endpoint stores last N for UI retrieval.
7. Policy / action engine may escalate, alert, or auto-block depending on confidence + policy.

## Current Registry Stages (Ordered)
| Stage | Purpose | Key Factors Emitted | Terminal Conditions |
|-------|---------|---------------------|---------------------|
| baseline | Basic heuristics / prior scores | baseline_* | None (informational) |
| regex | Pattern signatures (strings, cmdline) | regex_match:* | Possibly terminal if high confidence (future) |
| parent_child | Suspicious process lineage pairs | suspicious_parent_child_pair | No |
| endpoint | Endpoint hunter enrichment (file lineage etc.) | endpoint_* | No |
| auth_burst | Authentication burst anomalies | auth_burst_* | No |
| graph | HopGraph contextual relationships | graph_* | No |
| adaptive_pre | Adaptive tuner pre-adjustments | adaptive_* | (future) |
| packet_summary | Lightweight network summarization | pkt_* factors | No |
| beacon | Beaconing periodicity heuristics | beacon_periodic, beacon_low_jitter | No |
| egress | Egress EWMA spikes | egress_volume_spike | No |
| domain_novelty | Newly observed domains | new_domain_seen | No |

(Additional legacy logic such as correlation engine, embedding, clustering, mapping remains in legacy block; scheduled for migration into modular stages.)

## Confidence Blending Modes
Configured via `pipeline.blending.mode`:
- add (default): cumulative += delta (clamped)
- weighted_max: max(current, current + delta * 0.5)
- max: max(current, delta)

## Data Products & Telemetry
- Prometheus: `pipeline_stage_latency_ms`, `pipeline_confidence_progress`, rule hit counters, domain/asn distinct gauges.
- Summary Endpoint: `/api/v1/metrics/summary` exposes ingest rate, top rules, distinct counts, recent alert volume.
- Timeline Endpoint: `/api/v1/decisions/{id}/timeline` returns per-stage timing & factors (trimmed).
- SSE Stream: `/api/v1/stream/decisions` pushes decision summaries with truncated factors and stage timings.

## Alert Path
If confidence crosses policy thresholds or emitted factors intersect escalation policies:
1. Alert object created (JSONL rotation with hash chain integrity).
2. Notification dispatch (Slack/Teams/Webhook) if subscriber criteria met.
3. Auto-block (future) could trigger via action dispatcher based on actionable factor set (e.g., beacon + egress spike + rare domain).

## Latency Considerations
- Each stage records `duration_ms` (wall clock) inserted into the timeline.
- Metrics histogram per stage supports p50/p90 extraction (Grafana panel provided).
- Typical fast-path stages (< 2ms): baseline, parent_child, domain_novelty.
- Moderate stages (2–15ms): regex depending on pattern count, packet_summary.
- Heavier / optional (future staged): correlation, embedding (not yet migrated into registry).

## Future Migration Targets
- Correlation engine as `correlation` stage (with opt-in memory circuit breaker gating).
- Clustering dedupe stage.
- Mapping (MITRE/STRIDE) stage.
- Embedding semantic enrichment stage conditionally enabled by config.

## Memory & Circuit Breakers
A periodic RSS check can disable heavy correlation. When disabled, correlation stage will be skipped once migrated.

## Backup & Integrity
Artifacts (alerts/evidence) backed up by `scripts/backup_artifacts.py` producing a hash manifest for tamper detection.

## Extensibility
Add a new stage: implement `async def new_stage(event, ctx) -> StageResult` and append to `STAGE_REGISTRY` list in desired order.

## Factor Naming Conventions
snake_case descriptor with optional value suffix after ':' (numeric or categorical). Examples:
- egress_volume_spike
- cmd_rare_token_ratio:0.413

## Safety & Failure Handling
Stage errors are logged at debug and skipped—pipeline continues (best-effort resilience).

---
Generated: automated doc scaffold.
