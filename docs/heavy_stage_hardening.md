Heavy Stage Hardening

This document summarizes strategies to make heavy pipeline stages safer in production.

1) Per-stage timeouts
- Already implemented: `StageDefinition.timeout_ms` and pipeline-level enforcement using `asyncio.wait_for`.
- Recommended: sensible defaults per stage (e.g., 2000-10000 ms) and per-tenant overrides.

2) Process isolation
- Run heavy stages in worker processes (multiprocessing or separate service) to bound memory and crash impact.
- Use a small RPC interface (gRPC/HTTP/Unix socket) to send events to worker pools.

3) Memory breakers
- Circuit-breaker pattern already exists (MemoryCircuitBreaker). Ensure breakers are checked before scheduling heavy stages and during execution.
- Add per-stage memory budget sampling (rss) and enforce via OS cgroups or process-limits.

4) Graceful degradation
- When under memory/CPU pressure, degrade by disabling `heavy` group via `pipeline.enabled_stage_groups` or using `heavy_skip_confidence` thresholds.
- Emit telemetry counters for disabled stages and skipped reason.

5) Observability
- Export metrics: stage durations, timeout counts, import-failure counts.
- Export logs and structured events when a heavy stage is skipped, timed out, or failed.

6) Security
- Sandbox artifact extraction and scanning in containers to prevent arbitrary code execution.

Implementation plan
- Short-term: tune `StageDefinition.timeout_ms` defaults, wire metrics for timeout counts, and add small worker pool prototype.
- Medium-term: implement process-isolated worker service for heavy stages and CI tests that simulate OOM/timeouts.

