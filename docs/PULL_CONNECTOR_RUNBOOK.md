# Pull Connector Operator Runbook

This runbook guides operators through configuring and managing on-demand telemetry pulls via connector stubs (e.g., Purview) in the Missing Telemetry prototype.

## Overview
- Purpose: request targeted enrichment for entities (user/host/ip), persist results, and surface them via the API.
- Components:
	- Telemetry API: `/api/v1/telemetry_requests` (POST to enqueue, GET to list).
	- Worker: background async worker processes the queue and records results.
	- Store: DB-backed when available, otherwise in-memory (SQLite fallback in tests).
	- Metrics: Prometheus counters/histograms for request counts and latencies.

## Quotas & Rate Limits
- Respect provider quotas and per-tenant rate limits.
- Use `TelemetryCache` TTL to reduce duplicate pulls within a time window.
- Configure rate limits via environment:
	- `TELEMETRY_CACHE_TTL_SECONDS` (default ~600 via code) to reduce repeated requests.
	- For future connectors, add per-connector rate knobs (e.g., `PURVIEW_MAX_RPS`).

## Credentials
- Connector credentials should be added via existing integration config endpoints (e.g., `/api/v1/integrations/{name}/config`).
- For prototype stubs, no credentials are required; production connectors should read credentials from secure stores:
	- Environment variables or encrypted DB entries (`oauth_tokens`).
	- Azure: App Registration client ID/secret or certificate; audit via `/api/v1/integrations`.

## Interpreting Pull Logs
- API POST enqueues a request: the worker updates status to `processing` then `done`/`error`.
- Inspect status via GET endpoint:
	- Fields: `status`, `latency_ms`, `result_json`, `error`.
- Application logs and metrics:
	- Counter: `telemetry_pull_requests_total{connector,status}`.
	- Histogram: `telemetry_pull_latency_seconds{connector}`.

## Caching Behavior
- Keyed by `(domain, entity, window)`.
- Cache returns the last successful enrichment for the TTL period to avoid re-pulling.
- Eviction: time-based; entries beyond TTL are pruned on next access.

## Cost Tracking (Prototype)
- Each connector should expose a simple `estimate_cost_usd(domain, entity, window)`.
- For `purview_stub`, cost is a fixed `0.0005` USD per pull.
- Future: add per-connector pricing config and aggregate cost dashboards.

## Failure Modes
- `status=error` with `error` string; rely on counters to observe error rate.
- DB unavailable: store falls back to in-memory; requests still visible via GET but not persisted across restarts.
- Long queue: monitor queue depth via app state; scale workers or reduce RPS.

## Health & Observability
- Metrics exposed at `/metrics` (Prometheus scrape).
- Use `telemetry_pull_requests_total` for counts by outcome; `telemetry_pull_latency_seconds` for SLOs.
- Log context includes request `id`, `connector`, and entity identifiers in structured messages (future).

## Operations Checklist
- Configure credentials for production connectors.
- Validate quotas; set cache TTL appropriately.
- Monitor metrics; adjust worker concurrency if latency/backlog grows.
- Review DB migrations applied; ensure `telemetry_requests` table exists.

## API Examples
- Enqueue:
```
POST /api/v1/telemetry_requests
{
	"domain": "identity",
	"entity": "Alice@Example",
	"window": "24h",
	"connector": "purview"
}
```
- List recent:
```
GET /api/v1/telemetry_requests?limit=50
```

## Extending Connectors
- Implement `execute(domain, entity, window)` returning enrichment + latency + cost.
- Add caching key semantics and cost estimator.
- Wire credentials via `/api/v1/integrations/{name}/config` and secure storage.
