# Per-Tenant Severity Rollup (Design Notes)

Goal: Provide aggregated severity & action outcome metrics per tenant for governance and ROI panels, and presentation visuals.

## Metrics
Per tenant, rolling window (default 24h / configurable):
- events_total
- severity_mean
- severity_p95
- block_rate (blocks / events_total)
- escalate_rate
- policy_block_rate (policy-block / events_total)
- threshold_block_rate (threshold-block / events_total)
- allow_rate
- quality_suppressed_rate (if quality < suppression threshold)

## Data Sources
- File audit log (fast recent decisions) OR DB table `decisions` for historic.
- Reasons array distinguishes `policy_block` vs `severity_threshold`.

## Computation Strategy (MVP)
1. Maintain an in-memory ring buffer per tenant (size N=5k) storing tuples (ts, severity, decision, reasons).
2. Periodic task (every 60s) aggregates window-limited stats.
3. Expose endpoint `/metrics/severity/rollup?tenant_id=&window=24h`.

## Environment Overrides
- ROLLUP_WINDOW_DEFAULT (e.g., `24h`)
- ROLLUP_MAX_BUFFER (default 5000)

## Future Enhancements
- Persist to time-series (Prometheus or ClickHouse) for long horizon.
- Separate model explaining which factors most contributed to top decile severity.
- Multi-tenant comparison leaderboard (normalized by event volume).

## Presentation Slide Inclusion
Visuals:
- Sparklines: severity_mean & severity_p95
- Stacked bar: decision distribution (allow / escalate / block separated by policy vs threshold)
- Gauge: block rate vs target (e.g., containment efficiency)

## Open Questions
- Should escalations resolved as benign retroactively adjust stats? (Phase 2: maintain resolution verdict mapping.)
- Include quality distribution? Potentially as box plot overlay (later).

Document version: draft 0.1
