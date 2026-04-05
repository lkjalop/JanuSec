# Metrics & Dashboards

This repo exports Prometheus metrics via a unified registry (`api.metrics_init.REGISTRY`). The dispatcher and guardrails layers expose counters and gauges suitable for dashboards and alerting.

## Prometheus metric names

Namespace prefix (most helpers): `janusec_`

Key series:
- Rate limiting (gauges)
  - `janusec_rate_limit_rate_limited_pct`
  - `janusec_rate_limit_errors_5xx_pct`
  - `janusec_rate_limit_avg_wait_to_execute`
  - `janusec_rate_limit_dlq_depth`
  - `janusec_rate_limit_p95_step_latency`
  - Drops (counter): `rate_limit_dropped_total` and mirror `janusec_rate_limit_dropped_total`
- Dispatch
  - Latency histogram: `decision_dispatch_latency_seconds`
  - Decisions: `decisions_total{decision,reason}`
- Failure taxonomy & policy
  - `playbook_failures_total{type}` and mirror `janusec_playbook_failures_total{type}`
  - `policy_blocked_total{connector}` and mirror `janusec_policy_blocked_total{connector}`
- SLO gauges
  - `janusec_slo_success_rate` (0..1)
  - `janusec_slo_errors_5xx_rate` (0..1)
  - `janusec_guardrail_mttc_seconds` (EWMA of dispatch completion time)

## Grafana dashboard

Import `dashboards/guardrails_kpis.json` into Grafana.

Panels include:
- Rate-limit KPIs (bar gauges)
- Rate of dropped items (graph)
- Dispatch p95 latency (histogram_quantile)
- Failure taxonomy by type (bar gauge)
- Policy-blocked by connector (bar gauge)
- SLO gauges (bar gauge)

## Frontend wiring

If your frontend queries metrics by name, prefer the `janusec_*` mirrors added for policy blocks, playbook failures, and RL dropped so naming is consistent across modules.

## Notes

- The RL drain loop updates KPI gauges periodically; the dispatcher export mirrors counters so both legacy and namespaced metrics are available.
- In test environments, background loops are disabled by default to keep runs fast and deterministic. Set `ENABLE_BG_TASKS=1` to enable them.
