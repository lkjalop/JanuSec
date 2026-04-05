# JanuSec Grafana Dashboards

This folder contains a prebuilt dashboard JSON for Guardrails & SLOs.

## Importing the Dashboard

1. Ensure your Prometheus data source is configured in Grafana and scraping your app's `/metrics` endpoint.
2. Import `janusec_guardrails_dashboard.json` in Grafana (Dashboards -> Import).
3. Select your Prometheus data source.

## Metrics Covered

- Guardrails Counters
  - playbook_failures_total and janusec_playbook_failures_total
  - policy_blocked_total and janusec_policy_blocked_total
  - rate_limit_dropped_total and janusec_rate_limit_dropped_total
- Rate-limit Gauges
  - janusec_rate_limit_rate_limited_pct
  - janusec_rate_limit_dlq_depth
  - janusec_rate_limit_p95_step_latency
- SLO Gauges
  - janusec_slo_success_rate
  - janusec_slo_errors_5xx_rate
  - janusec_guardrail_mttc_seconds
- Risk Additions
  - janusec_risk_offhours_total
  - janusec_risk_role_mismatch_total

## Prometheus Scrape Example

Add a scrape job for your app exposing metrics (replace host/port):

```
- job_name: janusec
  metrics_path: /metrics
  static_configs:
    - targets: ['localhost:8000']
```

## Panels Overview

- Stat panels for counters (totals)
- Gauges for percentages
- Time series for latency and long-running gauges

Adjust titles, query filters (e.g., by tenant), and time ranges as needed.
