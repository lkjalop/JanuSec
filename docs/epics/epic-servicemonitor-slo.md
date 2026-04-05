Title: Prometheus Operator rollout + SLO rules

Context
- We ship ServiceMonitor/PrometheusRule templates behind flags.

Scope
- Validate labels/namespace selectors for Operator discovery.
- Provide a short operator install guide snippet and common troubleshooting.
- Expand SLO ruleset and align with `grafana/janusec_guardrails_dashboard.json` panels.

Acceptance Criteria
- ServiceMonitor scrapes API in target namespace; Jaeger ServiceMonitor scrapes when enabled.
- PrometheusRule evaluates without errors; alerts visible in Alertmanager.
- Docs updated with sample values and scrape label conventions.

