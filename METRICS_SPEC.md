# Metrics Specification (Initial Catalog)

This document enumerates platform metrics, their intent, type, labels, and notes.
Namespace default: `janusec` (new metrics follow naming pattern: `<namespace>_<component>_<what>_total` for counters, `_seconds` for latency histograms, plain for gauges.)

| Metric | Type | Labels | Purpose | Notes / SLO Hook |
|--------|------|--------|---------|------------------|
| events_ingested_total | counter | source | Raw ingestion volume | Legacy (no namespace) – migrate to janusec_ingest_events_total |
| ingest_failures_total | counter | reason | Track ingestion errors | Error budget input |
| ingest_buffer_size | gauge | – | Current buffered events | Queue health |
| alert_ring_utilization | gauge | – | Alert ring usage fraction | Capacity planning |
| ingest_decision_latency_seconds | histogram | – | Ingest-to-decision latency | P95 < 2.5s (guardrail) |
| decisions_total | counter | verdict | Decision volume by verdict | Precision/recall modeling |
| notifications_sent_total | counter | channel,outcome | Notification success/failure | Delivery SLO |
| escalations_total | counter | reason | Escalation triggers | Runbook validation |
| scenario_matches_total | counter | scenario_id,status | Scenario evaluation footprint | Demand for correlation |
| janusec_scenario_eval_latency_seconds | histogram | – | Scenario evaluation latency | p95 < 50ms target |
| inference_calls_total | counter | tier,path,cached,success | Model invocation volume | AI cost / reliability tracking |
| inference_latency_ms (legacy) | histogram | tier,path | Model latency (ms) | Will normalize to seconds |
| inference_tokens_total | counter | tier,path | Token consumption | Cost ledger |
| janusec_build_info | gauge | version | Build/version presence | Value always 1 |
| janusec_metrics_scrape_ts | gauge | – | Last successful scrape ts | Updated by exporter (planned) |

## Guardrails & Dispatch Metrics

| Metric | Type | Labels | Purpose | Notes |
|--------|------|--------|---------|------|
| decisions_total | counter | decision,reason | Decision volume by decision type and reason | Emitted by dispatcher |
| decision_dispatch_latency_seconds | histogram | – | Time to execute dispatch path | Includes audit write and enqueue |
| rate_limit_rate_limited_pct | gauge | – | Fraction of requests queued due to rate limiting | From RL KPIs |
| rate_limit_errors_5xx_pct | gauge | – | Fraction of dispatch steps resulting in exceptions | From RL KPIs |
| rate_limit_avg_wait_to_execute | gauge | – | Average wait time in queue (s) | From RL KPIs |
| rate_limit_dlq_depth | gauge | – | Items currently expired or pending in DLQ | From RL KPIs |
| rate_limit_p95_step_latency | gauge | – | p95 latency of dispatch step execution (s) | From RL KPIs |
| rate_limit_dropped_total | counter | – | Total items dropped from RL queues due to TTL expiry | Monotonic counter |
| playbook_failures_total | counter | type | Failure taxonomy for sink operations | Types: slack_send_error, slack_enqueue_error, eclipse_post_error, eclipse_enqueue_error |
| policy_blocked_total | counter | connector | Count of messages blocked by classification/policy | e.g., connector=slack when CONFIDENTIAL/RESTRICTED |

## Planned / Not Yet Implemented
| Metric | Rationale |
|--------|-----------|
| janusec_queue_rejections_total | Backpressure visibility |
| janusec_per_tenant_rate_limit_hits_total | Fair use enforcement |
| janusec_certificate_anomalies_total | TLS hygiene monitoring |
| janusec_http_header_anomalies_total | App layer hygiene |
| janusec_scenario_risk_flags_total | High/critical scenario flags raised |
| janusec_correlation_rules_fired_total | Correlation engine coverage |
| janusec_correlation_temporal_matches_total | Temporal correlation lift |
| janusec_threat_intel_matches_total | MISP/OpenCTI IoC hits |
| janusec_pcaps_processed_total | Network ingestion scaling |
| janusec_evtx_events_parsed_total | Endpoint log parsing depth |

## Deprecated / Migration Targets
- `scenario_eval_latency_ms` -> `janusec_scenario_eval_latency_seconds`
- Legacy un-namespaced counters will gain `janusec_` prefixed siblings; dashboards migrate then legacy removed.

## Self-Test Endpoint
`GET /api/v1/metrics/self_test` returns missing expected metric names per `core.metrics.registry.expected_metrics()`.

## SLO Drafts
| Objective | Metric | Target |
|-----------|--------|--------|
| Pipeline Latency | ingest_decision_latency_seconds p95 | < 2.5s |
| Scenario Eval Latency | janusec_scenario_eval_latency_seconds p95 | < 0.050s |
| High Risk Scenario Flag Latency | (time from decision ts to flag factor insertion) | < 100ms |
| Ingestion Error Rate | ingest_failures_total / events_ingested_total | < 0.5% |

---
Version: 0.1
