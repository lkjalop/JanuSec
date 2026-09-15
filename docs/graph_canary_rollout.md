## Graph & Correlation Canary Rollout Guide

This document outlines how to operationalize the new graph-enriched correlation rules and monitor their performance safely.

### Objectives
1. Validate stability (latency & memory) of graph enrichment.
2. Monitor rule hit volumes, FP/TP rates, and noisy outliers.
3. Provide guardrails for HopGraph latency and tenant metrics cardinality.

---
### Key Metrics & PromQL

#### Rule Hit Volume
Counter: `rule_hits_total{rule="<rule>"}` (already emitted by rules engine)

Top 10 rules (5m rate):
```
topk(10, sum by (rule) (rate(rule_hits_total[5m])))
```

#### (Planned) TP / FP Counters
Add counters (future implementation):
```
decision_true_positive_total{rule="<rule>"}
decision_false_positive_total{rule="<rule>"}
```

FP Rate (guarded denominator):
```
sum by (rule) (increase(decision_false_positive_total[24h]))
/
(sum by (rule) (increase(decision_true_positive_total[24h]))
 + sum by (rule) (increase(decision_false_positive_total[24h])) + 1)
```

Alert (Warning) FP rate >5% w/ volume > 30 hits/day:
```
(sum by (rule) (increase(decision_false_positive_total[24h])) > 30)
and
(sum by (rule) (increase(decision_false_positive_total[24h]))
 /
 (sum by (rule) (increase(decision_true_positive_total[24h]))
  + sum by (rule) (increase(decision_false_positive_total[24h])) + 1) > 0.05)
```

#### HopGraph Latency
Histograms: `hopgraph_reconstruct_latency_seconds`, `hopgraph_temporal_query_latency_seconds`

P95 (5m):
```
histogram_quantile(0.95, sum by (le) (rate(hopgraph_reconstruct_latency_seconds_bucket[5m])))
```

Warnings:
```
histogram_quantile(0.95, sum by (le) (rate(hopgraph_reconstruct_latency_seconds_bucket[10m]))) > 5
```
Critical:
```
histogram_quantile(0.95, sum by (le) (rate(hopgraph_reconstruct_latency_seconds_bucket[5m]))) > 30
```

Temporal query P95 warning:
```
histogram_quantile(0.95, sum by (le) (rate(hopgraph_temporal_query_latency_seconds_bucket[5m]))) > 2
```
Critical >10.

#### Queue / Processing Guardrails
If exposed metrics: `event_queue_depth`, `event_processing_latency_p95_ms` (add if missing) — (pseudo examples)
```
event_queue_depth > 0.85 * event_queue_capacity
```

#### Tenant Metrics Cardinality
When `ENABLE_TENANT_METRICS=1`, monitor unique series:
```
count(count by (__name__, tenant) ({__name__=~"hopgraph_.*|rule_hits_total"}))
```
Alert if sudden jump >2x 1h baseline.

---
### Dashboards (Suggested Panels)
1. Rule Activity: stacked area of rate(rule_hits_total[5m]) by rule (top N) + table with 24h totals.
2. Rule FP Rate: (after TP/FP counters added) – table showing 7d FP rate trend sparkline.
3. HopGraph Latency: P50/P95/P99 for reconstruct & temporal queries + request per second.
4. Graph Feature Coverage: ratio of events with graph_lateral_chain_len > 0 vs total evaluated events.
5. Decision Latency: P95 processing_time_ms distribution (if exported) + guardrail alert status.
6. Cardinality Monitor: time series of total series for hopgraph_* + rule_hits_total with tenant label.
7. Rule Coverage Progress: % of rules with at least one test vector + last CI pass time.

---
### Alert Policy Summary
| Category | Warning | Critical |
|----------|---------|----------|
| HopGraph reconstruct latency p95 | >5s for 10m | >30s for 5m |
| HopGraph temporal query latency p95 | >2s for 10m | >10s for 5m |
| Rule FP rate | >5% (>=30 FP/day) | >10% (>=50 FP/day) |
| Tenant metric cardinality growth | >2x 1h baseline | >3x 1h baseline |
| Queue utilization (if exported) | >85% 5m | >95% 2m |

---
### Operational Rollout Steps
1. Enable graph enrichment (already wired) and deploy to staging with only existing canary rules.
2. Observe HopGraph latency & memory for 24h.
3. Incrementally add rule batches (Initial Access + Execution first). Each batch: watch FP rate & latency for 48h.
4. Only enable tenant metrics once whitelist or hash buckets configured (`TENANT_METRICS_WHITELIST` / sampling envs).
5. After TP/FP counters implemented: baseline FP rates; adjust confidence_boost downward for broad rules exceeding targets.

---
### Future Enhancements
| Idea | Benefit |
|------|---------|
| Export decision_true_positive_total / decision_false_positive_total | FP monitoring & auto-tuning |
| Add per-rule latency instrumentation | Identify slow rules |
| Graph feature prefetch batching | Reduce reconstruct overhead for multi-event bursts |
| Feature store caching (redis) | Cross-process enrichment reuse |

---
### Implementation Notes
- All PromQL assumes default Prometheus metric naming; adjust if custom registry prefixes used.
- Add relabeling rules to drop high-cardinality tenant labels when whitelist not set.
- Consider recording rule hit cardinality with `record` rules for Grafana speed.

---
### Quick Checklist Before Prod
[] HopGraph reconstruct p95 <5s baseline
[] Rule FP rates within targets (<5%) for canaries
[] Tenant metrics behind whitelist or hashed buckets
[] Dashboards published & alert rules deployed
[] Runbook updated for on-call (link this doc)
