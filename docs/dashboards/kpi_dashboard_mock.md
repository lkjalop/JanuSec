# KPI Dashboard (Mock Layout)

This page describes the single-pane executive KPIs and the Prometheus metric sources.

## Summary Tiles
| KPI | Current | Target | Metric Source | Notes |
|-----|---------|--------|---------------|-------|
| Benign Suppression Precision | 0.985 | ≥0.98 | validation_metrics.json | Audit delta injected |
| Correlation Lift (TP) | 1.4 | ≥1.3 | hunt_corr_tp_* / hunt_corr_fp_* | Delta view: (tp_after - tp_before)/tp_before |
| Gray Recall | 0.87 | ≥0.90 | validation_metrics.json | Scenario expansion pending |
| High Recall | 0.96 | ≥0.98 | validation_metrics.json | Edge variants pending |
| Time-to-Decision p95 (ms) | 420 | <500 | decision_time_ms_histogram | Export histogram quantile |
| Alert Type Coverage Ratio | 0.62 | ≥0.80 | alert_coverage_ratio | Driven by target set size |
| External AI Token Rate (per hr) | 0 (mock) | budget ≤ threshold | cost ledger | Add budget manager gating |
| Playbook Action Success % | 100% | ≥99% | playbook_actions_total | (success / total) |
| Reliability (week) | - | ≥99% | soc soak report | Harness artifact |

## Graph Panels
1. Decision Latency Distribution: `decision_time_ms_histogram` quantiles (p50/p90/p95).
2. Correlation Lift Trend: Derived series (tp_after - tp_before) & (fp_after - fp_before).
3. Coverage Ratio Over Time: `alert_coverage_ratio` gauge scrapes with push to time series via recording rule.
4. Route Distribution: Stacked `alert_routed_total` (fast_path/adaptive/correlated).
5. Cost Ledger External vs Local: Aggregated from ledger summary endpoint (future REST wrap) or exported counters.
6. FP Taxonomy Composition: (When classifier produces taxonomy counters.)

## Data Refresh Cadence
| Data Type | Frequency |
|-----------|----------|
| Metrics scrape | 15s |
| Validation delta injection | Per audit run / nightly harness |
| Coverage matrix regeneration | Hourly or on deploy |
| SOC soak reliability summary | Rolling hourly window |

## Alert Coverage Drilldown
Leverages generated `docs/coverage/alert_coverage_matrix.md`.

## Action Items Panel
Dynamic list showing gaps vs targets:
- Gray Recall shortfall: +0.03 required
- Coverage Ratio: add hunts/instrumentation for missing alert classes
- Budget Policy: implement external budget manager before enabling external tier

## Implementation Notes
- For histogram quantiles with Prometheus: enable `histogram_quantile(0.95, sum(rate(decision_time_ms_histogram_bucket[5m])) by (le))`.
- Coverage ratio recording rule suggestion:
```
record: alert_coverage_ratio_timeseries
expr: alert_coverage_ratio
```
- Correlation lift panels should annotate when correlation FP delta tracking becomes active.

## Integrations Roadmap
| Feature | Dashboard Impact | Priority |
|---------|------------------|----------|
| External Budget Manager | Adds token burn rate & denial counters | High |
| Hunt DSL | Hunt TP lift panel | Medium |
| Knowledge Graph | Technique coverage vs decisions | Medium |
| RAG (Tiered) | Gray resolution success rate | Later |

---
This mock is a blueprint; once all metrics are live, capture Grafana JSON & embed snapshot.
