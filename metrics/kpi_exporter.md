# Pilot KPI Instrumentation Pack

This document defines 6 core KPIs for the JanuSec pilot using existing Prometheus metrics (or light additions). Each KPI includes: purpose, definition, PromQL, interpretation, and Grafana panel suggestion.

## 1. False Positive Reduction Proxy
**Goal:** Track proportion of analyst negative feedback relative to total reviewed decisions.
**Assumption:** Factor feedback with vote = -1 signifies dubious / false contributing factors.
**Metric Inputs:** `factor_feedback_total{vote="1"|"-1"}` (add counter if not present yet) OR derive via SQL exporter.
**PromQL (rate over 24h):**
```
false_positive_ratio = sum_over_time(janusec_factor_feedback_votes{vote="-1"}[24h])
  /
  clamp_min(sum_over_time(janusec_factor_feedback_votes[24h]),1)
```
**Panel:** SingleStat + sparkline; green when < 0.15.

## 2. Drift Trend (Factor Frequency Divergence)
**Metric:** `factor_freq_js_divergence` (gauge updated by drift analyzer).
**PromQL:**
```
factor_freq_js_divergence
```
Add 7d moving average:
```
avg_over_time(factor_freq_js_divergence[7d])
```
**Interpretation:** Sustained growth may signal data distribution shift or emerging attack pattern.

## 3. Feedback Adoption Rate
**Definition:** Percentage of decisions receiving at least one feedback action within window.
**Needed Counter:** `decisions_total` (increment per decision) and `decisions_with_feedback_total`.
**PromQL (rolling 24h):**
```
rate(decisions_with_feedback_total[24h])
 / clamp_min(rate(decisions_total[24h]),1)
```
**Target:** > 0.35 during pilot (analyst engagement).

## 4. Confidence Distribution Shape
Track p50 / p90 / p99 of decision confidence.
**Assuming Histogram:** Implement `decision_confidence_bucket` (buckets e.g. 0.0,0.2,...1.0).
**PromQL (p90):**
```
histogram_quantile(0.9, sum(rate(decision_confidence_bucket[6h])) by (le))
```
**Panel:** Three small gauges; highlight drift toward extremes.

## 5. Pipeline Latency p95
**Metric:** `decision_processing_ms_bucket` (histogram) or existing gauge if present.
**PromQL:**
```
histogram_quantile(0.95, sum(rate(decision_processing_ms_bucket[5m])) by (le))
```
**SLO:** p95 < 1500 ms (adjust based on baseline SLAs).

## 6. Uptime / Availability
**Metric:** `up` for service + custom heartbeat gauge `pipeline_active=1`.
**PromQL (rolling 1h availability %):**
```
( sum(min_over_time(up{job="janusec_api"}[1h]) )
  / ignoring(instance) count(up{job="janusec_api"}) ) * 100
```
For single instance just show `up` and `absent(up)` alerts.

---
## Light Metric Additions (if not already present)
- `janusec_factor_feedback_votes{vote=\"1|-1\", tenant_id}` counter
- `decisions_total{tenant_id}` counter
- `decisions_with_feedback_total{tenant_id}` counter (increment first feedback event per decision)
- `decision_confidence_bucket{le}` histogram
- `decision_processing_ms_bucket{le}` histogram

## Grafana Panel JSON Stub (Excerpt)
```json
{
  "title": "Pilot KPIs",
  "panels": [
    {"type": "stat", "title": "False Positive Ratio", "targets": [{"expr": "sum_over_time(janusec_factor_feedback_votes{vote=\"-1\"}[24h]) / clamp_min(sum_over_time(janusec_factor_feedback_votes[24h]),1)"}], "fieldConfig": {"defaults": {"unit": "percentunit"}}},
    {"type": "graph", "title": "Drift (JS Divergence)", "targets": [{"expr": "factor_freq_js_divergence"}]},
    {"type": "stat", "title": "Feedback Adoption", "targets": [{"expr": "rate(decisions_with_feedback_total[24h]) / clamp_min(rate(decisions_total[24h]),1)"}], "fieldConfig": {"defaults": {"unit": "percentunit"}}},
    {"type": "stat", "title": "Confidence p90", "targets": [{"expr": "histogram_quantile(0.9, sum(rate(decision_confidence_bucket[6h])) by (le))"}], "fieldConfig": {"defaults": {"unit": "none"}}},
    {"type": "stat", "title": "Latency p95 (ms)", "targets": [{"expr": "histogram_quantile(0.95, sum(rate(decision_processing_ms_bucket[5m])) by (le))"}]},
    {"type": "stat", "title": "API Availability % (1h)", "targets": [{"expr": "( sum(min_over_time(up{job=\"janusec_api\"}[1h])) / ignoring(instance) count(up{job=\"janusec_api\"}) ) * 100"}], "fieldConfig": {"defaults": {"unit": "percent"}}}
  ]
}
```

## Label Cardinality Guidance
Limit tenant dimension to top N active tenants or aggregate else risk blow-up. Avoid embedding raw factor strings as labels; aggregate category or hashed bucket if needed.

## Alert Examples
```
# Drift sustained high
factor_freq_js_divergence > 0.35 for 30m

# Latency SLO breach
histogram_quantile(0.95, sum(rate(decision_processing_ms_bucket[10m])) by (le)) > 1.5e3

# Feedback engagement low
(rate(decisions_with_feedback_total[24h]) / clamp_min(rate(decisions_total[24h]),1)) < 0.15
```

## Next Steps
1. Add missing counters/histograms in metrics module.
2. Import JSON stub into Grafana, adjust UIDs, folder.
3. Iterate thresholds after 1–2 weeks of baseline data.
