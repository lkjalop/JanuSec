# Service Level Objectives (SLOs)

## Scope
Applies to ingest → decision → enrichment → persistence pipeline and threat intel synchronization subsystem.

## Golden Signals & Objectives

| Domain | SLI | Objective (Target) | Alert Threshold |
|--------|-----|--------------------|-----------------|
| Availability | Successful API responses / total (5m) | 99.5% monthly | burn alert if error budget > 2% in 1h |
| Ingestion Latency | p95 decision end-to-end ms | < 2500 ms | warn > 2500 ms 3 intervals; page > 4000 ms |
| Decision Accuracy (Proxy) | Malicious verdicts confirmed / total malicious (weekly) | > 0.9 | investigate < 0.85 |
| Intel Freshness | % feeds synced within TTL | > 95% | alert if < 85% 15m |
| Intel Failure Streak | max failure streak any feed | < 3 | alert >= 5 |
| Queue Backlog | queue_depth / max_size | < 0.7 | alert >= 0.9 |
| Error Rate | 5xx responses / total (5m) | < 1% | alert >= 3% |
| Retention Job Health | purge success last run | 100% | alert if missed 2 intervals |
| Circuit Breaker Trip Rate | trips / minute | < 2 | alert >= 5 |
| Tracing Coverage | Spans recorded / requests | > 80% | backlog < 60% |

## Metric Mapping

| Metric | Type | Labels | Notes |
|--------|------|--------|-------|
| decision_latency_ms | Histogram | - | Base end-to-end ms |
| decision_time_ms_histogram | Histogram | - | Secondary distribution |
| ingest_decision_latency_seconds | Histogram | - | Legacy ingest latency |
| intel_sync_latency_seconds | Histogram | source | (_SYNC_LAT internal) |
| intel_feed_failure_streak | Gauge | source | Used for failure streak SLO |
| intel_source_age_seconds | Gauge | source | Freshness derived: age < TTL |
| ingest_buffer_depth | Gauge | - | Compare to max queue size |
| events_processed_total | Counter | verdict | Accuracy proxy w/ validation sample |
| processing_errors_total | Counter | - | Error rate component |
| decision_latency_ms_bucket | Prom auto | - | p95 / p99 extraction |
| circuit_open_total (future) | Counter | circuit | To add for breaker trip rate |

## Alert Expressions (PromQL Examples)
```
# Ingestion latency p95 > 2.5s for 3 consecutive periods
histogram_quantile(0.95, sum(rate(decision_latency_ms_bucket[5m])) by (le)) > 2500

# Feed freshness (% feeds synced within TTL) < 85%
(count(intel_source_age_seconds < <TTL_PLACEHOLDER>) / count(intel_source_age_seconds)) < 0.85

# Failure streak alert
max(intel_feed_failure_streak) >= 5

# Queue backlog
ingest_buffer_depth / <MAX_QUEUE_SIZE> >= 0.9

# Error rate
sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) > 0.03
```

## Error Budget Policy
- Monthly budget for availability (99.5%) → 0.5% = 216 minutes downtime.
- Multi-window fast burn: trigger page if > 10% of monthly budget consumed in 1 hour.

## Remediation Runbooks (Pointers)
| Condition | First Steps |
|-----------|-------------|
| Latency p95 spike | Check queue depth, circuit breaker stats, recent deployments |
| Feed freshness drop | Inspect `_failure_streak` & external feed status pages |
| Failure streak high | Temporarily disable feed via toggle endpoint, investigate credentials/endpoint |
| Queue backlog high | Enable backpressure, scale workers, inspect long-running decisions |
| Availability dip | Correlate with error logs (structured JSON) + tracing spans for hot spots |

## Future Enhancements
- Add circuit_open_total counter.
- Introduce dedicated SLI for enrichment latency.
- Correlate intel freshness with detection coverage score.
- Automate SLO report generation (weekly Markdown diff).

---
Document version: 1.0.0