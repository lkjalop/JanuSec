# Metrics & SLOs

## Philosophy
Metrics drive calibration, reliability, and cost governance. Each metric MUST have an owner and an action when breaching thresholds.

## Core Domains
1. Volume & Routing
2. Latency & Resource
3. Quality & Precision
4. Stability & Drift
5. Cost & Capacity

## Metric Catalog
| Metric | Type | Labels | Purpose |
|--------|------|--------|---------|
| `routing_decisions_total` | Counter | path | Benign/malicious/suspicious distribution |
| `decision_latency_ms` | Histogram | stage | Per-stage processing time |
| `confidence_histogram` | Histogram | bucket | Confidence distribution trend |
| `false_positive_samples_total` | Counter | disposition | Analyst-tagged FP tracking |
| `calibration_precision` | Gauge | band | Threshold health |
| `factor_coverage_ratio` | Gauge | factor_family | Replay coverage per taxonomy family |
| `novelty_clusters_total` | Counter | flag | Emerging pattern density |
| `cluster_stability_avg` | Gauge | - | Macro emergence signal |
| `graph_high_degree_nodes` | Gauge | - | Infra risk expansion |
| `hot_tier_degraded_total` | Counter | - | Infra reliability issues |
| `custody_verification_fail_total` | Counter | - | Integrity breaches |
| `playbook_executions_total` | Counter | playbook,result | Automation adoption |
| `playbook_latency_ms` | Histogram | playbook | Execution performance |
| `storage_archive_latency_s` | Histogram | - | Archival efficiency |

## SLO Targets (Initial)
| SLO | Target |
|-----|--------|
| Benign fast-path fraction | ≥ 70% within 2 weeks |
| Malicious precision (escalated) | ≥ 80% after calibration cycle 2 |
| 95p end-to-end latency | < 120ms at 10K events/min synthetic |
| Replay precision regression | < 5% drop week-over-week |
| Integrity verification failures | 0 critical per quarter |
| Automation adoption (playbooks) | ≥ 50% of malicious decisions trigger playbook |

## Alert Rules (Examples)
| Condition | Action |
|-----------|--------|
| Benign fraction < 55% (24h) | Initiate calibration review |
| Confidence JS divergence > 0.15 | Flag drift & freeze threshold changes |
| Hot tier degraded > 3 times/hour | Escalate infra incident |
| Custody verification failures > 0 | Immediate security incident review |

## Dashboards
1. Executive: Routing distribution, malicious precision, automation adoption.
2. Operations: Latency waterfall, queue depth, error factors.
3. Detection Quality: Factor coverage, false positive sample trends, cluster stability.
4. Forensics & Integrity: Custody verification results, config digest changes.

## Data Retention for Metrics
- Prometheus long-term via remote write (optional) or daily downsampled snapshots.

## Open Questions
1. Should we track cost-per-event (CPU ms * $cost_unit)? (Later for pricing.)
2. Add energy / carbon metric for sustainability reporting? (Optional future.)
