# Metrics Catalog (Single Pane Reference)

## Pipeline & Performance
| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| pipeline_stage_latency_ms | histogram | stage | Per-stage processing latency |
| decision_latency_ms | histogram | - | End-to-end decision latency |
| decision_time_ms_histogram | histogram | - | Inclusive pipeline+correlation timing |
| pipeline_events_total | counter | terminal | Events processed (terminal vs not) |

## Correlation & Lift
| hunt_correlation_rule_hits_total | counter | rule | Rule-specific hits |
| hunt_correlation_factors_total | counter | - | Synthesized correlation factors |
| hunt_corr_tp_before_total | counter | - | TP factor count before correlation |
| hunt_corr_tp_after_total | counter | - | TP factor count after correlation |
| hunt_corr_fp_before_total | counter | - | FP factor count before correlation |
| hunt_corr_fp_after_total | counter | - | FP factor count after correlation |

## Coverage & Routing
| alert_type_total | counter | alert_type | Count per alert type encountered |
| alert_routed_total | counter | route | fast_path/adaptive/correlated distribution |
| alert_coverage_ratio | gauge | - | Ratio targeted alert types seen at least once |

## Cost & Budget
| external_ai_tokens_used | gauge | tenant | Rolling token usage in window |
| external_budget_denial_total | counter | reason | Budget denials (soft/hard) |
| cost_ledger_inference_total* | counter | tier/model | (From ledger module) |

## Playbooks & Actions
| playbook_actions_total | counter | action,status | Action executions outcome |
| action_failures_total | counter | - | Generic action failures |

## FP & Feedback
| factor_feedback_up_total | counter | - | Positive factor votes |
| factor_feedback_down_total | counter | - | Negative factor votes |

## Observability & Drift
| distinct_mitre_tags | gauge | - | Distinct MITRE tags observed |
| embedding_avg_norm | gauge | - | Average embedding norm |
| factor_embedding_drift | gauge | - | Placeholder drift indicator |

## Budget & Reliability (Planned Additions)
| external_ai_invocations_total | counter | tenant | Invocation attempts (future) |
| soc_reliability_success_ratio | gauge | - | Calculated from soak harness |

## Usage Guidance
- Grafana: Use template variables for `rule`, `route`, `tenant` to build drilldowns.
- Lift Panels: Derive net lift = (tp_after - tp_before) / max(tp_before,1).
- FP Impact: (fp_after - fp_before) trend side-by-side with lift to ensure net signal positive.
- Budget Heatmap: external_ai_tokens_used per tenant vs soft_limit (export limits as config metric or static panel annotation).

## Export & Aggregation Notes
- Histograms: enable 5m rate and quantile aggregation for latency/time metrics.
- Counters: apply `increase(metric[1h])` for short-term windows.
- Gauge Snapshots: record daily for compliance evidence.

---
This catalog aligns backend metrics with the KPI dashboard mock for a cohesive single-pane experience.
