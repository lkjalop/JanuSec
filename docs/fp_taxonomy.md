# False Positive (FP) Taxonomy

A structured classification of false positive causes to enable targeted suppression, tuning, and analyst workflow optimization.

## Goals
- Provide consistent labeling of FP root causes.
- Quantify distribution of FP categories over time.
- Drive prioritization of engineering remediation (highest volume & highest analyst friction first).

## Top-Level Categories
| Code | Name | Definition | Example Signal | Mitigation Tactic |
|------|------|-----------|----------------|-------------------|
| PARSING | Parsing / Incomplete Event | Missing or malformed fields lead to heuristic misfire | Truncated `cmdline` triggers encoded detection | Improve parser; add field presence guard |
| CONTEXT | Missing Context / Enrichment Gap | Alert raised without asset/user enrichment producing generic risk assumption | No `host_role` caused high severity escalation | Add enrichment gating or deferred escalation |
| THRESH | Threshold Miscalibration | Static threshold too low/high vs current baseline distribution | JA3 rare threshold during baseline surge | Adaptive percentile-based thresholds |
| CORR_NOISE | Correlation Noise | Rule fired on weak factor combination | Macro + rare JA3 in benign lab test | Add secondary factor / raise support count |
| MODEL_OVER | Model Over-Sensitivity | Local model flags benign anomalies repeatedly | IsolationForest on transient workload spike | Retrain with augmented benign patterns |
| DRIFT | Distribution Drift | Underlying feature shift not recalibrated | Surge in new JA3 hashes after update | Automated drift detection & retune |
| DUPLICATE | Duplicate / Replay | Same underlying cause produces multiple near-identical alerts | Replay events during reprocessing window | Dedupe window extension |
| STALE_SUPPRESS | Stale Suppression Rule | Old suppression retired event semantics | Suppression missed renamed process | Version suppression policies & audit |
| ENV_TEST | Test / Synthetic Residue | Test harness artifacts leaking into prod channels | Scenario tag not filtered | Channel / tenant segregation |
| UNKNOWN | Unknown / Unclassified | Insufficient data to categorize | - | Add required logging fields |

## Data Model (Proposed JSON Schema)
```json
{
  "alert_id": "string",
  "timestamp": "ISO8601",
  "factors": ["string"],
  "assigned_category": "PARSING|CONTEXT|THRESH|CORR_NOISE|MODEL_OVER|DRIFT|DUPLICATE|STALE_SUPPRESS|ENV_TEST|UNKNOWN",
  "analyst_id": "string",
  "notes": "string",
  "auto_detected": true,
  "confidence": 0.0,
  "enrichment_missing": ["host_role", "user_risk"],
  "original_severity": "low|medium|high|critical"
}
```

## Labeling Flow
1. Gather candidate FPs (analyst rejects or post-facto validation labels).
2. Run automated heuristics (see `scripts/fp_classify.py`).
3. Present unresolved / low-confidence to analyst for final classification.
4. Persist to FP repository (future: database table) and aggregate metrics.

## Metrics
| Metric | Description | Usage |
|--------|-------------|-------|
| fp_total | Total false positives in window | Volume trend |
| fp_category_ratio | Count per category / fp_total | Prioritization |
| fp_enrichment_gap_rate | FPs where enrichment_missing non-empty | Enrichment ROI |
| fp_drift_flag_rate | FPs coinciding with feature drift alert | Drift response tuning |
| fp_duplicate_rate | Duplicate-related FPs | Dedupe window tuning |

## Automation Heuristics (Initial)
| Heuristic | Category | Logic |
|-----------|----------|-------|
| Missing enrichment fields count >=2 | CONTEXT | If alert lacks ≥2 core fields (host_role, geo, user_risk) |
| Factor contains `macro` + benign outcome | CORR_NOISE | Correlation factor appears without support chain |
| IsolationForest anomaly score near benign boundary | MODEL_OVER | Score within narrow band around threshold |
| Repeated alert_id root hash within short window | DUPLICATE | Hash of (principal, factor-set) repeats |
| JA3 rare factor volume spike >X baseline | THRESH | Rare threshold not adaptive |

## Roadmap
- Phase 1: Flat file JSONL storage + daily aggregation.
- Phase 2: Persist to relational table w/ time series view.
- Phase 3: Feedback loop integration (auto-suppression suggestions).
- Phase 4: FP reduction KPI tied to cost per TP improvements.

*Living document; extend as new FP archetypes emerge.*
