# Routing & Confidence Calibration

## Overview
Confidence drives early disposition to minimize deep analysis cost. Calibration must be data-driven using replay + sampled production outcomes.

## Confidence Components
1. Baseline seed (pattern matches, static risk weights)
2. Incremental deltas (network, endpoint, compliance, clustering)
3. Negative deltas (benign heuristics, allowlists)
4. Risk amplifiers (asset criticality, repeated multi-link graph presence) – capped

Formula (initial heuristic):
```
confidence = clamp( base + Σ bounded_deltas )
```
Where each `bounded_delta` ∈ [-0.15, +0.20].

## Threshold Bands (Initial)
| Band | Range | Action |
|------|-------|--------|
| Malicious | ≥ 0.90 | Fast malicious path + playbook pre-check |
| Benign | ≤ 0.10 | Archive (metrics + custody only) |
| Suspicious | (0.10, 0.90) | Deep analysis stages |

## Weekly Calibration Workflow
1. Run scenario replay harness against labeled corpus.
2. Compute precision/recall at candidate threshold pairs.
3. Recommend new thresholds if precision drop < 5% and coverage ↑ ≥ 3%.
4. Produce calibration report (store with config digest).
5. Stage change; require approval if delta > 0.05 absolute.

## Metrics
| Metric | Meaning |
|--------|---------|
| `routing_decisions_total{path}` | Distribution of decisions across paths |
| `confidence_histogram` | Bucketed confidence values pre-finalization |
| `early_false_negative_suspect` | Count of later-escalated events initially marked benign in shadow mode |
| `calibration_precision` | Precision on replay set at current thresholds |
| `calibration_coverage` | Coverage / recall proxy |

## Shadow Evaluation Mode
- In shadow: events that would have been archived at benign threshold are still passed to deep analysis asynchronously to measure missed detections.
- Factor `shadow_miss` added if deep stage yields malicious classification while original path was benign.

## Confidence Attribution
To maintain explainability, attach top contributors:
```
confidence_breakdown: [
  {component: 'baseline_indicator', delta: +0.30},
  {component: 'asset_criticality', delta: +0.05},
  {component: 'allowlist', delta: -0.10},
  ...
]
```
Returned in API for analyst trust.

## Drift Monitoring
Compare weekly histogram vs prior week using Jensen–Shannon divergence; if > threshold (e.g. 0.15), raise factor `confidence_distribution_shift` & alert operations.

## Failure / Timeout Handling
If any module exceeds budget, add neutral delta (0) and factor `<module>_timeout` so calibration reports include timing pressure context.

## Guardrails
- Total positive amplification from criticality + multi-link graph ≤ +0.15 of final confidence.
- No single module can push across both thresholds (benign → malicious) alone unless baseline already above 0.75.

## Open Items
1. Should we differentiate confidence for *maliciousness* vs *uncertainty*? (Future: two-dimensional scoring.)
2. Add uncertainty quantification (e.g., variance estimators) in Phase ML.
