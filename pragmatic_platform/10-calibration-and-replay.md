# Calibration & Replay Framework

## Purpose
Continuously validate routing thresholds, confidence distribution, and factor coverage while preventing silent regressions.

## Data Inputs
- Scenario corpus (JSONL) with optional labels: expected_recommendation, expected_factors.
- Production precision samples (subset of escalations).
- Factor occurrence logs (for coverage trends).

## Workflow (Weekly)
1. Freeze current config digests snapshot.
2. Run replay harness across scenario corpus.
3. Compute metrics: precision, coverage, factor hit ratio, confusion matrix.
4. Compare vs prior week; detect significant changes.
5. Generate calibration report (JSON + Markdown) persisted with snapshot.
6. If thresholds proposed → create change set requiring approval.

## Guard Conditions
| Condition | Action |
|-----------|--------|
| Precision drop > 5% | Auto-reject threshold change |
| Coverage drop > 10% | Flag regression; require investigation |
| Confidence distribution shift (JS divergence > 0.15) | Freeze threshold modifications |

## Replay Harness Enhancements
- Shadow mode: simulate alternative thresholds to produce candidate bands.
- Factor importance: compute frequency * (precision delta if removed) using ablation on sample subset.

## Report Contents
```
{
  meta: {timestamp, config_meta, corpus_size},
  thresholds: {current:{benign,malicious}, proposed:?},
  metrics: {precision:{...}, coverage:0.73, recall_proxy:0.68},
  factor_coverage: {infra:0.81, behavior:0.62, attack:0.55, policy:0.44},
  drift: {confidence_js:0.07},
  recommendations: ["Increase benign threshold to 0.12 to recover 3% coverage at <1% precision cost"],
  warnings: []
}
```

## Storage Paths
- `artifacts/calibration/reports/<date>.json`
- Latest symlink / pointer file for quick retrieval.

## Metrics Emitted
| Metric | Purpose |
|--------|---------|
| `calibration_run_duration_s` | Performance visibility |
| `calibration_precision` | Current precision snapshot |
| `calibration_coverage` | Coverage proxy |
| `calibration_reject_total` | Count of rejected threshold proposals |

## Open Questions
1. Introduce automated factor deprecation suggestion? (Phase 2)  
2. Keep per-scenario lineage (threshold version)? (Yes, include threshold stamp.)
