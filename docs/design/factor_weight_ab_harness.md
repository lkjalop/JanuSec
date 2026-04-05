# Factor Weight A/B Harness Design

## Objective
Experiment with alternative factor weighting strategies (risk attribution) safely, measure impact (score deltas, verdict boundary flips, precision proxies) and enable controlled activation.

## Use Cases
1. Validate new heuristic weight set before global promotion.
2. Compare adaptive ML-derived weights vs. static baseline.
3. Perform time-bound experiments (e.g., 24h) with rollback.

## Data Model
`data/factor_weight_sets.json`:
```json
{
  "active_set": "baseline_v1",
  "sets": {
    "baseline_v1": {"factor_a":1.0,"factor_b":0.5},
    "experiment_adaptive": {"factor_a":0.8,"factor_b":0.9}
  },
  "meta": {
    "baseline_v1": {"created_ts": 1732472000, "updated_ts": 1732472000, "notes":"Initial"},
    "experiment_adaptive": {"created_ts": 1732472500, "updated_ts": 1732472500, "notes":"Adaptive iteration"}
  }
}
```
Audit log: `data/weights_audit.jsonl` with entries:
```json
{"ts":1732472601,"action":"activate","user":"admin","old":"baseline_v1","new":"experiment_adaptive"}
```

## Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| /api/v1/weights/sets | GET | List sets + active |
| /api/v1/weights/sets | POST | Create/update set (payload: name, weights, notes) |
| /api/v1/weights/activate | POST | Activate set (payload: name) |
| /api/v1/weights/compare | POST | Compare sets on recent artifacts (payload: base, candidates[], limit) |
| /api/v1/weights/impact | GET | Aggregated delta stats window=24h |

## Risk Recompute Strategy
Reuse stored factor_contributions per artifact (weight-neutral):
```
risk_set = Σ (raw_signal_factor_i * weight_set[factor_i]) + bias
```
If absent raw_signal required → approximate using existing weight contribution / existing weight (inverse) with clamp.

## Comparison Output
`/weights/compare` sample:
```json
{
  "base":"baseline_v1",
  "candidates":["experiment_adaptive"],
  "artifact_sample":100,
  "results":[
    {"artifact_id":"a1","base_risk":0.62,"experiment_adaptive":0.71,"delta":0.09,"verdict_flip":true},
    {"artifact_id":"a2","base_risk":0.44,"experiment_adaptive":0.42,"delta":-0.02,"verdict_flip":false}
  ],
  "aggregate":{
    "mean_delta":0.031,
    "p90_abs_delta":0.12,
    "flip_rate":0.07,
    "positive_delta_ratio":0.68
  }
}
```

## Activation Safety
- Hard cap on absolute weight magnitude (env `FACTOR_WEIGHT_ABS_CAP`).
- Dry-run compare mandatory before first activation (store `last_compared_ts`).
- If flip_rate > threshold (env `AB_FLIP_RATE_MAX`) deny activation unless `force=true`.

## Metrics
- `ab_weight_activation_total{set}` counter.
- `ab_weight_compare_samples{set}` gauge (last run).
- `ab_weight_verdict_flips_total{direction}` (up,down).

## Security & Governance
- Only admin (X-Admin header) can create or activate sets.
- Audit every activation and deletion.

## Phase 1 Deliverables
- Persistence helpers (load/save/audit).
- Endpoints: list, create/update, activate, compare.
- Compare logic using last N artifacts from latest report snapshot.

## Phase 2 Ideas
- Persist per-factor correlation with flips.
- Weight auto-tuning loop (Bayesian or bandit) writing candidate sets.
- UI panel for risk delta histogram & boundary heatmap.
