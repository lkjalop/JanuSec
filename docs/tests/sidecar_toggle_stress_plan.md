# Toggleable Sidecar Threat Hunting: Stress & Validation Plan

## Objectives
1. Validate functional correctness across permutations (window, model flag, async, replay).
2. Quantify cost estimation accuracy (delta% distribution) and adaptive margin behavior.
3. Exercise replay provenance determinism (hash stability, replay_of annotation).
4. Confirm instrumentation increments: model tier selections, replay latency histogram, cost guard triggers, anomaly alerts, artifact failures (should remain zero under normal conditions).
5. Memory safety: HopGraph Light node/edge caps hold under synthetic load.
6. Budget gating reliability.

## Test Dimensions & Permutations
- Windows: 3h, 24h, 72h, 120h
- model_enabled: true/false
- async_run: true/false
- Replay: once per completed session

Total raw combinations: 4 x 2 x 2 = 16; stress harness samples subset (configurable) to avoid long runtime.

## Synthetic Data & Heuristics
Hunts currently generate minimal synthetic graph data; heuristic factors produced by fusion stubs. For richer synthetic variation:
- Optionally extend harness to inject pseudo-random branching factor by adding extra dummy nodes/edges before factor aggregation.
- Seed FinOps hourly costs to produce controlled variance scenarios:
  - Low variance: repeat 10 ±0.2
  - High variance: alternating 3, 20, 2, 25, ... (already used in estimator tests)

## Metrics Under Observation
| Metric | Expectation | Pass Criteria |
|--------|-------------|---------------|
| hunt_model_tier_selection_total | >= 1 per session | Count increases monotonically |
| hunt_replay_latency_seconds | Observed for synchronous replays | Non-empty histogram buckets |
| cost_guard_triggers_total | 0 or small (>0 only when projection > estimate+margin) | If triggered, factor cost_guard_triggered present |
| artifact_write_failures_total | 0 | No increments |
| anomaly_alerts_total{source="finops"} | 0 in stable synthetic; may be >0 if forced variance | Only increments when last hour > mean+2σ |
| finops accuracy history | New entries after hunts complete | Contains session estimate ids |
| HopGraph stats | Node/edge counts within caps | nodes <= max_nodes; edges <= max_edges |

## Replay Provenance
- Hash recomputation with identical parameters equals stored replay_hash.
- /hunts/replay/{session_id} response contains new session id and `replay_of` reference.

## Budget Gating
- Start with `budget_cap_units` below estimate → 400 error (rejection) captured in stress summary.

## Pass/Fail Thresholds
| Category | Pass Condition |
|----------|----------------|
| Replay determinism | 100% hash match on recompute in sample set |
| Estimation accuracy | Median absolute delta% < 15% for low variance windows |
| Margin adaptation | High variance scenario applies >= 20% margin tier |
| Memory safety | No OOM / process crash; compaction keeps caps |
| Gating | Rejection path reliably executed when cap < estimate |
| Artifacts | 100% of sessions have artifact file present |

## Execution Steps (Manual)
1. Start API server.
2. Run stress harness:
```bash
python -m scripts.sidecar_stress_test --base-url http://localhost:8000 --runs 4 > stress_output.json
```
3. Scrape metrics endpoint (`/metrics`) before and after run; diff counts.
4. Validate artifact directory contents:
```bash
ls artifacts/hunts | wc -l
```
5. Optional high variance injection: modify FinOps hourly rollups before a run to provoke anomaly alert.

## Automated Validation Outline (Pseudo)
```python
import json, re
with open('stress_output.json', 'r', encoding='utf-8') as fh:
  out = json.load(fh)
assert len(out['summary']) >= 4
median_delta = median(s['delta_pct'] for s in out['summary'] if s.get('delta_pct') is not None)
assert median_delta < 25
```

## Potential Enhancements (Future)
- Integrate factor coverage delta once baseline coverage tracker diff is implemented.
- Add parallel run mode with thread pooling to simulate contention.
- Introduce selective embedding simulation to project full HopGraph upgrade impact.

## Synthetic Data Needed Before Live
- Command line templates with benign vs suspicious variants.
- User pivot patterns (multi-host login sequences) to measure lateral_chain_density sensitivity.
- Cost spike scenarios (batch-injected inference tokens) to tune anomaly threshold (false positive control).

## Exit Criteria for Phase
All pass conditions satisfied across two consecutive stress runs with different random seeds and no artifact write failures.

```END_OF_PLAN```