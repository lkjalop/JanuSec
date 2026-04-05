# Validation Runbook

Comprehensive guide to execute, collect, interpret, and act on validation metrics for Hunt Lanes Phase 1 + Correlation.

## 1. Objectives
| Goal | Metric | Target | Failure Signal |
|------|--------|--------|----------------|
| Low Overhead | p95 added latency | ≤ 2 ms vs disabled | > 4 ms or ratio > 1.15 |
| Stability | Unhandled exceptions | 0 | Any pipeline crash / loop halt |
| Signal Quality | Lane emission rate | 1–10% (advisory) | >25% (too noisy) or <0.5% (too sparse) |
| Correlation Value | Correlation rule hits | Present only in synergy scenarios | Frequent in benign baseline |
| Precision Uplift (Simulated) | Variant vs baseline precision | + ≥5% absolute | No uplift or negative precision |
| Factor Hygiene | Unsuppressed noisy factor growth | Flat or decreasing | Runaway repeated noisy factor |
| Novelty Baseline | Distinct JA3 growth stabilization | Derivative slows after warm window | Constant rapid growth (instability) |
| Governance | Namespacing & tenant isolation | All lane factors prefixed; no cross-tenant rows | Mixed factors or tenant leakage |

## 2. Test Suite Execution Overview
You will run multiple layers:
1. Unit Tests (lanes + correlation) via `pytest`.
2. Replay Scenarios (synthetic behavioral sequences).
3. Precision Simulation (scoring uplift modeling).
4. Performance Bench (latency overhead at volumes).
5. Manual Governance Checks (namespacing, tenant isolation queries).
6. Failure Injection.

## 3. Commands (All)
```powershell
# 3.1 Run unit & integration tests
pytest -q

# 3.2 Replay individual scenarios
python scripts/replay_harness.py --scenario lateral_movement
python scripts/replay_harness.py --scenario brute_force
python scripts/replay_harness.py --scenario macro_rare_ja3
python scripts/replay_harness.py --scenario encoded_signed_synergy
python scripts/replay_harness.py --scenario exfiltration
python scripts/replay_harness.py --scenario dns_beacon

# 3.3 Precision simulation (baseline vs variant)
python scripts/precision_simulation.py --labels metrics/precision/labels_synthetic.csv --limit 300 --lane-weight 0.04 --corr-weight 0.06 --cap 0.15 > metrics/precision/simulation_result.json

# 3.4 Optional variant weights
python scripts/precision_simulation.py --labels metrics/precision/labels_synthetic.csv --limit 300 --lane-weight 0.02 --corr-weight 0.08 --cap 0.12 > metrics/precision/simulation_result_variant.json

# 3.5 Benchmarks (multi-volume)
mkdir metrics\bench 2>$null
python scripts/bench_hunt_lanes.py --events 1000 > metrics/bench/bench_1000.json
python scripts/bench_hunt_lanes.py --events 3000 > metrics/bench/bench_3000.json
python scripts/bench_hunt_lanes.py --events 5000 > metrics/bench/bench_5000.json

# 3.6 (Optional) Capture Prometheus snapshot (curl exporter)
curl http://localhost:8080/metrics > metrics/prometheus_snapshot.txt

# 3.7 Run single playbook harness (A1 sample) for emulation metrics
python scripts/run_playbook.py --playbook scripts/harness_playbook_sample.yaml --tenant demo --speed 15 > metrics/emulation/run_a1_summary.json

# 3.8 Evaluate false positive reduction (after generating before/after benign JSONL)
python scripts/fp_reduction_eval.py --before metrics/precision/benign_before.jsonl --after metrics/precision/benign_after.jsonl

# 3.9 Pilot readiness gate (requires emulation + fp reduction artifacts)
python scripts/pilot_readiness_check.py
```

## 4. Expected Artifacts
| Path | Description |
|------|-------------|
| `metrics/precision/simulation_result.json` | Baseline vs variant precision stats |
| `metrics/bench/bench_*.json` | Latency & overhead per volume |
| `metrics/prometheus_snapshot.txt` | Raw metrics for lane emission %, rule hits |
| `docs/launch_readiness_checklist.md` | Updated gating values |
| `docs/test_matrix.md` | Scenario definitions (reference) |
| `metrics/emulation/latest_summary.json` | Latest harness playbook detection coverage summary |
| `metrics/emulation/latest_trace.json` | Per-event trace with decisions per playbook run |
| `metrics/precision/fp_history.json` | FP density before/after suppression/gating |
| `metrics/precision/benign_before.jsonl` | Raw decision dump (pre-change benign) |
| `metrics/precision/benign_after.jsonl` | Raw decision dump (post-change benign) |

## 5. Parsing & Interpretation
### Precision Simulation JSON (Fields)
```json
{
  "baseline_precision": 0.X,
  "variant_precision": 0.Y,
  "per_factor": [ {"factor":"lane_process_lineage:...","tp":N,"fp":M,"conditional_precision":Z}, ... ]
}
```
Action Rules:
- If `variant_precision` < `baseline_precision`: DO NOT enable scoring; analyze highest FP factors.
- If lane factors show conditional_precision < 0.3 with >= 10 observations: mark candidate for suppression or refinement.
- If correlation factors show conditional_precision ≥ 0.7 with >= 5 observations: candidate for small positive weight (future phase).

### Bench JSON (Example)
```json
{
  "lanes_enabled": {"p95": 11.2},
  "lanes_disabled": {"p95": 9.8},
  "p95_overhead_ms": 1.4,
  "p95_ratio": 1.14
}
```
Action Rules:
- Overhead > 2ms OR ratio > 1.15 → investigate slow lane (check `hunt_lane_latency_ms` histogram buckets).
- Overhead < 1ms: green.

### Replay Harness Output
### Factor Promotion & Precision Window Endpoints
New endpoints to support governance & continuous improvement:

- `GET /api/v1/factors/promotion/status`: Observations & suppression state for lane/correlation factors (staging before true TP/FP attribution integration).
- `GET /api/v1/factors/quality/precision_window`: Sliding window precision snapshot (TP, FP, total) based on recent `/api/v1/feedback/factors` submissions.

Usage:
```powershell
curl http://localhost:8000/api/v1/factors/promotion/status -H "X-Tenant-ID: demo" | jq
curl http://localhost:8000/api/v1/factors/quality/precision_window | jq
```

Interpretation:
- Promotion status `candidate` → observed >=3 times & not suppressed.
- `observe` → currently suppressed; needs quality improvement before re-enable.
- Precision window <0.6 with >100 total → investigate top FP factors in window.

### False Positive Reduction Workflow
1. Run benign baseline to produce `benign_before.jsonl` (decision stream capture).
2. Apply suppression / gating changes (e.g., adjust env thresholds, quality manager resets).
3. Re-run benign corpus to produce `benign_after.jsonl`.
4. Execute `fp_reduction_eval.py` → writes `fp_history.json` with density reduction.
5. Gate pilot readiness via `pilot_readiness_check.py` requiring reduction >=30%.

### Emulation Harness
Harness script `run_playbook.py` executes YAML-defined adversary sequences with accelerated simulated time producing summary & trace artifacts. Integrate multiple playbooks (A2–A5) to raise coverage confidence.

SLA Measurement:
- `first_detection_time_s` in summary vs `sla.first_detection_within` in playbook.
- Coverage ratio per playbook aggregated at report time.

### Parallel Lane Execution (Planned)
Env var `HUNT_LANES_PARALLEL=true` (to be added) will enable concurrent lane runs for latency optimization; validate p95 improvement vs baseline with harness after implementation.
Contains `factors` list.
Required presence mapping:
| Scenario | Must Contain |
|----------|--------------|
| macro_rare_ja3 | `lane_process_lineage:office_macro_spawn_powershell`, `lane_ja3_novelty:ja3_rare`, `corr_office_ps_rare_ja3` |
| encoded_signed_synergy | `lane_process_lineage:powershell_encoded_command`, `lane_process_lineage:signed_to_unsigned_transition`, `corr_encoded_ps_signed_to_unsigned` |
| brute_force | `auth_fail_burst_5m` |
| exfiltration | `exfil_volume_high` |

If any missing → inspect pipeline stage order & lane registration logs.

## 6. Success vs Failure Scenarios
| Domain | Success Example | Failure Example | Primary Remediation |
|--------|-----------------|-----------------|---------------------|
| Precision Uplift | +6% variant precision | -2% precision change | Identify top FP lane factor; adjust suppression threshold or disable lane temporarily |
| Latency | Overhead 1.2 ms p95 | Overhead 3.5 ms p95 | Profile per-lane latency → optimize regex / reduce JA3 map size |
| Correlation Signal | Corr factors only in synergy scenarios | Corr factors appearing in benign baseline run | Tighten rule conditions, add frequency thresholds |
| Novelty Stability | JA3 novel rate drops after warm | Novel rate stays >20% events | Increase warm_min or cap max_entries lower |
| Governance | All lane_* prefixed | Raw unsuffixed factor appears from lane | Audit lane emission tagging (envelope add_emission) |
| Resilience | Lane exception logged, pipeline continues | Pipeline abort on lane exception | Wrap lane.run calls in try/except (already done; verify) |
| Suppression | Noisy synthetic factor suppressed after N FPs | Factor persists unsuppressed | Review quality manager thresholds |

## 7. Troubleshooting Flow
1. Identify failing metric (e.g., high overhead).
2. Pull relevant metrics subset (Prometheus histogram for offending stage/lane).
3. Reproduce with focused synthetic subset events to isolate lane.
4. If factor noise: Inspect per-factor TP/FP tallies (feedback or simulation) → add to manual suppression set or tweak heuristic.
5. If correlation noise: Add additional predicate (e.g., require both lane factors + low baseline frequency). Re-run synergy scenario to confirm still triggered.
6. Update test_matrix with remediation notes.

## 8. Escalation Rules (When to “Go Back”)
| Trigger | Escalation Action |
|---------|------------------|
| Variant precision uplift < 2% twice | Re-evaluate lane heuristics before enabling scoring |
| p95 overhead > 3ms after optimization attempt | Consider async offloading or batching lane persistence |
| >10% events produce correlation factor | Raise gating threshold or disable correlation stage until refined |
| JA3 novelty > 10% events after 24h | Increase warm_min; verify baseline variety data feed |

## 9. Checklist Update Instructions
After running all steps:
1. Open `docs/launch_readiness_checklist.md`.
2. Fill: p95 added latency, lane emission %, correlation conditional precision, suppressed lane factors count.
3. Append snapshot of `baseline_precision` vs `variant_precision`.
4. Commit with message: `chore(validation): populate readiness metrics`.

## 10. Optional Automation Hooks
Future (not implemented yet):
- GitHub Action to run `pytest` + replay harness scenarios on PR.
- Script to parse Prometheus snapshot -> JSON summary stored in `metrics/summary/latest.json`.

## 11. Final Go/No-Go Thresholds Summary
| Metric | Go Threshold | No-Go Trigger |
|--------|--------------|---------------|
| Precision uplift | ≥ +5% | < +3% |
| p95 overhead | ≤ 2ms | > 3ms |
| Corr factor conditional precision | ≥ 0.7 (with ≥5 obs) | < 0.5 (with ≥5 obs) |
| Lane emission rate | 1–10% | >25% or <0.5% |
| JA3 novel rate after warm | <5% of events | >10% |

## 12. Reporting Template (Executive)
```
Summary: Phase 1 advisory enrichment validated.
Latency: p95 added 1.4ms (ratio 1.12) – PASS
Precision: +6.1% uplift (baseline 0.41 -> variant 0.47) – PASS
Correlation: 2 rules firing only in designed scenarios – PASS
Noise: Lane emission 6.8% of events – PASS
Novelty Stabilization: Distinct JA3 growth derivative <3% after 800 events – PASS
Risks: Need real dataset confirmation for novelty, pending pilot.
Next Gate: Simulated scoring enable with weight caps (0.05 lane, 0.07 correlation).
```

## 13. What To Do If Everything Passes
- Prepare scoring weight experiment branch (do NOT merge): add small additive confidence deltas behind feature flag.
- Define rollback env vars (`ENABLE_LANE_SCORING`, `ENABLE_CORR_SCORING`).
- Maintain advisory mode until at least one real dataset pilot completes with feedback loop.

## 14. What To Do If Multiple Areas Fail
- Convene design review: identify if heuristics are too permissive or baseline dataset unrealistic.
- Prioritize: (1) Latency remediation, (2) False positive suppression, (3) Correlation tightening.
- Defer new lane additions until stabilization of current KPIs.

---
End of Runbook. Execute sections in order and populate artifacts before executive review.
