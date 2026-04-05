# Threat Hunting Cost & Scenario Playbook

This document augments the sidecar stress plan by modeling endpoint + network threat hunting scenarios over short (3h) and extended (7d) windows, projecting FinOps impact, cost balloon risks, and validation checkpoints.

## 1. Goals
- Provide structured hunt scenarios (endpoint + network) with factor hypotheses.
- Simulate event volume & enrichment intensity over 3-hour burst vs 7-day deep dive.
- Project costs under current estimator model; identify escalation triggers.
- Define measurable success signals that the sidecar + FinOps instrumentation "works".

## 2. Scenario Matrix
| Scenario ID | Domain | Window | Objective | Primary Signals | Risk Indicators |
|-------------|--------|--------|-----------|-----------------|-----------------|
| EP-BURST-1  | Endpoint | 3h | Detect rapid credential theft & lateral logins | multi_host_same_user_score, lateral_chain_density | Escalation storm, anomalous token spend |
| EP-BURST-2  | Endpoint | 3h | Identify novel process lineage (LOLBin abuse) | rare process lineage, process-child frequency deviation | High variance coverage delta |
| NET-BURST-1 | Network  | 3h | Flag beacon-like egress (JA3 / interval patterns) | connection periodicity, JA3 novelty factor | Excessive fusion expansion |
| EP-DEEP-1   | Endpoint | 7d | Correlate staggered privilege escalations | cross-day user pivot accumulation | Graph growth near memory cap |
| NET-DEEP-1  | Network  | 7d | Low-and-slow lateral scanning + DNS entropy | lateral_chain_density slope, DNS entropy factor | Estimator under-forecast (delta_pct > +35%) |
| HYBRID-DEEP-2 | Endpoint+Network | 7d | Multi-vector intrusion (process + anomalous egress) | fused factors union set size | Model tier escalation churn |

## 3. Synthetic Data Projections
Assumptions (tunable):
- Baseline events per hour (endpoint+network aggregated): 8,000 (already encoded in estimator).
- Fusion density (candidates / events): 0.002 (current placeholder).
- Model call ratio (fusion subset) with model_enabled: 0.1.

### 3.1 3-Hour Burst
```
Events = 8,000 * 3 = 24,000
Fusion candidates = 24,000 * 0.002 = 48
Model calls (if enabled) = 48 * 0.1 = 4-5
Base cost units (example cost_per_1k ~ 1.0): ~24
Fusion cost (0.05 each): 48 * 0.05 = 2.4
Model cost (0.5 each): ~2.0 - 2.5
Projected total: ~28.5 - 29 (margin 10-15% low variance)
```

### 3.2 7-Day Deep Dive
```
Hours = 168
Events = 8,000 * 168 = 1,344,000
Fusion candidates = 1,344,000 * 0.002 = 2,688
Model calls (if enabled) = 268 (round) (with ratio 0.1)
Base cost units ≈ 1,344,000 / 1,000 ≈ 1,344
Fusion cost = 2,688 * 0.05 = 134.4
Model cost = 268 * 0.5 ≈ 134
Projected total ≈ 1,612 units
Adaptive margin (expected higher variance): 15–25%
High variance upper bound scenario (CV >= 0.5): margin ~403 units
```

### 3.3 Cost Balloon Risks
| Risk | Driver | Mitigation | Metric Watch |
|------|--------|-----------|--------------|
| Fusion Explosion | Mis-tuned fusion density (0.002 → 0.01) | Cap candidates per hour | cost_guard_triggers_total |
| Model Escalation Storm | Low confidence spiral | Minimum dwell time per tier | hunt_model_tier_selection_total trend |
| Under-Forecast Long Window | Non-linear weekend spikes | Rolling variance weighting | finops accuracy history delta_pct |
| Memory Pressure | HopGraph edges > cap | Early compaction + TTL | hopgraph stats vs cap |

## 4. FinOps Impact Modeling
### 4.1 Sensitivity Table (Illustrative)
| Parameter Change | New Value | Cost Multiplier | Notes |
|------------------|-----------|-----------------|-------|
| Fusion density +2x | 0.004 | ~1.07x | Fusion cost minor but model follow-on increases risk |
| Model call ratio +2x | 0.2 | ~1.08x | Late tier escalation biggest contributor |
| Events/hour +50% | 12k | ~1.50x base | Elastic scaling needed for forecast reliability |
| Weekend Drop -40% | 4.8k | ~0.60x base | Estimator may overshoot; improves accuracy if CV lowers |

### 4.2 Forecast Accuracy Targets
| Window | Target Median Delta % | Action If Breached |
|--------|-----------------------|--------------------|
| 3h     | < 20%                 | Increase recent-hour weighting |
| 24h    | < 18%                 | Adjust variance smoothing |
| 7d     | < 25%                 | Switch to exponentially weighted moving avg |

## 5. Validation Checklist Per Scenario
| Check | Method | Pass Criterion |
|-------|--------|----------------|
| Estimation vs Actual | Compare `delta_pct` | Within target band (see above) |
| Cost Guard | Examine report factors | `cost_guard_triggered` only when projection > estimate+margin |
| Replay Determinism | Replay same session | `replay_of` set & replay_hash stable |
| Artifact Archive | Inspect file | JSON present & contains session + timeline |
| Tier Selection Metrics | /metrics scrape | Increment count >= 1 |
| Anomaly Alert (forced) | Inject variance then /finops/overview | `anomaly_alerts_total{source="finops"}` increments |

## 6. Forced Variance Procedure
1. Manually seed hourly costs alternating high/low in FinOps manager before a 7d estimation.
2. Invoke `/finops/estimate?window_hours=168` (via custom endpoint or extrapolation) if exposed.
3. Run a hunt; then call `/finops/overview` to test anomaly trigger.

## 7. Synthetic Data Extension Ideas
| Extension | Purpose | Effect |
|-----------|---------|--------|
| Add pseudo process lineage depth param | Stress lateral_chain_density | Potential cost guard activation |
| Vary user pivot fan-out | Multi-host user scoring sensitivity | Fusion candidate growth |
| DNS entropy strings set | Network anomaly simulation | Could justify tier escalation |

## 8. Determining "It Works"
A hunt sidecar + FinOps stack is considered functionally effective if:
1. Predictability: Median estimation delta within target thresholds across at least 5 sequential hunts (mixed windows).
2. Stability: No artifact write failures; memory caps never exceeded (no crash, stable compaction behavior).
3. Observability: All key counters present and non-zero where expected (tier selection, replay latency).
4. Safety: Budget gating rejects undersized budgets deterministically.
5. Adaptivity: High variance cost patterns produce higher margins (margin % increases with CV).
6. Replay Integrity: Replayed hunts produce comparable cost profile (<10% delta) absent random variance injections.
7. Guard Effectiveness: When triggered, guard reduces additional model tiers (manual inspection or future metric of prevented escalations).

## 9. Pass/Fail Table (Execution Run Template)
| Scenario | Est Delta % | Margin % | Guard Triggered? | Replay Delta % | Anomaly Fired? | Pass/Fail |
|----------|-------------|----------|------------------|----------------|----------------|-----------|
| EP-BURST-1 | 12 | 10 | No | 4 | No | PASS |
| EP-DEEP-1 | 23 | 20 | Yes | 7 | Yes | PASS |
| ... | ... | ... | ... | ... | ... | ... |

## 10. Data Capture Commands (Examples)
```bash
# Start hunts
python -m scripts.sidecar_stress_test --base-url http://localhost:8000 --runs 6 > stress_output.json

# Save metrics snapshot
curl -s http://localhost:8000/metrics > metrics_after.txt

# List artifacts
ls artifacts/hunts | wc -l

# Quick parse delta distribution (jq):
jq '[.summary[].delta_pct] | {median: (sort| .[length/2|floor]), max: max, min: min}' stress_output.json
```

## 11. Improvement Roadmap (Pre-Live)
| Priority | Action | Rationale |
|----------|--------|-----------|
| High | Add coverage delta implementation | Show detection lift from hunts |
| High | Add prevented escalation metric | Quantify cost guard savings |
| Medium | Move anomaly detection to EWMA + seasonality | Reduce false positives in diurnal cycles |
| Medium | Introduce selective embedding simulation flag | Safely model future HopGraph expansion cost |
| Low | Persist factor emergence counters | Support analyst promotion workflows |

## 12. Appendix: JSON Artifact Schema
```json
{
  "session": {"session_id":"...","window_hours":24,"estimate_units":123.45,"actual_units":129.0,"delta_pct":4.49,...},
  "timeline": [{"ts": 1737573881.23, "tier":2, "reason":"severity=..."}],
  "replay_hash": "sha256...",
  "factors": {"lateral_chain_density":0.12, "multi_host_same_user_score":0.3, "cost_guard_triggered":1.0}
}
```

## 13. Final Validation Gate Before Live Data
All Pass/Fail entries green, anomaly alerts only in induced high variance runs, and estimator CV-driven margin classification matches expected tiers (10/15/25%). Upon completion, freeze estimator parameters and version tag the FinOps module (`finops_v1_baseline`).

```END_OF_COST_SCENARIOS```