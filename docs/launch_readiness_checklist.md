# Hunt Lanes Phase 1 Launch Readiness Checklist

## 1. Functional Completeness
- [ ] EvidenceEnvelope emits lane & correlation factors
- [ ] Lane toggles work (global + per lane)
- [ ] Correlation rules (2) produce expected composite factors
- [ ] Explain endpoint shows provenance_groups & descriptions

## 2. Quality Gates
| Gate | Threshold | Status (Fill at run) |
|------|-----------|----------------------|
| p95 added latency | <= 2ms (bench script) |  |
| Lane emission rate | < 15% of events (initial) |  |
| JA3 baseline size stabilization | Growth derivative < 5% over 24h |  |
| Correlation factor precision | >= 70% conditional TP ratio |  |
| Suppressed lane factors | <= 5% of lane factors (healthy) |  |
| No pipeline errors from lanes | 0 in last 24h |  |

## 3. Data Validation
- [ ] 3–5 day replay run executed
- [ ] Precision simulation JSON stored (variant vs baseline)
- [ ] Entropy delta recorded (factor entropy before/after lanes)
- [ ] Lane factor conditional precision table reviewed

## 4. Risk & Mitigations
| Risk | Mitigation |
|------|------------|
| Novelty false spikes early | Warm baseline (warm_min) + advisory only |
| Factor spam from misparsed fields | Quality suppression layer + prefix namespace |
| Latency regression | Bench before enabling scoring weights |
| Overconfidence after scoring enable | Cap lane delta & correlation delta; simulation first |

## 5. Go/No-Go Criteria
- Precision uplift >= +5% OR triage time reduction evidence.
- No significant FN increase (<= 2% relative) in sampled labeled set.
- Latency gate passed.
- Analyst sign-off of top 10 lane & corr factors (clear descriptions).

## 6. Post-Launch Observability
Dashboards:
- Hunt Lanes Dashboard (emissions, latency, JA3 baseline)
- Correlation factor counts & conditional precision (future panel)
- Suppression gauge (track if lane factor suppression grows unexpectedly)

## 7. Rollback Plan
- Toggle `pipeline.hunt_lanes.enabled=false` -> immediate disable.
- If correlation noisy: set `pipeline.correlation.enabled=false`.
- Emergency disable path documented in runbook section.

## 8. Artifacts to Archive
- Bench results JSON
- Precision simulation output
- Replay scenario logs
- Dashboard snapshot
- Analyst review notes

## 9. Future Phase Hooks
- Weight promotion config file
- Additional lanes (LOLBin, low-slow beacon)
- ML insertion points (DGA, JA3 clustering) once gap proven

---
Fill checklist before enabling scoring influence for lane & correlation factors.
