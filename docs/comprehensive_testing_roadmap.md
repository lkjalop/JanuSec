# Comprehensive Testing Roadmap (Phase 1 -> Pilot)

## Purpose
Establish a time-bounded, metrics-driven path to validate detection coverage, precision uplift, performance, and analyst value prior to executive (CEO) review and pilot enablement.

## Current Capability Snapshot
| Dimension | Status | Notes |
|-----------|--------|-------|
| Hunt Lanes | ✅ Process lineage, JA3 novelty | Advisory mode, prefixed factors enforced |
| Correlation | ✅ 3 rules (office_ps_rare_ja3, encoded_signed_unsigned, lateral_pivot_possible) | Adds synthesized factors |
| Replay / Harness | ✅ Playbooks A1–A5 | Coverage ratio & first-detection time produced |
| FP Evaluation | ✅ Density + weighted reduction | Severity weighting added |
| Summarization | ✅ Rule-based narrative | Future: ML summarizer upgrade |
| Precision Metrics | ✅ Sliding window endpoint | Requires feedback attributions feed |
| Parallel Lanes | ✅ Optional via env | Batch latency metric added |
| SOAR Path | ✅ No-op client skeleton | Eclipse adapter stubded |
| Governance | ✅ Tenant isolation, factor promotion telemetry | Memory breaker & suppression in place |
| Gaps | ❌ Exfil lane, DNS tunnel lane, persistence heuristics | Phase 2 scope |

## Remaining Phase 1 Focus (Pre-Pilot)
1. Expand harness to batch-run all playbooks and aggregate consolidated coverage report.
2. Add at least 1,000 benign events baseline (already scriptable) -> generate before/after FP runs.
3. Feed at least 300 feedback TP/FP factor attributions (synthetic) to populate precision window.
4. Document correlation uplift narrative in executive summary.

## Timeline (Assuming 1 Engineer Equivalent)
| Day | Tasks | Deliverables |
|-----|-------|--------------|
| 0 (Today) | Artifacts complete (playbooks A1–A5, generator, metrics) | This roadmap doc |
| 1 | Batch harness runner (multi-playbook), baseline benign run (before) | metrics/emulation/aggregate_<ts>.json |
| 2 | Apply gating/suppression tuning, after benign run, FP eval weighted | fp_history.json (>=30% reduction) |
| 2 | Populate synthetic feedback (script) -> sliding precision >0.65 | precision_window >=0.65 |
| 3 | Executive pack (coverage %, MTTD median, FP reduction, correlation cases) | exec_summary.md |
| 4 | Optional: Add A6 (persistence), A7 (DNS tunnel) placeholders | scenario docs |
| 5 | Final polish / dry run | readiness PASS |

Fast path (skip A6/A7): Ready for CEO review by Day 3.

## Coverage & Metrics Targets
| Metric | Target | Stretch |
|--------|--------|---------|
| Playbook Coverage (A1–A5) | ≥ 60% (gap exfil lane accepted) | 70% with added A6 |
| MTTD Median | < 30s | < 20s |
| FP Density Reduction | ≥ 30% | 40% |
| Weighted FP Reduction | ≥ 35% | 45% |
| Sliding Precision Window | ≥ 0.65 | ≥ 0.72 |
| Correlation Uplift Cases | ≥ 1 | ≥ 2 |
| Parallel Lane p95 Saving | ≥ 10% vs sequential | ≥ 15% |

## Execution Workflow (Automated Sequence)
1. `python scripts/generate_benign_corpus.py --count 600 --out metrics/precision/benign_before.jsonl --ingest --decisions metrics/precision/benign_before_decisions.jsonl`
2. Run playbooks (A1–A5): loop `scripts/run_playbook.py` → collect summaries.
3. Aggregate coverage & compute initial coverage ratio.
4. Apply suppression adjustments (if noisy factors visible).
5. Produce new benign corpus (after) & decisions JSONL.
6. `python scripts/fp_reduction_eval.py --severity-weights low=1,medium=1,high=1.5,critical=2 --before metrics/precision/benign_before_decisions.jsonl --after metrics/precision/benign_after_decisions.jsonl`
7. Submit synthetic feedback events to raise precision window.
8. `python scripts/pilot_readiness_check.py` for gating.
9. Generate executive pack.

## Synthetic Feedback Seeding (Outline)
Loop over decision JSONL; randomly label factors with 70% benign / 30% malicious distribution except for known high-signal ones (lineage macro, lateral pivot) to bias TP. Post to `/api/v1/feedback/factors` in batches.

## Executive Pack Contents
| Section | Contents |
|---------|----------|
| Overview | Coverage %, MTTD stats, FP reduction chart |
| Correlation Value | Before/after confidence examples, lateral pivot case timeline |
| Analyst Narrative | Summarizer samples for top 3 scenarios |
| Governance | Tenant isolation test results, suppression list |
| Performance | p95 latency sequential vs parallel, lane batch histogram snapshot |
| Roadmap | Phase 2 lane additions (exfil, DNS, persistence) |

## Phase 2 Glimpse (Post-Pilot)
- Implement exfil_lane (rolling window bytes, z-score anomaly + threshold).
- DNS tunneling lane (length entropy + query volume ratio).
- Persistence lane (scheduled task / service install heuristics).
- Beacon periodicity scorer (spectral / interval variance metric).
- ML summarizer upgrade (local embedding + template fill).

## Risks & Mitigations
| Risk | Impact | Mitigation |
|------|--------|-----------|
| Overfit synthetic corpora | Inflated precision claims | Introduce randomized benign permutations & hold-out set |
| Parallel race in lane emissions | Inconsistent factor ordering | Envelope structure immutable per emission; order not critical presently |
| Correlation factor explosion | Noise / FP inflation | Restrict rules; add frequency & diversity predicates |
| Memory growth from harness runs | Resource exhaustion | Periodically truncate decision cache / use DB queries |

## Go / No-Go Checklist (Final)
- [ ] Coverage >= target
- [ ] FP density + weighted reduction >= thresholds
- [ ] Precision window >= target
- [ ] Correlation uplift present
- [ ] No tenant leakage in queries
- [ ] Lane batch p95 within SLA
- [ ] Executive pack generated & reviewed

---
End of Roadmap.
