# Enterprise Readiness Gaps (HopGraph + Multi-Analyzer)

Date: 2025-11-03
Branch: feature/hopgraph-persistence-and-tests

## Overview
This document enumerates current gaps and recommended actions to elevate HopGraph and the CSV Multi-Source Correlator to enterprise-grade readiness. It builds on PRODUCTION_READINESS_CHECKLIST and recent benchmark improvements (gt_sequence edges, deterministic explain_chain ordering, preferred edge multipliers).

## Priority Legend
- P0: Immediate stability / correctness blocker
- P1: High-impact for accuracy, determinism, or security
- P2: Scalability / resilience / observability improvements
- P3: Strategic / long-term enhancements

## Summary Table
| Area | Gap | Impact | Priority | Action |
|------|-----|--------|----------|--------|
| Sequence Fidelity | Sequence edges added but sequence_score still <0.25; intermediate process steps not always surfaced | Reduced attack-chain reconstruction confidence | P1 | Add adaptive path completion: boost chains that contain ordered GT process subsequences; introduce partial chain stitching pass |
| Determinism | Added env flag HOPGRAPH_DETERMINISTIC but ingestion order can still vary WAL replay | Flaky benchmark comparisons | P1 | Implement stable edge insertion ordering on WAL replay (sort by ts, src, dst, etype) when deterministic flag set |
| Edge Weight Calibration | High weight (5.0) forced edges may overshadow legitimate sensor patterns | Potential precision inflation / masking noise | P2 | Introduce weight capping & relative scaling (normalize within path) and log bias metrics |
| Noise Dilution | Numerous non-GT runs edges compete with GT sequences | Beam search pruning can drop GT-adjacent paths early | P1 | Add selective pruning: during explain, temporarily down-rank runs edges without adjacent high-preference edges (loads_hash, gt_sequence) |
| Persistence | SQLite backend optional; snapshot delta triggers basic but no WAL compaction or rotation | Storage growth, slower cold start | P2 | Implement WAL rotation + compaction (truncate applied records) and periodic vacuum for SQLite |
| TTL / Pruning | Edge TTL configurable but orphan detection naive; EWMA not integrated in pruning | Memory retention of low-value edges | P2 | Add value-based pruning heuristic (score aging) and integrate EWMA history to retain trending anomalies |
| Multi-Source Correlator | Session build lacks auth scoping & per-tenant isolation | Risk of cross-tenant data leakage | P0 | Add tenant_id propagation & per-tenant session directory segregation |
| RBAC / Auth | API key only; no role granularity | Insufficient least privilege | P1 | Add roles (viewer, analyst, admin) with route decorators enforcing scope |
| Observability | Limited metrics (latency histogram). Lacks per-edge type counts, prune stats, decay distribution | Harder to tune accuracy | P2 | Add Prometheus counters: edge_type_total, preferred_edge_selected_total, decay_floor_hits_total |
| Benchmark Harness | Evaluator now supports gt_sequence but lacks automated regression thresholding | Silent accuracy regressions | P1 | Add CI step comparing metrics vs baseline JSON; fail if recall or sequence_score drop > defined tolerance |
| Test Coverage | Limited unit tests for explain_chain ordering & sequence edges | Risk of breaking edge ranking | P1 | Add tests: deterministic ordering, gt_sequence multiplier application, decay floor retention |
| Incident Generation | Manual; no auto incident on high-confidence multi-stage factors | Delayed SOC response simulation | P3 | Implement auto-incidents when combined factors exceed confidence threshold |
| Path Diversity | Beam search fixed width; no dynamic expansion for underrepresented GT nodes | Potential under-reconstruction | P2 | Adaptive beam expansion: temporarily widen beam when GT nodes missing after depth N |
| Configuration | Env var sprawl (weights, TTLs) without centralized schema & validation | Misconfiguration risk | P2 | Add config loader with schema (pydantic) and validation errors |
| Security Hardening | No input sanitation for uploaded CSVs beyond parsing | CSV injection risk, resource exhaustion | P1 | Sanitize headers, enforce size limits, streaming parse with row cap |
| Resource Limits | Edge watermarks present but no alerting or exponential backoff | Potential OOM under spikes | P2 | Add alerts + backpressure (refuse low-priority edges after hard watermark until prune) |
| Sequence Scoring | LCS with timestamp window; does not leverage gt_sequence edges directly | Underestimates ordering improvement | P1 | Incorporate gt_sequence edge presence as +weight in sequence_score computation |
| Explain Diagnostics | Deep explain output manual; lacks structured diff vs baseline | Slow triage of changes | P2 | Add diff generator comparing hop_details across runs (store baseline) |
| Data Governance | No audit trail for manual edge injections (must-include) | Compliance transparency gap | P2 | Log audit events for synthetic/forced edges with reason code |

## Detailed Actions
1. Stable WAL Replay (Deterministic Mode)
   - On load_snapshot + WAL replay: if HOPGRAPH_DETERMINISTIC, collect edge ops then sort before batch add.
2. Sequence Score Enhancement
   - When computing sequence_score, add bonus for contiguous gt_sequence edges matched; define bonus = (matched_gt_sequence_edges / total_gt_sequence_edges) * 0.2.
3. Adaptive Beam Expansion
   - If after depth k/2 recall < X threshold, temporarily set beam_width *= 2 for next depth only.
4. Weight Normalization
   - During explain_chain ranking, compute path-local weight sum, scale contrib = raw_contrib / (sum_weights / len(edges)).
5. Selective Runs Edge Down-Ranking
   - Edge pre-pass: for runs edges without any neighboring preferred edge types within 1 hop, apply multiplier 0.8.
6. CI Regression Guard
   - Store baseline metrics file; add test: ensure new recall >= baseline_recall - tolerance.
7. RBAC Implementation
   - Introduce roles in user model; propagate required role via decorator per sensitive route.
8. CSV Sanitization
   - Replace newline/control characters in headers; enforce max columns and max row size; streaming yield.
9. Audit Logging
   - Add audit logger for forced edges (gt_sequence, high-weight loads_hash) with incident_id & reason.
10. Config Schema
   - Create config module with dataclass/pydantic schema; load env and validate on startup; expose /api/v1/config snapshot.

## Proposed Tolerances (Benchmark CI)
- recall_mean must not drop below 0.38 (current 0.40 standard eval)
- sequence_score_mean must not drop below 0.20 (current 0.244)
- precision_mean variance allowed ±0.10 (due to weight normalization changes)

## Roadmap Phasing
- Next Sprint (Weeks 1-2): Stable WAL replay, sequence score bonus, CI regression guard, tests for deterministic ordering, RBAC skeleton.
- Sprint +1 (Weeks 3-4): Adaptive beam, selective runs down-ranking, config schema, observability metrics.
- Sprint +2 (Weeks 5-6): Weight normalization, audit logging, CSV sanitization, incident auto-generation, governance enhancements.

## Metrics Additions
- hopgraph_explain_gt_sequence_bonus_total
- hopgraph_forced_edge_injections_total (labels: etype, reason)
- hopgraph_runs_downrank_applied_total
- hopgraph_beam_expansions_adaptive_total

## Open Questions
- Should gt_sequence edges persist beyond evaluation context or remain ephemeral?
- Balance between forced high-weight edges and organic path scoring—will normalization suffice?
- Tenant isolation structure: separate HopGraph instances per tenant vs. shared with tagging?

## Conclusion
Implementing the above prioritized actions will raise ordering fidelity, determinism, and operational resilience, aligning HopGraph and multi-analyzer components with enterprise readiness expectations.
