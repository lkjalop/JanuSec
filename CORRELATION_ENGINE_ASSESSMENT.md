# Correlation Engine Assessment (October 2025)

## Current Components
- HopGraph Lite: weighted, age-decayed edges, beam-search `explain_chain` scoring.
- Network Factors: beacon (multi-scale), DNS tunneling, SSL rarity/known-bad, port scatter, port scan, user-agent rarity, connection rate anomaly, device fingerprint rarity.
- Endpoint Factors: lineage rarity, exec burst, persistence artifacts, signed mismatch, LSASS access, privilege escalation, LOLBin registry + TF-IDF token rarity, obfuscation hints.
- Incident Aggregator: groups events, attaches graph explanation & framework enrichment (MITRE / STRIDE / DREAD / PASTA mapping).
- Enrichment: Factor → frameworks mapping used for narrative and UI panel.
- Caching: Explain cache (LRU + TTL) to amortize repeated path explanations.

## Strengths
| Area | Strength |
|------|----------|
| Latency | All correlating operations O(1) or bounded small (beam search small depth/width). |
| Explainability | Path-level chain detail (hops with age-decay & weight) + factor enrichment. |
| Extensibility | Pluggable node/edge types; WAL + snapshot for resilience. |
| Memory Safety | Edge caps per node, optional TTL pruning, LRU explain cache. |
| Multi-Scale Signal | Beacon detector multi-scale selection improves periodic detection robustness. |

## Gaps
| Gap | Impact | Notes |
|-----|--------|-------|
| No Temporal Chain Aggregator | Missed multi-event scenarios (e.g., staging → exfil) across minutes/hours. | Need sliding window aggregator with sequence rules. |
| Limited Negative Correlation | Some benign pattern clusters still raise elevated risk. | Add suppression correlation (benign co-occurrence templates). |
| Static Factor Weighting | Co-occurrence not dynamically boosting/dampening risk. | Introduce pairwise frequency vs expected scoring. |
| Lack of Campaign Clustering | Incidents remain isolated even if sharing infra (IP/domain/process). | Build campaign nodes for shared pivot sets. |
| Absent Feedback Loop | No analyst TP/FP ingestion to recalibrate correlations. | Feedback API + reweight. |
| Limited Cross-Lane Convergence | Endpoint and network factors not jointly forming composite meta-factors. | Implement meta-factor synthesis (e.g. internal lateral + new beacon). |
| No Confidence Attribution per Hop | Hard to debug why a path outranks another. | Add per-hop normalized contribution + cumulative path score explanation (JSON). |

## Proposed Enhancements (Phased)
| Phase | Enhancement | Detail | KPI |
|-------|------------|--------|-----|
| 1 | Temporal Window Sequencer | Maintain per-entity rolling event deque; match pattern templates. | +Recall of multi-stage chains |
| 1 | Factor Co-occurrence Matrix | Track N x N counts; score PMI-like weighting into risk delta. | Precision ↑; FP ↓ |
| 1 | Cache Hit/Miss Metrics | Instrument LRU explain cache. | Hit rate ≥70% |
| 2 | Campaign Graph Layer | Higher-level nodes linking incidents; dedup repeated infra usage. | Campaign clustering quality |
| 2 | Negative Correlation (Suppression) | Learned or rule-based benign pattern signatures. | FP rate reduction |
| 2 | Meta-Factors | Compose multi-lane pattern into single enriched factor (e.g., `corr:lateral_beacon_chain`). | Analyst triage speed |
| 3 | Feedback-Driven Weight Tuning | Online update of pair weights via Bayesian or EMA. | Drift responsiveness |
| 3 | Path Score Calibration | Fit logistic on path features vs labeled outcomes. | Path ranking AUC |
| 3 | GNN / Embedding Prototype | Node/edge embeddings for advanced anomaly ranking (offline scoring). | Additional high-signal chains found |

## Data Structures & Instrumentation Additions
- Co-occurrence counts: fixed-size dictionary keyed by sorted factor pair (evict low frequency when over limit).
- Temporal sequencer: per entity (host/process/IP) deque of (ts, factor_mask) with configurable horizon.
- Campaign clustering: union-find or incremental community detection keyed by shared pivot nodes.

## Risk Mitigations
| Risk | Mitigation |
|------|------------|
| Cardinality explosion (factor pairs) | Cap pair set; periodic pruning of lowest frequency; skip pairs with stop-list factors. |
| Memory growth (temporal deques) | Per-entity cap + time pruning + eviction after inactivity. |
| Feedback label sparsity | Active learning suggestions to prioritize ambiguous chains. |

## Metrics to Add
- hopgraph_explain_cache_hits_total / misses_total (counter, label=outcome)
- correlation_factor_pair_evals_total (counter)
- correlation_temporal_matches_total (counter)
- campaign_clusters_active (gauge)

## Acceptance Criteria for Phase 1
- Co-occurrence scoring behind feature flag; measurable impact on precision in replay harness.
- Temporal sequencer detects at least 3 defined multi-step scenarios (configurable patterns).
- Cache hit/miss metrics exposed & documented.

---
Owner: Correlation Working Group
Review Cadence: Bi-weekly
