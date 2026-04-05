# JanuSec Platform Progress Report — HopGraph, CSV Analyzer, Pipeline & Kill Chain Alignment

Date: 2025-11-01
Branch: feature/hopgraph-persistence-and-tests
Author: Automated Analysis (GPT-5)

---

## Executive Summary

The platform has moved from ad-hoc in‑memory graph correlation and partially integrated enrichment toward a cohesive attack reconstruction stack (HopGraph + explainability + CSV/XLSX ingestion). Core detection pipeline (13 stages) is stable with sub‑500ms p95 latency, high-tier recall at 96%, benign suppression at 98.5%, and correlation lift at 1.4x. Remaining strategic gaps center on (1) HopGraph persistence and consolidation, (2) gray-tier recall uplift (+3%), (3) eBPF container runtime stage integration, (4) multi-source log correlation (CSV multi-analyzer / HopGraph session builder), and (5) identity/cloud resource coverage expansion and visualization polish.

Overall readiness for controlled pilot: HIGH. Readiness for broad GA: MEDIUM (persistence, gray-tier uplift, resource fairness, advanced correlation labeling still pending).

---

## 1. HopGraph: Current vs Roadmap

| Dimension | Current Implementation | Roadmap Target (Docs: PART2, BACKLOG, PR_HOPGRAPH) | Gap | Priority |
|-----------|------------------------|-----------------------------------------------------|------|----------|
| Persistence | In-memory with test drain/reset; snapshot JSON helper (partial) | SQLite or Redis persistent store; TTL & cleanup loop; export to Neo4j optional | Durable store & TTL pruning absent | High |
| API Facade | Direct GLOBAL_* graph access; mixed modules | Unified `api_hopgraph.py` facade normalizing identity/network/cloud access | Missing abstraction layer | Medium |
| Identity Graph | Users, sessions, privileges; lateral movement heuristics | Consolidated identity snapshot w/ atomic save/load; privilege escalation linkage scoring | Snapshot enriched & scoring weights incomplete | Medium |
| Network Graph | IP/domain edges; BGP prefix ingestion (basic) | Full BGP enrichment in pipeline + route risk factors (hijack/leak) | Partial (route factors not influencing scoring) | Medium |
| Cloud Graph | Basic resource & API call nodes (limited connectors) | AWS first-class ingestion, posture connectors, IAM policy risk, SBOM/CVE overlay | Connector breadth + posture scoring absent | High |
| eBPF Stage | Smoke harness test; analysis stage stub described; Falco integration not live | Falco webhook endpoint + Stage 22 runtime factor emission + correlation rules (escape + egress) | Endpoint + stage not yet implemented | High |
| Graph Aging | Manual / none; risk of memory growth | Periodic cleanup loop (SESSION_CLEAN_INTERVAL + prune heuristics) | No aging/prune logic | Medium |
| Visualization | Table-based explain view; D3 preview instructions (graph_explain.html upgrade pending) | Interactive D3 force-directed w/ tooltips, legends, risk edge coloring | Partially documented, not fully deployed | Medium |
| Explainable Factors | Factors surfaced; EWMA smoothing for some; KEV/CVSS mapping | Integrate ASN rarity tags, NXDOMAIN spike factor thresholds, KEV candidate tagging | Some tags missing (ASN rarity KEV:CANDIDATE, NXDOMAIN spike) | Low |
| Multi-Source Correlation | Single-source event correlation + CSV single upload | Multi-file session builder (csv_multi_analyzer.html) w/ EWMA overlap matrix & mapping editor | Multi-source analysis page not implemented | High |

### HopGraph Strengths
* Attack reconstruction: multi-domain (identity, process, network) path extraction with Top-K ranking.
* Deterministic test helpers (drain queue) enabling CI reliability.
* BGP prefix ingestion groundwork (nodes created, tests added).
* Explainability layered (MITRE mapping, factor weighting, DREAD scoring).

### Immediate Improvements (Next 2 Weeks)
1. Implement `src/core/graph/api_hopgraph.py` facade (central read/write, tenancy scoping).
2. Add lightweight persistence (SQLite file or Redis hashes) + periodic prune.
3. Flesh out eBPF ingestion endpoint (`ebpf_endpoints.py`) + Stage 22 analysis + container escape correlation rule.
4. Deploy D3 visualization (graph_explain.html update per PART3 spec) for live graph UI.
5. Integrate ASN rarity & NXDOMAIN spike factors into correlation and chain narrative.

---

## 2. CSV Analyzer: Single vs Multi-Upload Status

| Aspect | Current (csv_analyzer.html) | Target (csv_multi_analyzer.html roadmap) | Gap | Priority |
|--------|-----------------------------|------------------------------------------|------|----------|
| File Types | CSV/XLSX single upload (stream + enrich) | Multiple heterogeneous batches (CSV/JSON/etc.) | Multi-batch orchestration absent | High |
| Header Detection | Heuristics for IP/domain/hash/user columns | Auto-detect + interactive mapping editor | Mapping editor UI missing | High |
| HopGraph Link | Per-row enrichment → optional single-row reconstruction | Build session by merging artifact sets across batches | No session builder API | High |
| Overlap Metrics | Risk-based Top-K reconstructions | EWMA-smoothed overlap matrix between datasets | EWMA overlap generation absent | Medium |
| Factors Explanation | Row details with factors & MITRE | Multi-source factor rationale & conflict resolution | Cross-batch factor merging logic missing | Medium |
| Export | Incident creation + report export | Session summary with correlation_smoothed, mapping_stats, factors, verdict | Session summary endpoints absent | High |

### Required Additions
* New static page `csv_multi_analyzer.html` with: multi-drop zone, header map editor, overlap matrix panel, factors summary.
* Backend endpoints: `POST /api/v1/graph/session/build`, `GET /api/v1/graph/session/{id}` (payload & response per AGENTS.md spec).
* EWMA history maintenance & TTL pruning (`EWMA_HISTORY_PATH`, `EWMA_HISTORY_TTL_SECONDS`).

---

## 3. 13-Stage Pipeline → MITRE / Cyber Kill Chain Mapping & Future Extensions

| Pipeline Stage (Current) | Function | Kill Chain Phase | MITRE Tactics | Enhancement Opportunity |
|--------------------------|----------|------------------|---------------|------------------------|
| 1 Baseline | Known good/bad early exit | Recon (Pre-filter) | N/A / Pre | Add quick allowlist factor reasoning |
| 2 Regex | Pattern detection (injection, macro) | Initial Access / Execution | Initial Access, Execution | Expand technique tagging granularity |
| 3 Network | Beacon/scan/geo/ASN | C2 Setup / Recon | Command & Control, Discovery | Incorporate BGP hijack/leak enrichment |
| 4 Endpoint | Process lineage, LOLBins | Execution / Persistence | Execution, Persistence | Add eBPF syscall anomalies (container) |
| 5 Parent-Child | Suspicious spawn chains | Execution | Execution | Merge with Stage 4? unify factor naming |
| 6 Domain Novelty | New/rare domains | Recon / C2 | Recon, Command & Control | NXDOMAIN spike factor integration |
| 7 Egress | Port scatter, data egress | Exfiltration | Exfiltration | Data volume anomaly thresholds by asset criticality |
| 8 Beacon | Periodicity confirm | Command & Control | C2 | Container beacon differentiation |
| 9 SBOM | Vulnerabilities map | Weaponization / Exploit | Impact / Priv Esc / Defense Evasion | Add KEV urgency boost & exploit correlation |
| 10 Hunt Lanes | Advanced heuristics | Multiple | Multi-tactics | Add lateral-pivot chain scoring refinement |
| 11 Network-2 | Second pass enrichment | Lateral Movement | Lateral Movement | Insert BGP route risk & ASN rarity tags |
| 12 Correlation | Multi-signal fusion | All chain synthesis | Multi-tactic | Add kill-chain completeness score |
| 13 Advanced ML | Anomaly models & escalation | Variable | All applicable | Model confidence calibration via gray-tier labeling |
| 22 (Planned) eBPF | Container runtime analysis | Execution / Priv Esc / Defense Evasion | Execution, Priv Esc, Defense Evasion | Falco integration; syscalls baseline |

### Kill Chain Coverage Summary
* Phases strongly covered: Initial Access, Execution, Lateral Movement, Exfiltration.
* Moderate: Persistence, Privilege Escalation (factors exist but cloud/IAM dimension light).
* Weak / Planned: Defense Evasion (syscall/rootkit detection pending eBPF; cloud stealth), Command & Control variants (domain flux, TLS certificate anomalies), Impact (ransom encryption behaviors).

### Enhancements Mapping
* Add eBPF stage (container escape, privilege escalation factors) → strengthens Execution / Priv Esc / Defense Evasion.
* Cloud posture/IAM connectors → bolster Persistence & Priv Esc detection (misused roles, anomalous API patterns).
* BGP enrichment: route hijack/leak factors to reinforce Command & Control & Recon phases for network manipulations.
* Kill chain completeness scoring at correlation stage: embed percentage coverage & dwell time heuristics.

---

## 4. Gray-Tier Recall Improvement Plan (Current 87% → Target ≥90%)

### Current Metrics (Deep Dive Doc)
* Benign suppression: 98.5% (stable)
* High-tier recall: 96% (near target)
* Gray-tier recall: 87% (needs +3%)
* False positive rate: 12/1k (needs reduction to <10/1k)

### Root Causes of Gray-Tier Misses (Inferred)
1. Under-weighted correlation factors for medium-confidence multi-stage chains (lack of labeling feedback).
2. Sparse factor enrichment for cloud/IAM events (cloud dimension thin → fewer mid-weight hybrid factors).
3. Missing container runtime anomalies (eBPF stage not yet contributing medium-severity detections).
4. Lack of adaptive threshold calibration per tactic cluster (single global threshold may suppress borderline events).
5. Limited semantically similar factor boosting (embedding similarity exists but not fully applied to borderline events).

### Improvement Actions
| Action | Impact Mechanism | Effort | Risk |
|--------|------------------|--------|------|
| Enable labeling pipeline for medium-confidence events (analyst feedback auto-weight) | Raises borderline factor contribution | Low | Low |
| Add eBPF syscall anomaly factors (container_escape, priv_escalation) | New mid/high contributors for runtime threats | Medium | Low |
| Cloud IAM anomaly heuristics (rapid role assumption, unusual API fan-out) | Introduces fresh medium-weight identity/cloud factors | Medium | Medium |
| Correlation factor calibration (increase weight for multi-domain chains with diversity > N types) | Converts multi-artifact blends to higher confidence | Low | Low |
| Dynamic tactic-aware thresholding (Execution vs Exfil vs Priv Esc separate sigmoid calibration) | Reduces suppression of mid-confidence phases | Medium | Medium |
| Similarity boosting (embedding cluster proximity adds minor weight delta to borderline events) | Elevates near-miss events into recall | Medium | Low |
| False positive feedback loop focusing on subtractive corrections (prevent overshoot) | Protects precision while raising recall | Low | Low |

### Measurement Plan
1. Baseline dataset segmentation (high vs gray vs benign sets labeled) — produce confusion matrix per phase.
2. Incremental rollout: enable eBPF + labeling; measure delta after 1 week synthetic runs.
3. Track recall uplift vs FP drift; maintain guard rail: FP rate ≤ +1/1k during adjustments.
4. Introduce per-tactic threshold calibration only after stabilization of new factors (avoid compounding variability).

### Success Criteria
* Gray-tier recall ≥90% sustained over 3 consecutive evaluation batches.
* FP rate <10/1k with ≤+0.5/1k variance.
* Correlation lift ≥1.4x maintained (no regression).

---

## 5. Enhancement Backlog (Prioritized)

| Priority | Item | Description | Outcome |
|----------|------|-------------|---------|
| P0 | HopGraph persistence (SQLite/Redis) | Durable node/edge store + TTL prune; snapshot export/import | Demo & multi-process safety; memory control |
| P0 | eBPF ingestion & Stage 22 | Falco webhook endpoint, analysis stage, correlation rules (escape + egress) | Container runtime visibility & new factors |
| P0 | CSV Multi-Analyzer | Multi-batch upload, mapping editor, EWMA overlap matrix, session build endpoints | Multi-source correlation & HopGraph session narratives |
| P1 | Identity Graph API Facade | Consolidate accessors, unify node creation, enforce tenancy scoping | Cleaner API & easier persistence transition |
| P1 | Gray-tier recall uplift tasks | Implement improvement actions list | Achieve ≥90% recall |
| P1 | D3 HopGraph Visualization deployment | Implement Part3 force-directed graph page | Better analyst comprehension & demo impact |
| P2 | Cloud posture connectors (AWS first) | Inventory + IAM policy ingestion to Cloud Graph | Expand Priv Esc & Persistence detection coverage |
| P2 | ASN rarity & NXDOMAIN spike factors | Enrich network events & correlation narrative | Higher fidelity network anomaly scoring |
| P2 | Kill chain completeness scoring | Quantify coverage & dwell time in decisions | Executive reporting & correlation ranking refinement |
| P3 | Advanced persistence (Neo4j export) | Optional graph DB export for deep queries | Advanced analytics & sales differentiator |
| P3 | Performance aging & prune heuristics | Edge/node decay & compaction worker | Memory stability & stale artifact reduction |

---

## 6. Risks & Mitigations (Focused Subset)

| Risk | Description | Mitigation | Status |
|------|-------------|------------|--------|
| Memory Growth | HopGraph accumulates unbounded edges | Implement TTL prune + snapshot rotation | Pending |
| Gray Recall Stagnation | Failure to reach 90% recall target | Structured uplift plan & weekly evaluation | In progress |
| Container Visibility Gap | Runtime threats missed pre eBPF integration | Fast-path Falco webhook & Stage 22 | Planned |
| Multi-Source Correlation Delay | Missing csv_multi_analyzer reduces demo impact | Parallel development with persistence | Planned |
| Correlation FP Drift | Weight tuning increases FPs | Guard rails & incremental calibration | Pending instrumentation |

---

## 7. Implementation Sequencing Recommendation

Week 1:
* HopGraph SQLite persistence MVP (node, edge tables + simple load/save; TTL prune job).
* Falco webhook endpoint + Stage 22 minimal factors (container_escape, priv_escalation, syscall_anomaly).
* Begin gray-tier labeling harness (store borderline event snapshots).

Week 2:
* CSV multi-analyzer backend endpoints + EWMA overlap logic.
* D3 visualization upgrade deployment & basic Playwright UI test.
* Identity API facade introduction.

Week 3:
* Cloud AWS connector (resource + IAM events) feeding Cloud Graph.
* ASN rarity + NXDOMAIN spike factor integration.
* Dynamic tactic-aware threshold calibration with evaluation harness.

Week 4:
* Kill chain completeness scoring in correlation stage.
* Performance aging & prune heuristics refinement.
* Optional Redis migration or Neo4j export prototype.

---

## 8. Dedup Unification Plan (Adjacent Improvement)

Current dedup uses layered global caches + ring gating; unify into a single service:
* Create `src/core/dedup/dedup_service.py` with:
  - `reserve(key, ttl_seconds)` → returns first-seen boolean.
  - `seen(key)` → boolean check.
  - In-memory dictionary mapping key → expiry timestamp; periodic cleanup.
  - Optional Redis backend (when configured) for multi-process consistency.
* Replace scattered dedup logic with service calls; integrate metrics: `dedup_reservations_total`, `dedup_suppressed_total`.
* Regression tests: TTL suppression, concurrency race, multi-process simulation (Redis variant).

Outcome: Reduced complexity, improved clarity for future maintenance & performance tuning.

---

## 9. KPIs to Track Post-Enhancements

| KPI | Definition | Target | Measurement Frequency |
|-----|------------|--------|-----------------------|
| Gray-tier Recall | Medium threat detection rate | ≥90% | Weekly synthetic batch |
| HopGraph Persistence Latency | Snapshot save/load time | <2s save / <3s load | Per snapshot |
| Container Runtime Coverage | % Falco events yielding factors | ≥70% | Daily ingestion stats |
| Multi-Source Session Build Success | % builds producing correlation_smoothed | ≥95% | Per build job |
| Visualization Load Time | D3 graph render (<50 nodes) | <2s | Per UI test |
| Dedup Efficiency | Suppressed duplicates / total duplicates | ≥95% | Daily metrics aggregation |

---

## 10. Summary

The platform’s foundational capabilities (pipeline speed, suppression, high-tier recall, explainability) are strong and aligned with roadmap direction. Strategic focus now shifts to breadth (cloud + container + multi-source correlation) and resilience (persistent HopGraph + aging) while refining mid-confidence detection accuracy (gray-tier uplift). Executing the prioritized backlog over the next 4 weeks positions JanuSec for a high-quality pilot and accelerates path to GA.

---

## Appendix A: Artifact Path References
* HopGraph identity snapshot & persistence (planned): `src/core/graph/identity_hopgraph.py`, future `api_hopgraph.py`.
* Network graph BGP wiring: `src/integrations/bgp_client.py`, `src/core/graph/network_hopgraph.py`.
* eBPF stage planned: `src/core/event_pipeline/stages/ebpf_analysis.py` (spec in PART2 doc).
* CSV analyzer (current): `frontend/static/csv_analyzer.html`; multi-source (planned): `frontend/static/csv_multi_analyzer.html`.
* Visualization upgrade: `frontend/static/graph_explain.html` (D3 integration spec in PART3 doc).
* Risk scoring: `core/risk_score` (DREAD scoring logic).

---

## Appendix B: Proposed Table Schemas (SQLite Persistence MVP)

```sql
CREATE TABLE hopgraph_nodes (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  first_seen TIMESTAMP,
  last_seen TIMESTAMP,
  metadata JSON
);

CREATE TABLE hopgraph_edges (
  edge_id INTEGER PRIMARY KEY AUTOINCREMENT,
  src TEXT NOT NULL,
  dst TEXT NOT NULL,
  etype TEXT NOT NULL,
  ts TIMESTAMP,
  weight REAL,
  metadata JSON,
  FOREIGN KEY (src) REFERENCES hopgraph_nodes(id),
  FOREIGN KEY (dst) REFERENCES hopgraph_nodes(id)
);

CREATE INDEX idx_edges_src_dst ON hopgraph_edges(src, dst);
CREATE INDEX idx_edges_ts ON hopgraph_edges(ts);
```

---

## Appendix C: eBPF Factor Mapping (Initial)

| Falco Rule | Factor | Weight | MITRE | Rationale |
|------------|--------|--------|-------|-----------|
| Terminal shell in container | ebpf:container_escape | 0.95 | T1610 | Indicates potential escape attempt |
| Privileged container operation | ebpf:priv_escalation | 0.85 | T1548 | Suggests privilege gain inside container |
| Unusual syscall pattern | ebpf:syscall_anomaly | 0.70 | Multiple (Defense Evasion) | Deviation from baseline syscall set |

---

## Appendix D: Gray-Tier Labeling Data Points (Sample Features)

| Feature | Description | Use in Calibration |
|---------|-------------|--------------------|
| factor_diversity | Unique factor types (network/endpoint/cloud) | Boost multi-domain chains |
| temporal_density | Events per time window normalized | Detect rapid stage chaining |
| privilege_change_delta | Difference in user privilege level | Escalation heuristic |
| anomaly_score_local | Isolation Forest score (Stage 13) | Weighted in mid-band fusion |
| artifact_reuse_count | Repeated artifact across hosts | Lateral movement signal |

---

End of Report
