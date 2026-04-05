# Architecture Evolution & Maturity Layers

Version Context: v0.9.0-pre (Pre-Production Validation)  
Legacy Snapshot: See `./archive/architecture_legacy_2025-09-22.md`

## Evolution Overview
The platform evolved from a linear progressive analysis pipeline into a *governed decision fabric* emphasizing: 
- Measurement-first design (correlation lift, suppression precision, replay determinism)
- Cost & efficiency accounting (inference ledger across tiers)
- Governance & reproducibility (rubric scoring, factor naming policy, manifest intent)
- Multi-tenant isolation readiness (stress harness + contamination heuristics)
- Structured false positive attribution (taxonomy + classification stub)

## Current High-Level Architecture (Annotated)
```
                              ┌──────────────────────────────────────────┐
                              │              Ingestion Layer             │
                              │  (API, Eclipse XDR, Normalization)       │
                              └───────────────┬──────────────────────────┘
                                              │ events
                                              ▼
                ┌────────────────────────────────────────────────────────┐
                │                 Orchestrator / Router                  │
                │  (Module registry, lifecycle, circuit breakers)        │
                └───────────┬──────────────────────────┬─────────────────┘
                            │                          │
                            │                          │ async fan-out / gating
                            │                          ▼
                            │           ┌────────────────────────────────┐
                            │           │ Progressive Analysis Pipeline  │
                            │           │ 1. Baseline (deterministic)    │
                            │           │ 2. Regex Patterns              │
                            │           │ 3. Adaptive Blend (ML + weights)│
                            │           │ 4. Optional Deep / External AI │
                            │           └───────────────┬────────────────┘
                            │                           │ enriched factors
                            │                           ▼
                            │                ┌───────────────────────────┐
                            │                │ Correlation Engine         │
                            │                │ (Rules + TP/FP counters)   │
                            │                └───────┬───────────────────┘
                            │                        │ correlation factors
                            │                        ▼
          ┌─────────────────┴────────────────┐   ┌────────────────────────────┐
          │  Decision Assembly & Custody     │   │  Cost Ledger (Inference)    │
          │  (Confidence calc, chain hashing)│   │  tier usage + Prom counters │
          └───────────┬──────────────────────┘   └──────────────────┬─────────┘
                      │ decisions                                 usage metrics
                      ▼
        ┌────────────────────────────┐          ┌─────────────────────────────┐
        │  Decision Store / Index    │<---------│  Feedback & Factor Weights   │
        └─────────────┬──────────────┘    votes │  (bounded ± influence)       │
                      │                           └─────────────────────────────┘
                      │ query
                      ▼
         ┌─────────────────────────────┐
         │ API / Analyst Interfaces    │  (SSE streams, NLP Query, Similarity)
         └─────────┬───────────────────┘
                   │ telemetry
                   │                                 Governance & Quality Sidecars
                   │                                 -----------------------------
                   │    ┌─────────────────────────┐   ┌─────────────────────────┐
                   │    │ Observability (Prom,    │   │ Audit Runner (coverage, │
                   │    │ latency, lift, ledger)  │   │ dep diff, rubric scoring│
                   │    └───────────┬─────────────┘   └───────────┬─────────────┘
                   │                │ metrics                     │ artifacts
                   │                ▼                            │
                   │    ┌─────────────────────────┐               │
                   │    │ Replay Determinism Test │               │
                   │    └─────────────────────────┘               │
                   │                │ guards                      │
                   │                ▼                            │
                   │    ┌─────────────────────────┐               │
                   │    │ FP Taxonomy Classifier  │<──────────────┘
                   │    └─────────────────────────┘
                   │                │ categories
                   │                ▼
                   │    ┌─────────────────────────┐
                   │    │ Tenant Isolation Harness│
                   │    └─────────────────────────┘
                   │                │ leak signals
                   ▼                ▼
        ┌─────────────────────────────┐
        │ Risk Register & Reporting   │ (readiness score, deltas)
        └─────────────────────────────┘
```

Legend:
- Sidecar components (right) enforce *governance, measurement, and safety* loops without blocking core decision latency.
- Cost Ledger attaches to inference tier boundaries collecting usage events.
- Correlation engine now publishes pre/post counters enabling net-signal monitoring.

## Key Maturity Additions vs Legacy
1. Correlation Lift Accounting – before/after TP/FP counters to avoid blind amplification.
2. Cost Awareness – first-class inference ledger (future cost-per-signal KPI).
3. Reproducibility – replay determinism guard (diff == 0 invariant) + planned run manifest.
4. Governance – factor naming prefix test + rubric-scored readiness gating.
5. FP Strategy – taxonomy-enabled root cause classification feeding suppression backlog.
6. Tenant Safety – synthetic isolation stress harness catching cross-tenant contamination.

## Pending Architectural Enhancements
- Enrichment completeness gate (pre-correlation false context guard)
- External AI budget policy (tokens/hour per tenant) integrated with ledger alerts
- Automated manifest hashing + integrity digest for decision reproducibility attestation
- Coverage matrix generation for ATT&CK technique mapping

## User Flows
### 1. Benign Fast-Path (High Suppression Precision Goal)
```
 Event → Ingestion → Orchestrator → Baseline → Regex → (confidence < malicious & < gray escalation gate?)
                │          │             │          │         │
                │          │             │          │         └─+--[Low-risk patterns matched ⇒ suppression candidates]
                │          │             │          └────────────+--[Deterministic signals hashed into custody chain]
                │          │             └────────────────────────+--[Lane timing recorded]
                │          └──────────────────────────────────────+--[Queue depth metric]
                └─────────────────────────────────────────────────+--[Ingress counter]

        → Confidence Aggregator → (Below benign threshold?) → SUPPRESSED DECISION
                                        │                               │
                                        │                               └─> FP Taxonomy (optional sampling) for future tuning
                                        └─> Cost Ledger: tiers_used = {baseline, regex}; no deep / external cost

        Sidecar Observability: lane_latency_ms, batch_latency_ms updated.
```

Key Points:
- Minimal modules touched; avoids correlation & adaptive ML where possible.
- Ensures low cost footprint (ledger confirms absence of expensive tiers).
- Replay determinism ensures same suppression verdict on repeat.

### 2. Gray Adaptive Path (Uncertain / Needs ML + Weights)
```
 Event → Ingestion → Orchestrator
         → Baseline + Regex (signals inconclusive) → Adaptive Blend (ML scoring + factor weights)
                                │                    │                       │
                                │                    │                       └─> Weight adjustments bounded (±0.25)
                                │                    └─> Deterministic features hashed
                                └─> Initial factors

         → Confidence Aggregator (result within GRAY band) → Correlation (selected low-risk rules)
                                                │                                                │
                                                │                                                └─> Pre/Post TP/FP counters increment
                                                └─> Cost Ledger tiers_used = {baseline, regex, ml_local}

         → Decision (Gray) stored → Analyst/NLP query ⇒ feedback votes
                                                                                                                                                                 │
                                                                                                                                                                 └─> Feedback weights table → influences future adaptive blend

        Sidecar Hooks: replay test (periodic), rubric scoring (audit run), FP taxonomy (sampled disagreements).
```

Key Points:
- Introduces local ML cost but avoids external AI unless necessary.
- Correlation applied selectively; monitoring ensures net benefit.
- Feedback loop drives gradual precision improvements without nondeterminism.

### 3. High Severity & Correlation Expansion → SOAR Advisory
```
 Event (high-risk indicators present) → Ingestion → Orchestrator
         → Baseline / Regex (strong hits) + Adaptive Blend (reinforced) → External / Deep Tier (if local insufficient & budget OK)
                                 │                 │                   │                          │
                                 │                 │                   │                          └─> Cost Ledger record external_inference
                                 │                 │                   └─> Confidence escalated above malicious threshold?
                                 │                 └─> High-signal factors (e.g., suspicious_lateral_pivot)
                                 └─> Deterministic chain anchor

         → Correlation Engine (multi-factor synthesis) → Adds chain factors (e.g., corr_lateral_pivot_possible)
                                                 │                                              │
                                                 │                                              └─> Pre/Post counters (tp_before, tp_after, fp_before tentative)
                                                 └─> FP Amplification Guard (planned: track delta) 

         → Decision (Malicious) persisted + Custody hash chain updated
                                                 │
                                                 ├─> SOAR Advisory Mapper (playbook hints)
                                                 │       └─> (Future) DSL compiled playbook graph
                                                 │
                                                 ├─> Risk Register update candidate (if new pattern)
                                                 └─> Analyst Notification (Slack / console)

        Sidecars: rubric weighting (detection strength), ledger external usage exposure, isolation harness (if multi-tenant patterns observed), taxonomy classification (if downgraded later).
```

Key Points:
- May invoke costlier tiers; ledger enables per-tenant budgeting.
- Correlation expansion accompanied by lift measurement to justify complexity.
- SOAR advisory currently non-destructive (human-in-the-loop) reducing automation risk.

## Prototype vs Current Comparison
| Dimension | Prototype (Early) | Current v0.9.0-pre | Benefit / Rationale |
|-----------|-------------------|--------------------|---------------------|
| Modularity | Linear progressive chain | Orchestrated lanes + sidecar governance | Easier incremental hardening |
| Observability | Basic latency + counts | Latency, lane parallel metrics, correlation lift, inference ledger | Data-backed tuning & ROI tracking |
| Governance | Ad hoc manual review | Rubric scoring, factor naming test, suppression regression guard | Objective readiness gating |
| FP Strategy | Unstructured backlog | FP taxonomy + classifier stub + precision threshold guard | Targeted engineering focus |
| Correlation Measurement | Rule hits only | Pre/Post TP/FP counters (lift accounting) | Prevents silent noise inflation |
| Cost Awareness | None | Inference tier usage ledger (Prom counters) | Budget & efficiency management |
| Multi-Tenant Safeguards | Concept only | Isolation stress harness & contamination heuristics | Early detection of leakage risks |
| Reproducibility | Best-effort | Replay determinism test (diff=0 invariant) | Trust & audit defensibility |
| Executive Readiness | Narrative slides | README CEO brief + gating table | Aligned decision framing |
| Risk Register Integration | Manual notes | Structured risk register endpoint | Continuous risk visibility |
| Feedback Adaptation | Basic factor votes | Bounded weight influence (±0.25) + periodic aggregation | Controlled adaptivity without drift |
| Custody & Integrity | Hash chain partial | Chain-of-custody hashing + planned manifest | Forensic trace continuity |

## Synthetic Validation Metric Deltas
<!--AUTO-DELTA:START-->
Baseline values represent the earliest reproducible synthetic harness run before governance instrumentation (ref: archived snapshot). Replace placeholder baseline cells once historical metrics are backfilled.

| Metric | Baseline (Placeholder) | Current | Delta | Notes / Driver |
|--------|------------------------|---------|-------|----------------|
| Benign Suppression Precision | 0.972 (?) | 0.985 | +0.013 | FP taxonomy prep + regex tuning |
| Gray Tier Recall | 0.79 (?) | 0.87 | +0.08 | Scenario expansion (partial) |
| High Tier Recall | 0.92 (?) | 0.96 | +0.04 | Added lateral pivot + JA3 correlation |
| Correlation Lift (TP) | 1.0 (none) | 1.4 | +0.4 | Introduced synthesis rules + factoring |
| Parallel Lane Speedup | 1.0 | 1.6x | +0.6x | Parallel execution flag + batch metrics |
| Batch Latency p95 (ms) | 480 | 420 | -60 | Early pruning + parallel lanes |
| FP Rate (/1k benign) | 24 | 12 | -12 | Suppression heuristics + precision tuning |
| Replay Determinism Drift | n/a | 0 | - | Guard added (stabilized) |
| Rubric Score | n/a | 0.78–0.81 | - | New readiness metric |

Automation Plan:
1. Extend `audit_runner.py` to accept `--previous-metrics metrics_prev.json` & compute delta JSON.
2. Emit `synthetic_delta.json` with keyed diff + pass/fail thresholds (e.g., precision must not drop by >0.01 absolute).
3. Integrate generation into CI pipeline nightly harness workflow.
4. Append machine-generated block to this section (bounded markers `<!--AUTO-DELTA:START-->` / `<!--AUTO-DELTA:END-->`).

Risk Note: Until real traffic calibration, deltas are *internal quality trajectory indicators* not production performance guarantees.
<!--AUTO-DELTA:END-->

## Change Rationale Summary
| Driver | Problem (Legacy) | Change | Benefit |
|--------|------------------|--------|---------|
| Signal Confidence | Correlation impact opaque | Pre/Post TP/FP counters | Prevents silent FP inflation |
| Cost Control | No cost attribution | Inference ledger | Early cost-per-signal governance |
| Reproducibility | Potential nondeterminism | Replay test & manifest plan | Trust & auditability |
| FP Reduction | Unstructured FP backlog | Taxonomy & classifier stub | Targeted suppression engineering |
| Executive Readiness | Narrative subjective | Rubric scoring | Objective gating for pilot |
| Tenant Safety | Unmeasured leak risk | Isolation stress harness | Early detection of cross-tenant bleed |

## Measurement Surfaces
| Domain | Metric / Artifact | Purpose | Frequency |
|--------|-------------------|---------|-----------|
| Correlation | lift (tp_before/after, fp_before/after) | Validate net benefit | Per run / continuous |
| Suppression | precision, FP taxonomy distribution | Analyst workload | Per validation batch |
| Performance | lane latency p95, batch p95 | SLO tracking | Continuous |
| Cost | inference_tier_usage_total | Efficiency & budgeting | Continuous |
| Governance | rubric score, naming test pass/fail | Release gating | Per audit run |
| Reproducibility | replay diff invariant | Regression detection | Per CI run |
| Isolation | cross_tenant_leaks count | Multi-tenant safety | Scheduled synthetic |

## Architecture Integrity Principles
- Additive Observability: New metrics never require refactoring hot path logic.
- Graceful Degradation: Every external or deep tier has a bounded fallback.
- Deterministic Core: Adaptive weights bounded; replay must reproduce factor set & verdict.
- Separation of Concerns: Governance sidecars observe & gate, never block base processing latency path.
- Progressive Generalization: Start with rule + heuristic clarity, layer ML only where measurable net lift.

---
Further details will be appended as remaining TODO sections are completed.

## External AI Budget Policy (Design)
Goal: Prevent unbounded external inference spend while preserving high-signal coverage.

Policy Dimensions:
- Per-tenant token/hour soft quota (e.g., 50K) with hard cap (e.g., 75K) -> after soft quota crossed require correlation justification.
- Global circuit breaker triggers if rolling 15m external failure rate > X% or median latency > threshold.
- Cost Ledger Augmentation: record entries `{tenant, tier: external_ai, tokens_used, model_id, latency_ms}`.

Enforcement Flow:
1. Before external tier invocation, consult `ExternalBudgetManager` with `(tenant, projected_tokens)`.
2. Manager maintains sliding window token usage per tenant + global aggregates.
3. If soft quota exceeded: attach factor `external_budget_soft_exceeded` and require either (a) high severity precursor factors or (b) correlation lift prediction (future) to proceed.
4. If hard quota exceeded or circuit breaker open: skip external call, fallback to local ML; increment `external_budget_denial_total` metric.
5. Periodic (5m) reconciliation task flushes ledger deltas and recomputes adaptive quotas if unused capacity abundant (fair-share redistribution planned).

Metrics:
- `external_ai_tokens_used_total{tenant}`
- `external_ai_invocations_total{tenant}`
- `external_budget_denial_total{reason}` (reason ∈ {soft, hard, breaker})
- `external_ai_latency_ms` (histogram)

Readiness Gates:
- Pilot start requires denial rate <5% (soft) and zero hard denials for high severity events.
- Alert if projected monthly tokens > budget envelope (budget JSON spec upcoming).

Future Enhancements:
- Dynamic token allocation weighting by historical true positive yield per tenant.
- Optional downgrade instead of deny: shorter context windows or summarization pre-pass to compress tokens.
