# Business Justification: Embedding Provider + HopGraph-lite + MITRE/STRIDE

## Executive Summary
The enhancement stack (graph context + layered security embeddings + tactic mapping) delivers higher precision, faster triage, and defensible explainability with *bounded incremental cost*. It directly accelerates KPI attainment (precision ≥75%, coverage ≥80%, time-to-first-verdict -40%). Graceful degradation assures reliability (≥99%) under resource constraints.

## Why Upgrade vs Status Quo
| Dimension | Status Quo Risk | Enhancement Benefit |
|----------|-----------------|---------------------|
| Precision | Regex & single semantic layer cause over-triggering | Multi-signal (graph + temporal + semantic) reduces false positives |
| Explainability | Raw factor list only | Enriched with MITRE/STRIDE tactics; executive narrative ready |
| Scalability | Uniform model cost per event | Complexity-driven model selection lowers average cost |
| Latency SLO | Spikes if heavier model always used | Escalation only on complex cases; majority remain fast path |
| Analyst Load | Many medium-confidence noise items | Context factors allow auto-lowering or suppression of isolated signals |
| Reliability | Model outage = quality drop | Graceful fallback path preserves core function |

## Graceful Degradation Rationale (Implement Now)
Implementing the SecBERT → TinyBERT → MiniLM → Hash ladder **now** avoids a later refactor and provides safety if GPU/large model pulls fail. Deferring would:
- Force retrofitting provider abstraction under production load
- Increase rollback risk when introducing larger models later
- Delay observability of provider selection metrics critical for capacity planning

Early instrumentation of provider selection also feeds financial forecasting (cost/event projection).

## Cost Control Strategy
| Lever | Mechanism |
|-------|-----------|
| Model Escalation | Activate SecBERT only when complexity score ≥ threshold |
| HopGraph Window | Limit to 10–15 min and max events per tenant |
| Embedding Truncation | Use last N (50) factors for embedding context snapshot |
| Mapping Cache | Pre-resolve MITRE/STRIDE base tokens in-memory |
| Optional Modules | Packet summarizer & RAG deferred until ROI validated |

## KPI Alignment
| KPI | Supporting Mechanism |
|-----|----------------------|
| ≥75% Precision | Composite context lowers false positives by requiring multi-axis corroboration |
| ≥80% Coverage | Tactic mapping broadens classification across ATT&CK lattice |
| -40% Time-to-First Verdict | Skips heavy embedding path for low-complexity events; graph pre-factors accelerate confidence buildup |
| 99% Reliability | Fallback provider path + no hard dependency on SecBERT availability |
| Full Audit | Provider selection + factor mapping + custody chain captured in explanation endpoint |

## Risk Mitigation
| Risk | Control |
|------|---------|
| Model drift causing regression | Replay harness diff + drift divergence comparison |
| Graph factor explosion | Cap factor additions per stage; taxonomy normalization |
| Latency exceedance | Complexity threshold tuning + metrics alert on p95 increase |
| Overfitting to rare sequences | Decay & weight cap + sentinel event evaluation |

## Implementation Phasing
1. Abstraction & selection (delivered)  
2. Graph + mapping integration (delivered)  
3. Provider performance tuning & threshold calibration  
4. Add advanced temporal (sequence n-grams) if needed  

## ROI Snapshot
Assuming baseline FP rate 30% of reviewed items, and 50% of those demoted by context gating: net FP load reduction ≈15 percentage points → direct analyst time savings. If an analyst hour ≈ $120 loaded cost, and pipeline processes 5k events/day with 2% requiring manual review, a 15 pp reduction yields ~15 fewer reviews/day → ~$1.8k/month saved (pilot scale). Scales with volume.

## Decision
Proceed with current incremental deployment; monitor provider selection distribution and adjust complexity threshold to maintain latency SLO while increasing precision.
