# Architecture Diagram & Strategic Positioning

## High-Level ASCII Architecture
```
                               ┌──────────────────────────────────────────┐
                               │                 Frontend                 │
                               │  Analyst UI (HTML/JS)                    │
                               │  - Artifact Table (live)                 │
        Live Updates (SSE) ───▶│  - Escalation Trace Panel                │
                               │  - NLP Query / History                   │
                               │  - Capability & Health Badges            │
                               └──────────────────────────────────────────┘
                                                ▲
                                                │ REST / SSE
                                                │
┌────────────────────────────────────────────────┴──────────────────────────────────────────────────┐
│                                            FastAPI API Layer                                      │
│  Ingest Endpoints  Config / Digests  Weight Harness  SBOM Upload  Playback / Calibration  Health  │
└───────────┬───────────────────────┬───────────────────┬──────────────────┬────────────────────────┘
            │                       │                   │                  │
            │                       │                   │                  │
            ▼                       ▼                   ▼                  ▼
   ┌────────────────┐      ┌────────────────┐   ┌────────────────┐  ┌────────────────┐
   │ Ingestion &    │      │ Config Digest  │   │ Weight Set Repo│  │ SBOM Component │
   │ Normalization  │      │ Registry       │   │ (JSON store)   │  │ & Vuln Repo    │
   └───────┬────────┘      └──────┬─────────┘   └────────┬───────┘  └──────┬─────────┘
           │                       │                       │                 │
           ▼                       │                       │                 │
   ┌────────────────┐              │                       │                 │
   │ Baseline       │  (digests in decisions)             │                 │
   │ Deterministic  │──────────────┐                       │                 │
   │ Filters (<1ms) │              │                       │                 │
   └──────┬─────────┘              │                       │                 │
          │  seed confidence       │                       │                 │
          ▼                        │                       │                 │
   ┌────────────────┐              │                       │                 │
   │ Confidence /   │──────────────┘                       │                 │
   │ Routing Engine │  thresholds from active weights      │                 │
   └──────┬─────────┘                                      │                 │
   Fast   │            Deep Path                           │                 │
  Paths   ▼                                                │                 │
        (Benign / Malicious)                               │                 │
                 ╲                                         │                 │
                  ╲                                        │                 │
                   ▼                                       ▼                 ▼
            ┌────────────────┐  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐
            │ Network Hunter │  │ Endpoint Hunter│  │ Clustering /   │  │ SBOM Vuln Map  │
            │ (geo/asn/etc)  │  │ (proc lineage) │  │ Novelty / Graph│  │ (severity →    │
            └──────┬─────────┘  └──────┬─────────┘  └──────┬─────────┘  │  factors)      │
                   │                   │                   │            └──────┬─────────┘
                   └───────────────┬───┴──────┬────────────┴──────────────────┘
                                   ▼          ▼
                           ┌────────────────────────┐
                           │ Compliance / Mapping   │ (MITRE / STRIDE / Controls)
                           └──────────┬────────────┘
                                      ▼ Enrichments (factors + deltas)
                           ┌────────────────────────┐
                           │ Factor Aggregation &   │  (Active Weight Set applied)
                           │ Scoring (A/B Harness)  │
                           └──────────┬────────────┘
                                      ▼
                           ┌────────────────────────┐
                           │ Decision Finalization  │  custody hash + config meta
                           └──────────┬────────────┘
                                      │
             ┌────────────────────────┼──────────────────────────────┐
             ▼                        ▼                              ▼
   ┌────────────────┐        ┌────────────────┐            ┌────────────────┐
   │ SSE Event Bus  │        │ Notifications  │            │ Storage /      │
   │ (diff stream)  │◀──────▶│ Dispatcher     │            │ Custody Chain  │
   └────────────────┘   ack  │  (Slack/Teams/ │            └────────────────┘
                            │   Webhook/WA)  │ metrics
                            │ RateLimit+CB   │ dead-letter
                            └──────┬─────────┘
                                   │ metrics / audit
                                   ▼
                           ┌────────────────────────┐
                           │ Metrics & Observability│ (Prometheus)
                           └────────────────────────┘

         ┌──────────────────────┐                 ┌─────────────────────────┐
         │ Calibration & Replay │← historical ----│ Analyst Feedback Labels │
         └──────────────────────┘                 └─────────────────────────┘
```

## Data / Control Plane Key
- Solid downward arrows: synchronous data flow.
- Fan-in lines: aggregation of enrichment signals.
- Double arrow (`◀──────▶`): bidirectional acknowledgment / status feedback.
- Side repositories (weight sets, SBOM, config digests) inject metadata but are not on critical latency path.

## Positioning Summary
The platform is an Explainable Threat Sifting & Supply Chain Risk Fusion layer that aggressively removes benign noise early while preserving forensic integrity, experimentation agility (A/B factor weights), and supply chain (SBOM + vulnerability) context inside the *same* scoring envelope.

## Naming Candidates (With Rationale)
| Candidate | Rationale | Notes |
|-----------|-----------|-------|
| LucidSift | Clarity (lucid) + selective reduction (sift). Emphasizes explainability. | Recommend #1 (memorable, pronounceable). |
| Pragmatic Sentinel | Practical, defender posture. | Slightly longer; ties to existing doc naming. |
| Factorium | Focus on factor transparency & provenance. | Niche / industrial tone. |
| SiftForge | Iterative improvement (forge) + sifting. | Slightly harsher phonetics. |
| Custos | Latin for guardian; evokes custody hashing. | Potential pronunciation confusion. |
| Threat Loom | Weaves multi-source signals. | More poetic; could dilute precision tone. |
| ExplainIQ | Directly calls out explainable intelligence. | Risk of sounding generic SaaS. |

Recommended Brand: **LucidSift** – Aligns with differentiation: lucid (clear) scoring rationale + sifting pipeline removing noise.

Tagline Options:
1. "LucidSift – Cut the noise. Trust every escalation."
2. "LucidSift – Explainable threat scoring fused with SBOM intelligence."
3. "LucidSift – Faster decisions, defensible outcomes."

Elevator Pitch:
"LucidSift is an explainable threat sifting platform that fuses real‑time telemetry, factor‑level scoring, and live SBOM vulnerability context to eliminate benign noise early while preserving forensic integrity and analyst trust. With built‑in A/B weight experimentation, custody hashing, and resilience controls, teams iterate detection logic safely and quantify impact before risking precision."

## Differentiators
1. Progressive Enhancement Pipeline: Deterministic early rejection keeps compute/unit cost low.
2. Factor-Level Explainability: Every confidence change is attributable and streamed live.
3. Dynamic Weight Harness (A/B): Rapid iteration on detection weights without redeploying code.
4. Integrated SBOM Vulnerability Factors: Supply chain exposure influences incident scoring in real time (not an afterthought report).
5. Custody & Config Provenance: Cryptographic digests and chain-of-custody at each decision lifecycle stage.
6. Resilient Notification Plane: Rate limiting + per-subscription circuit breakers + delivery metrics & dead-letter queue.
7. Calibration Discipline: Replay & distribution drift guardrails gating threshold changes.
8. Minimal Vendor Lock Core: Primarily FastAPI + Prometheus; pluggable enrichment modules.

## Competitive Landscape (High-Level)
| Segment | Typical Gaps | LucidSift Advantage |
|---------|--------------|---------------------|
| Traditional SIEM (Splunk/Elastic) | Expensive ingestion, coarse correlation, opaque scoring | Lightweight factor scoring + early benign shedding reduces ingest volume |
| XDR Suites (CrowdStrike/M365) | Vendor data lock, limited custom weighting transparency | Open factor taxonomy + weight experimentation |
| SOAR (XSOAR, Tines) | Workflow focus; limited scoring context | Native scoring + custody + playbook triggers with provenance |
| SBOM / SCA (Snyk, Anchore) | Point-in-time posture, disconnected from live events | Inline SBOM severity factors drive live risk adjustments |
| Detection Engineering Platforms (Panther) | Strong structured ingestion, less A/B risk weight tooling | Built-in weight set harness & calibration guardrails |

## Value Metrics to Track / Expose
- Benign Fast-Path Rate (noise reduction %) – ROI narrative.
- Analyst Hours Saved (estimated from escalations avoided * avg triage time).
- Mean Explainability Score (presence of top-N factor deltas in decisions).
- SBOM Influence Rate (% of malicious decisions where SBOM factors contributed ≥ X confidence).
- Time-to-Weight-Change (proposal → activation).

## Pricing Levers (Future)
- Base: Events processed (with benign fast-path discount multiplier to encourage optimization).
- Add-on: Advanced SBOM correlation pack (CWE/MITRE projection), compliance mapping module, replay report exports.
- Tiered Notification SLA or retained delivery history depth.

## GTM & Adoption Narrative
1. Start as an adjunct scoring/filter layer reducing ingest cost into existing SIEM.
2. Demonstrate precision stability via calibration reports + factor transparency.
3. Expand into response automation (playbook DSL) once trust established.
4. Layer in SBOM live influence to bridge SecOps + AppSec narratives.

## Short FAQ Snippets
Q: "How is this different from just tuning SIEM rules?"  
A: Weight harness + factor deltas quantify marginal impact rapidly without rebuilding detection content; SBOM context is native to scoring.

Q: "Will SBOM ingestion slow detection?"  
A: SBOM severity aggregation occurs off the latency-critical path; only summarized factors enter scoring.

Q: "Does explainability add storage overhead?"  
A: Factor deltas are compressed into bounded arrays; custody hashing ensures integrity without duplicating raw content.

## Next Strategic Enhancements
- Two-dimensional scoring (maliciousness vs uncertainty).
- MITRE cluster progression modeling (attack stage state machine weight scaling).
- Model-assisted drift detection (light histogram embedding).

---
Document version: 0.1 (initial draft)  
Pending Review: Naming final selection, pricing model quantification, SBOM factor weight calibration numbers.
