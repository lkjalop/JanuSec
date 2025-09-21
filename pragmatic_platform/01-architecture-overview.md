# Architecture Overview

## Goal
Deliver a progressive enhancement threat sifting platform that discards or auto-dispositions the majority of benign events cheaply while preserving high-fidelity escalation quality and full forensic/audit traceability.

## Layered Flow
1. Ingestion & Normalization
2. Baseline Pattern Filter (deterministic, constant time)
3. Confidence Router (decides: benign fast‑path, malicious fast‑path, or deep analysis)
4. Deep Analysis Stages (network → endpoint → enrichment / clustering → compliance mapping)
5. Response Orchestrator (playbook DSL)
6. Persistence & Chain of Custody
7. Observability & Calibration

## Progressive Enhancement Principle
- Each stage MUST either (a) produce a terminal decision with confidence justification or (b) enrich and downgrade remaining uncertainty.
- Earlier low-cost stages MUST bound per-event compute (budget: <1ms @ p95 for baseline on target hardware).

## Decision Object (Canonical)
```
Decision {
  event_id: UUID,
  stage: string,                # last stage that modified the decision
  confidence: float,            # 0..1 adjusted cumulative
  disposition: benign|malicious|suspicious|pending,
  factors: [string],            # normalized taxonomy
  rationale: [string],
  timings: {stage: ms},
  config_digests: {name: sha256},
  custody_hash: sha256,
  version: semver
}
```

## Confidence Routing Thresholds (Initial Defaults)
| Threshold | Action |
|-----------|--------|
| >=0.90    | Fast malicious path (playbook candidate) |
| <=0.10    | Fast benign archive |
| else      | Deep analysis pipeline |

Thresholds are dynamic: replay calibration updates recommended values weekly; proposed changes gated by precision guard (max 5% degradation allowed).

## Module Size Constraint
- Each analytic module SHOULD target 400–500 LOC (excluding tests & shared utilities).
- Shared foundational utilities (hashing, schema validation, config loader) live under `/core/common` and are exempt.

## Minimal External Dependencies
Priority: stdlib + well-vetted libs (e.g. `pydantic` for schema, `prometheus_client` for metrics). ML-heavy libs deferred until Phase ML.

## Failure Containment
- Baseline must degrade gracefully: if threat intel cache fails, it logs and proceeds without TI factors.
- Deep analysis exceptions convert event to `suspicious` with factor `analysis_error` (never silent drop).

## Scaling Strategy
- Vertical scale (single node) until sustained >70% CPU at 10K events/min.
- Introduce queue + worker pool before sharding by tenant or source type.

## Reuse from Neuron.ai
| Existing Asset | Mapping |
|----------------|--------|
| Factor-based scoring & audit log | Decision object + custody & config digest extension |
| Novelty / cluster logic | Deep analysis optional clustering stage |
| Graph edges & degree analytics | Infrastructure correlation enrichment |
| Impact/advice modeling | Compliance & business mapping stage |
| Scenario replay harness | Calibration pipeline |

## Out-of-Scope (Phase 0)
- GPU inference
- Full-text NLP large model embedding
- Full packet reconstruction
- Automated kill switch responses without playbook approval option

## Open Questions
1. Do we require tenant isolation from day one? (Recommended optional namespace wrapper, low overhead.)
2. Will baseline maintain on-disk indicator snapshot for warm restart? (Yes: hashed manifest + digest.)
3. How do we fold cluster stability into confidence? (Add weight scaler: `confidence += clamp(stability*0.05)`).
