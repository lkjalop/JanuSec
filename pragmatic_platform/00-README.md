# Pragmatic Threat Sifting Platform Docs

This directory bootstraps the design and implementation guidance for a cost‑effective progressive threat sifting platform derived from Neuron.ai lessons.

## Document Index
| File | Purpose |
|------|---------|
| 01-architecture-overview.md | High-level system & layering rationale |
| 02-module-contracts.md | Per-module responsibilities, inputs/outputs, LOC budget |
| 03-routing-and-confidence.md | Confidence scoring model & routing thresholds calibration |
| 04-detection-strategy.md | Detection families, factor taxonomy, APT heuristic spec |
| 05-storage-and-custody.md | Tiered storage, hashing, provenance & verification APIs |
| 06-metrics-and-SLOs.md | Metrics catalog, SLO targets, alerting rules |
| 07-config-provenance-and-digests.md | Config hashing, reload semantics, audit embedding |
| 08-playbook-dsl-spec.md | SOAR / response playbook YAML schema & execution model |
| 09-nlp-intent-spec.md | Lightweight intent + entity extraction registry |
| 10-calibration-and-replay.md | Replay harness use, threshold tuning workflow |
| 11-risk-register.md | Tracked risks, mitigation statuses, owners |
| 12-roadmap-and-cost-model.md | Phased delivery & infra / staffing cost bands |
| 13-extensibility-and-future-ml.md | Embeddings, neuromorphic roadmap & optional upgrades |

## Authoring Conventions
- Keep each doc < ~500 lines; deeper explorations go in `appendices/`.
- Use RFC-style MUST/SHOULD/MAY for normative guidance.
- All code examples are language-agnostic pseudocode unless suffixed with language tag.

## Immediate Next Actions
1. Finalize confidence & routing calibration spec (03).
2. Lock module contracts (02) before coding skeleton.
3. Implement config digest prototype referencing 07.
4. Stand up replay gating referencing 10.
