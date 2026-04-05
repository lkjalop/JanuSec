# JanuSec ML Upgrade Roadmap (20 Steps)

This document outlines the next milestones to mature the ML loop from feature logging to automated promotion and safe deployment. Each milestone lists scope, owner role(s), and a rough effort band.

## M1. Feature Logging & Schema Contracts
- Scope: Standardize event/feature logging (versions, nullability), add JSONSchemas, validation hooks.
- Owner: Backend + Data Eng
- Effort: S

## M2. Offline Dataset Builder
- Scope: Deterministic export (snapshots + labels + features), train/val/test splits, metadata.
- Owner: Data Eng + ML Eng
- Effort: M

## M3. Experiment Tracking & Registry
- Scope: Track runs (config, code hash, metrics, artifacts), simple model registry with tags.
- Owner: ML Eng
- Effort: M

## M4. Training Pipelines
- Scope: Config-driven training (hyperparams, seeds), reproducibility, CI smoke train on sample.
- Owner: ML Eng
- Effort: M

## M5. Cross-Validation & Calibration
- Scope: K-fold CV, calibration comparison (Platt/isotonic/temperature), confidence intervals.
- Owner: ML Eng
- Effort: M

## M6. Drift-Resilient Recalibration
- Scope: Distribution monitoring, rolling recalibration triggers, guardrails.
- Owner: ML Eng + SRE
- Effort: M

## M7. Feature Store Abstraction
- Scope: Materialize features consistently for training/inference; catalog & TTL.
- Owner: Data Eng
- Effort: L

## M8. Online Inference & Hot-Swap
- Scope: Model server abstraction, hot-reload with rollback, version pinning, health probes.
- Owner: Backend + SRE
- Effort: M

## M9. Feedback Loop Integration
- Scope: Factor nudging tied to Labels & Stats with guardrails, promotion-state aware weighting.
- Owner: ML Eng
- Effort: M

## M10. Promotion Policy Automation
- Scope: Formal acceptance gates (precision, support, business KPIs), audit trail.
- Owner: Product + ML Eng
- Effort: S-M

## M11. Drift Detection & Alerts
- Scope: PSI/KS metrics on features/scores, alerting thresholds, runbooks.
- Owner: ML Eng + SRE
- Effort: M

## M12. A/B Testing & Canary
- Scope: Weighted canaries, user/tenant bucketing, success criteria.
- Owner: Backend + Product
- Effort: M

## M13. Explainability Standardization
- Scope: Consistent XAI schemas, per-decision attributions, storage & retrieval.
- Owner: ML Eng + Backend
- Effort: S

## M14. Evaluation Dashboards
- Scope: PR curves, calibration plots, factor precision over time, proposal histories.
- Owner: Data Viz + ML Eng
- Effort: M

## M15. Security & PII Hardening
- Scope: Redaction, minimization, retention policies for training data & logs.
- Owner: Sec Eng + Data Eng
- Effort: M

## M16. Data Quality Gates
- Scope: Contract checks pre-train/pre-serve, anomaly detection on inputs.
- Owner: Data Eng
- Effort: M

## M17. End-to-End Integration Tests
- Scope: Data → Train → Propose → Accept → Apply → Serve; reproducible harness.
- Owner: QA + ML Eng
- Effort: M

## M18. CI/CD for ML
- Scope: Jobs for lint/type/test, sample-train, evaluation gates; artifact promotion.
- Owner: DevX + ML Eng
- Effort: M

## M19. Documentation & Runbooks
- Scope: Playbooks for training, rollback, incident response; onboarding docs.
- Owner: DevRel + ML Eng
- Effort: S

## M20. Observability & Cost
- Scope: Metrics on inference latency/cost, training resource usage, caching effectiveness.
- Owner: SRE + FinOps
- Effort: M

Notes:
- Several foundations are already in place: factor attributions, labels, rolling factor stats, recalibrator proposals with lifecycle & SQLite persistence, gauges, and basic report UI.
- The next practical milestones to unlock fast value are M2 (Dataset Builder), M3 (Experiment Tracking), and M5-M6 (Calibration & Drift).