# Roadmap & Cost Model

## Phase Breakdown (Indicative)
| Phase | Weeks | Focus | Exit Criteria |
|-------|-------|-------|---------------|
| P0 Foundation | 1-2 | Baseline, orchestrator, metrics skeleton, storage (hot+warm) | Benign fast-path active, custody hash persisted |
| P1 Core Detection | 3-4 | Network hunter, TI cache, routing thresholds calibration, 2 playbooks | ≥65% benign fast-path, first precision report |
| P2 Intelligence Layer | 5-6 | Endpoint hunter, compliance mapper, clustering, impact mapping | MITRE mapping coverage metrics available |
| P3 Advanced Analytics | 7-8 | APT heuristics, infra clustering, NLP intents v1 | APT test scenario flagged within SLA |
| P4 Operationalization | 9-10 | Dashboards, chain verification API, policy/gov module | SLO dashboard live, config digests in decisions |
| P5 Hardening | 11-12 | Rate limiting, action safeguards, perf tuning, docs | 95p latency <120ms @ target load |

## Optional Enhancements & Costs
| Feature | Incremental Effort | Infra Cost Impact |
|---------|--------------------|-------------------|
| Malware analyzer | 2–3 weeks | Sandbox infra $$ |
| Embedding similarity | 1–2 weeks | Minor CPU / mem |
| Multi-tenant isolation | 1–2 weeks | Namespacing overhead |
| Merkle custody | 1 week | Minimal |
| Advanced NLP (LLM assist) | 2–3 weeks + GPU | GPU hourly spend |

## Cost Bands (Rough)
| Deployment Tier | Monthly Infra (Est.) | Description |
|-----------------|-----------------------|-------------|
| Starter | $200–300 | Single node, co-located Redis/Postgres |
| Growth | $600–900 | 3 nodes, dedicated Postgres | 
| Scale | $2k–5k | Autoscaling workers, separate storage tiers |

## Staffing Core (Lean Team)
| Role | Allocation | Phase Presence |
|------|-----------|----------------|
| Lead Engineer | 0.6–1.0 FTE | All phases |
| Detection Engineer | 0.5–0.8 FTE | P1–P4 |
| SRE / Infra | 0.3–0.5 FTE | P0, P4–P5 |
| Security Analyst (feedback) | 0.2–0.4 FTE | Calibration cycles |

## KPI Evolution
| Stage | KPI Focus |
|-------|-----------|
| Early | Routing distribution, latency |
| Mid | Precision, coverage, custody integrity |
| Mature | Automation uptake, APT detection SLA, cost per protected asset |

## Upgrade Pricing Rationale
Value-based Add-ons: clustering analytics pack, compliance reporting suite, advanced response automation.

## Decision Gates
- Gate 1 (end P1): Bench benign fast-path; proceed only if ≥60%.
- Gate 2 (end P3): APT detection test passes.
- Gate 3 (end P5): Latency & precision SLOs stable.

## Open Questions
1. Offer pay-as-you-go event-based billing early? (Requires robust metering first.)
2. Bundle compliance mapping as add-on or core? (Market validation.)
