# Slide Deck Outline (Draft)

## 1. Title
"JanuSec Detection & Action Platform – Lean MVB"  
Tagline: From Raw Telemetry to Actionable Containment in <1s

## 2. Problem & Context
- Fragmented signals, high FP noise
- Slow containment loop
- Lack of governance & promotion methodology

## 3. High-Level Architecture
Diagram: Ingestion → Policy → Factor Pipeline → Decision Ladder → Actions (Slack/Eclipse) → Governance/ROI
Bullets: Multi-tenant isolation, integrity hashing, promotion workflow

## 4. Ingestion & Normalization
- Canonical schema
- Eclipse.XDR adapter (batch + streaming)
- Integrity & truncation safeguards

## 5. Policy & Classification Ladder
- Allow/Block fast path (wildcards, regex)
- Severity + quality gating (threshold ladder)
- Escalation queue for analyst loop

## 6. Detection Signal Stack
List factors (sbom drift, egress spikes, domain novelty, rare token, beacon heuristics, lane factors)  
Promotion readiness & sustained emergence logic

## 7. Quality & Suppression
- Factor precision tracking (windowed)
- Automatic suppression, re-enable on recovery

## 8. Governance & ROI
- Coverage delta trends (visual matrix)
- Promotion candidates & uplift metrics
- Roadmap: per-tenant threshold overrides

## 9. Actions & Outbound Integrations
- Slack alerts (block / escalate)
- Eclipse action callback stub
- File + DB custody & audit

## 10. Multi-Tenancy & Integrity
- Partitioned state directories
- HMAC state file option
- Custody chain hashing for decisions

## 11. Metrics & Observability
- Prometheus counters/gauges (promotion candidates, queue depth, drift)
- Planned severity rollup endpoint

## 12. Roadmap (Next 60–90 Days)
- Persistent escalation store & analyst resolution feedback loop
- Severity rollup endpoint + dashboards
- Policy suggestion engine (data-driven)
- Enforcement plugins (EDR isolation, firewall APIs)
- ML anomaly scoring (embedding drift + ensembles)

## 13. Risk & Mitigations
Table: Area | Risk | Mitigation (e.g., policy misconfig, false block → dry-run mode)

## 14. KPIs & Success Criteria
- Mean decision latency
- Block rate accuracy (manual sample FP < X%)
- Time-to-promotion for high-signal factors
- Analyst escalation resolution time

## 15. Call to Action
- Approve next phase (rollup + enforcement plugin)
- Provide Eclipse outbound API spec for full integration

---
Appendix: Config table, Env vars, Factor descriptions
