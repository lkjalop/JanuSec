Compliance Readiness Assist
===========================

Scope
- Evidence-to-control readiness indicators for ISO 27001 (subset), SOC2/NIST extensible via JSON.
- Transparent mapping and explainability; NOT a certification engine.

Key Features
- Upload policy/log/text/PDF evidence; deterministic chunk scoring against controls.
- STRIDE/DREAD/MAESTRO model context (from LIVE console) supports mapping hints.
- SBOM tie-in: link sbom_id and fetch vulnerabilities to augment controls.
- Reports: HTML/PDF; GraphML export of control–evidence relationships.
- External mode: optional webhook to offload processing to client infra.

Guardrails
- Redaction applied to evidence text (email/SSN/card/IP patterns); size/type limits configurable.
- Tenant-scoped in-memory storage; persistence optional.
- Positioning as readiness assist; outputs are advisory and not legal attestations.

Metrics
- Prometheus counters: janusec_compliance_assess_total{mode}, janusec_compliance_report_total{format}.

Roadmap
- JSON taxonomy import for TitanAI mappings; unit tests for coverage.
- UI: filters, CSV export, risk heatmap (added); processing mode toggle (added).
- Persistence: sqlite/adapter-backed assessments + background jobs.

