# COMPREHENSIVE STRATEGIC ASSESSMENT – Addendum (Edits + Evidence)

This addendum provides precise redlines, evidence hooks, and connection guidance to strengthen the assessment and align it with the current platform capabilities.

## Key Corrections

- Compliance capability exists.
  - Update claim to: “ISO/IEC 27001 assessment and reports are present; PCI‑DSS/HIPAA templates pending.”
  - References: `src/api/compliance_endpoints.py`, `src/modules/compliance_mapper.py`, `src/modules/compliance/taxonomy_loader.py`.

- Controls mapping in reports.
  - Note factor→control IDs (CIS/NIST/ISO) and that the ingestion report includes “Observed Control References.”
  - References: `src/core/threat_modeling/factor_taxonomy.py`, `src/api/report_aggregation.py`, `src/api/report_endpoints.py`.

- Cloud Posture (CSPM‑lite).
  - Add: “CSPM‑lite posture intake + dashboard card” with tenant‑scoped summary.
  - References: `src/api/compliance_endpoints.py`, `src/api/metrics_status_endpoints.py`, `frontend/static/janusec-platform-complete-LIVE.html`, `frontend/static/compliance.html`.

- UI size/claim clarification.
  - Prefer: “multi‑section single‑file console” rather than line count.
  - Reference: `frontend/static/janusec-platform-complete-LIVE.html`.

## Stronger Evidence Hooks

- FinOps / ROI
  - Suggested: “FinOps overview and daily/forecast endpoints quantify cost avoidance and analyst time saved.”
  - References: `src/api/metrics_status_endpoints.py`, `src/core/metrics/cost_ledger.py`.

- Explainability
  - Link threat model and explain endpoints already present.
  - References: `src/api/report_endpoints.py`, `src/api/risk_endpoints.py`, `src/core/risk_score.py`.

## How Customers Connect

- Ingest options
  - HTTP uploads: `POST /api/v1/upload/files`
  - Streams: `POST /api/v1/stream/ingest`
  - Connectors (Filebeat/Fluent Bit/Logstash): configs under `deploy/connectors/`

- Posture (cloud/K8s/IAM)
  - Ingest: `POST /api/v1/compliance/posture`
  - Summary: `GET /api/v1/compliance/posture`

- SBOM
  - Upload: `POST /api/v1/sbom/upload`
  - Vulns: `GET /api/v1/sbom/vulns?sbom_id=...`

- Reports
  - Executive: `/api/v1/report/ingestion?format=html&include_model=true`

- Headers / Security
  - Include `x-api-key` (local default `devkey123`) and `X-Tenant-ID` for tenant scope.
  - Terminate TLS/OIDC/mTLS at gateway: see `deploy/gateway/*`.
  - Redaction and webhook guardrails: `src/core/redaction.py`, `src/api/webhook_middleware.py`.

## Polish Recommendations (Drop‑in Text)

- Executive Summary
  - Add: “Includes CSPM‑lite cloud posture summary and ISO/IEC 27001 compliance reports.”

- Frontend Quality
  - Replace with: “Functional console with real‑time widgets; Cloud Posture card and control reference pills visible. React app present under `frontend/react/*`, default startup serves the static console.”

- Unique Selling Points
  - Add: “Compliance‑aware narratives with control IDs in executive reports” and “Cloud posture risk card (tenant‑aware).”

- Compliance Templates: Missing
  - Replace with: “ISO/IEC 27001 assessment and reports are available. PCI‑DSS/HIPAA/SOC 2 templates are not yet implemented.”

- Commercial Viability / ROI
  - Add: “FinOps endpoints provide cost/savings estimates for ingestion, storage, and avoided manual triage to back ROI claims.”

## Recently Landed Improvements

- Tenant‑aware Cloud Posture summary + dashboard card
  - `GET /api/v1/compliance/posture` (tenant filter, severity rollup, risk score)
  - Dashboard aggregation is tenant‑aware: `src/api/metrics_status_endpoints.py`

- Control IDs surfaced in ingestion reports (HTML + JSON)
  - “Observed Control References (CIS/NIST/ISO)” section
  - References: `src/api/report_aggregation.py`, `src/api/report_endpoints.py`

- Lightweight JSONL cache for predictive and posture reads
  - Avoids per‑request file scans; improves demo robustness.
  - Reference: `src/common/jsonl_cache.py`

## Optional Next Steps (Roadmap Inserts)

- Validation (KPIs)
  - “Track FP/TP deltas via correlation rule metrics in Prometheus; export deltas to reporting endpoints. Target FP < 10/1000, Gray recall ≥ 90%.”

- Productization (Compliance templates)
  - Enumerate PCI‑DSS 4.0, HIPAA Security Rule, SOC 2 CC series; plan taxonomy loaders like `src/modules/compliance/taxonomy_loader.py`.

- Market (MSSP tenancy)
  - Add “MSSP tenancy demos” scenario using `X-Tenant-ID`.

---

Updated paths and endpoints reflect current repo state. You can link this addendum in your executive doc or inline the drop‑in copy where indicated.

