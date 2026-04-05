# Reporting in JanuSec

Overview
--------
JanuSec includes a report generator that aggregates decisions, threat model summaries (STRIDE/DREAD/MAESTRO), and factor-level explainability into downloadable CSV/HTML and optional PDF outputs. Reports support filtering by time range, tenant, host, and severity.

Where it lives
--------------
- Core report aggregation code: `src/api/report_aggregation.py`
- API endpoints for exporting reports: `src/api/report_endpoints.py`

Report types
------------
- Summary Report (CSV/HTML)
  - Aggregates decision counts, average DREAD components, MAESTRO tags
  - Parameters: start_ts, end_ts, tenant_id, min_confidence

- Detailed Event Report (CSV/JSON)
  - Row per decision including factors, event_id, verdict, confidence, threat model
  - Parameters: same as above + include_raw_event (bool)

- Forensic Report (ZIP)
  - Bundle of selected raw events, custody hashes, replay IDs and attached artifacts
  - Parameters: event_id list or time range

- Executive Summary (HTML/PDF)
  - High-level counts, top threat types, DREAD heatmap, recommended remediations
  - Designed for SOC managers and compliance teams

How to generate
---------------
- UI: `/api/v1/reports` endpoints provide links to CSV/HTML downloads.
- Programmatic: call `/api/v1/reports/generate` with JSON payload describing filters.

Customization & templates
------------------------
- Reports are generated from templates; to change presentation edit templates under `src/api/templates/`.
- PDF generation uses `reportlab`/`weasyprint` if available; otherwise HTML is returned for conversion by external tools.

Scheduling & exports
--------------------
- Reports can be scheduled externally (cron or CI) by calling the report endpoints.
- For large historical exports, prefer exporting in batches (per-day) to avoid memory spikes.

Security & access
-----------------
- Ensure that report endpoints respect tenant scoping and auth tokens; only authorized users should request tenant-scoped exports.
- Forensic reports contain raw events — protect delivery channels (S3 with pre-signed URLs, encrypted ZIPs).

Examples
--------
1. Generate a CSV summary for tenant `acme` last 24 hours (programmatic):

```json
POST /api/v1/reports/generate
{
  "tenant_id": "acme",
  "start_ts": 1696128000,
  "end_ts": 1696214400,
  "format": "csv",
  "type": "summary"
}
```

Notes
-----
- The report generator is intentionally memory-conservative; streaming writers are used for CSV generation.
- PDF generation is heavier and may be disabled in low-memory environments.
