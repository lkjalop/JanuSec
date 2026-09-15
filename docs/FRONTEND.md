# JanusSec frontend

The canonical, supported UI is the framework-free case workspace:

- `frontend/static/janusec-platform-complete-LIVE.html`
- `frontend/static/css/case-workspace.css`
- `frontend/static/js/case-workspace.js`

It is served at `/`, `/console`, and `/live`. The UI consumes the server-owned
`GET /api/v1/assessments/{assessment_id}/case-view` projection. The browser must
not infer causal edges, merge identities, calculate verdicts, or authenticate by
putting credentials in URLs.

`assessment.html` and `investigation.html` are compatibility redirects. Their
former implementations are under `frontend/archive/legacy/` and are not supported
application surfaces. Other specialist pages remain available during migration,
but new case workflows belong in the canonical workspace.

See `docs/architecture/case-workspace-wireframes.md` for the layout and interaction
model.

The header's Model scope selector is populated from
`GET /api/v1/assessments/{assessment_id}/cases`. Model runs for multi-case
assessments must include the selected `case_id`; the server rejects an
assessment-wide model request rather than allowing cross-case contamination.
Case/question-scoped retrieval uses
`POST /api/v1/assessments/{assessment_id}/cases/{case_id}/evidence-pack`.
