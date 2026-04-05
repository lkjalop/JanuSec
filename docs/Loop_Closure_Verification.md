# Loop-Closure & CSV Deep-Analyze Verification Plan

Use this checklist when a full backend is available so Opus 4.5 (or another agent with UI/network access) can finish validation. All file/line references are 1-based and match the current repo state.

## 1. LIVE Console Loop-Closure Buttons

### Relevant code
- [frontend/static/janusec-platform-complete-LIVE.html](frontend/static/janusec-platform-complete-LIVE.html#L1289-L1299) – “Loop Closure” panel with `#btnLoopIncident`, `#btnLoopSbom`, and `#loopClosureStatus`.
- [frontend/static/js/investigation.js](frontend/static/js/investigation.js#L17-L33) – stores the currently opened investigation context in `window.__activeInvestigationContext`.
- [frontend/static/js/live_console.bundle.js](frontend/static/js/live_console.bundle.js#L23-L112) – wires the buttons (`attachActionHandlers`) and defines `pushIncidentFromInvestigation` / `pushSbomFromInvestigation`.

### What to verify
1. Open the LIVE console, click a recent alert to open the investigation modal. Ensure `window.__activeInvestigationContext` is populated (e.g., inspect via DevTools console).
2. Click **Push Incident** and confirm:
   - Network tab shows `POST /api/v1/incidents` with the `artifact_id`, `description`, and `attack_subgraph` fields pulled from the active investigation.
   - UI surfaces the success toast and updates `#loopClosureStatus`.
3. Click **Publish SBOM Delta** and confirm:
   - Network tab shows `POST /api/v1/sbom/upload` with a single `components` entry including hash/version metadata from the same investigation.
   - UI status text changes appropriately on success/failure.

## 2. CSV Analyzer Enrichment Loop

### Relevant code
- [frontend/static/js/csv_analyzer.js](frontend/static/js/csv_analyzer.js#L753-L916) – breaker banner, mapping HUD, evidence coverage meter, cached evidence block.
- [frontend/static/js/csv_analyzer.js](frontend/static/js/csv_analyzer.js#L2005-L2050) – `fetchCachedEvidence` helper.
- [frontend/static/js/csv_analyzer.js](frontend/static/js/csv_analyzer.js#L1882-L1975) – “Push Incident” and “SBOM Delta” buttons for per-row loop closure.
- [frontend/static/js/csv_analyzer.js](frontend/static/js/csv_analyzer.js#L1803-L1813) – persona generation wiring.

### What to verify
1. Run a real CSV deep-analyze batch (e.g., `POST /api/v1/csv/deep_analyze`) and load results in `csv_analyzer.html`.
2. Open a high-risk row and confirm the Tier‑1 sidebar shows:
   - Pipeline rank card.
   - Breaker banner text (derived from backend telemetry).
   - Mapping HUD and evidence coverage meter.
   - Cached evidence list with buttons.
3. Click a cached evidence button; verify it calls `GET /api/v1/deep_analyze/assessments/{id}/evidence/{cache_key}` and populates the inline `<pre>` with the payload.
4. Trigger SOC, CISO, and Compliance personas. Confirm `window.LAST_RESULTS[row_index].persona_reports` updates and the persona text appears in both the drilldown pane and the report persona tabs.
5. Use the per-row **Push Incident** / **SBOM Delta** buttons (added near the persona controls). Confirm they post to `/api/v1/incidents` and `/api/v1/sbom/upload` with the normalized row data.

## 3. Assessment Payload Inspection

### Relevant code
- Backend fields were added in [src/api/deep_analyze_endpoints.py](src/api/deep_analyze_endpoints.py) (see `_augment_llm_row` and persona routing logic) and [src/api/graph_sessions.py](src/api/graph_sessions.py).

### What to verify
1. After running deep-analyze, call `GET /api/v1/deep_analyze/assessments/{assessment_id}`.
2. Check that each `llm_row` contains the new enrichment fields:
   - `pipeline_snapshot`
   - `breaker_signal`
   - `mapping_semantics` / `mapping_semantics_score`
   - `binary_context`
   - `kill_chain`
   - `cached_evidence`
   - `persona_templates`
3. If any downstream consumer (dashboards, reports) still expects the older schema, update those modules to tolerate the new fields (no code changes have been made outside the CSV/LIVE console so far).

## 4. Suggested Prompt for Opus 4.5

```
You have access to a running JanuSec backend with valid API credentials.
1. Open http://localhost:8080/static/janusec-platform-complete-LIVE.html, load the latest alerts, and test the “Loop Closure” quick actions. Confirm they call /api/v1/incidents and /api/v1/sbom/upload with the currently opened investigation context.
2. Run a CSV deep-analyze (e.g., POST /api/v1/csv/deep_analyze with sample rows). Load the results in csv_analyzer.html and verify breaker banners, mapping HUD, evidence coverage meter, cached evidence buttons, personas, and the per-row loop-closure buttons.
3. Fetch /api/v1/deep_analyze/assessments/{id} for the same assessment and confirm llm_rows include pipeline_snapshot, breaker_signal, mapping_semantics, binary_context, kill_chain, cached_evidence, and persona_templates.
Document screenshots or logs for each step.
```

Following this checklist will ensure the new loop-closure features are thoroughly exercised before we hand the repo back to stakeholders.

## Fixes Made
- Normalized the top heading and removed a duplicate.
- Converted inline file references to workspace-relative markdown links with line range anchors.
- Fixed minor spacing and non-breaking-space issues.

## Recommended Next Steps (actionable)
- Add small `curl` snippets under each verification step for quick testing. I can add these automatically if you want.
- Add a lightweight `scripts/verify_loop_closure.py` that exercises the endpoints in the checklist (requires the backend to be running).
- Harden backend to always include `pipeline_snapshot` and `persona_templates` in `llm_row` (if missing, return empty defaults) to make UI tolerant to schema evolution.

Quick curl snippets (assumes server on http://localhost:8080 and default dev key `devkey123`)

- Create a CSV deep analyze assessment (replace sample rows as needed):

```bash
curl -sS -X POST http://localhost:8080/api/v1/csv/deep_analyze \
   -H "Content-Type: application/json" \
   -H "x-api-key: devkey123" \
   -d '{"rows":[{"process_name":"notepad.exe","file_path":"C:/Windows/notepad.exe","sha256":""}], "org":"unknown"}'
```

- Start auto backfill (use assessment_id from the previous response):

```bash
curl -sS -X POST http://localhost:8080/api/v1/csv/deep_analyze/auto_backfill \
   -H "Content-Type: application/json" -H "x-api-key: devkey123" \
   -d '{"assessment_id":"<ASSESSMENT_ID>", "target_coverage":0.8, "batch_size":25}'
```

- Poll backfill status:

```bash
curl -sS http://localhost:8080/api/v1/csv/deep_analyze/auto_backfill/<ASSESSMENT_ID>/status -H "x-api-key: devkey123"
```

- Create Incident (loop-closure example):

```bash
curl -sS -X POST http://localhost:8080/api/v1/incidents \
   -H "Content-Type: application/json" -H "x-api-key: devkey123" \
   -d '{"artifact_id":"row-0","title":"Test Incident","description":"From loop-closure test","attack_subgraph":{}}'
```

- Upload SBOM delta (loop-closure example):

```bash
curl -sS -X POST http://localhost:8080/api/v1/sbom/upload \
   -H "Content-Type: application/json" -H "x-api-key: devkey123" \
   -d '{"components":[{"name":"example","version":"1.2.3","purl":"pkg:generic/example@1.2.3"}]}'
```


