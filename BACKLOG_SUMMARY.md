# Backlog summary — done vs left (snapshot)

This document maps the main backlog/test/demo items to current files, scripts, and tests in the repository (evidence + owner). Generated: 2025-10-13.

## Short rationale: why ingest analyze results into HopGraph?
- Faster multi-hop detection: connecting host → process → hash in the graph lets explainability (`explain_chain`) find relationships across rows and time.
- Context enrichment: graph stores node attributes and timestamps, enabling age-decay and temporal reasoning for triage.
- Reuse: other subsystems (graph endpoints, correlation engine) can reuse the same provenance graph.
- Alert consolidation: linking duplicate hashes/processes across hosts reduces analyst noise.
- Lightweight pivoting: analyst can quickly pivot from a hash to all affected hosts or processes.
- Supports downstream scoring and automated playbooks that operate on graph patterns.

## Implemented (evidence)
- CSV analyzer (processor and endpoints)
  - `src/api/csv_handler.py` — `CSVProcessor` (core heuristics and analysis).
  - `src/api/csv_endpoints.py` — `/api/v1/csv/upload`, `/api/v1/csv/upload-page`, `/api/v1/csv/analyze_row` (HTTP wiring and UI page).
  - Scripts used to validate: `scripts/run_csv_processor.py`, `scripts/post_analyze.py`, `scripts/post_analyze_rows_from_csv.py`.
- Excel → CSV path
  - Excel conversion used in `src/api/csv_endpoints.py` (openpyxl conversion). Sample created: `dump/Cyberstash_csv2_sample.xlsx` and `dump/Cyberstash_csv2_sample.csv`.
- HopGraph ingestion & explain
  - `src/graph/hopgraph.py` — `HopGraph` and `GLOBAL_HOPGRAPH` with `ingest_event`, `add_edge`, `explain_chain`.
  - Ingestion scripts: `scripts/ingest_csv_rows_to_hopgraph.py`, `scripts/ingest_analyze_results_into_hopgraph.py`, `scripts/process_excel_and_ingest.py`.
  - Smoke tests / demos: `scripts/hopgraph_smoke.py`.
- Demo server and UI
  - FastAPI app served by `api.app:app` (startable with uvicorn). Live demo endpoint used: `/api/v1/csv/upload-page` (served HTML in `src/api/csv_endpoints.py`).

## What I ran / validated (this session)
- Started uvicorn locally and exercised the demo upload page (`/api/v1/csv/upload-page`).
- Uploaded `dump/Cyberstash_csv2_sample.xlsx` to `/api/v1/csv/upload` — server returned 6 processed rows and `session` id.
- Queried `/api/v1/upload/tabular/page?session=<id>` to read rows back for pagination.
- Called `/api/v1/csv/analyze_row` successfully; fixed an async bug where `compose_risk_score` could be a coroutine (patched `src/api/csv_endpoints.py`).
- Ran `scripts/post_analyze_rows_from_csv.py` to call `analyze_row` for each CSV row and saved results to `dump/session_manual_analyze.jsonl`.
- Ingested CSV rows directly into `GLOBAL_HOPGRAPH` using `scripts/ingest_csv_rows_to_hopgraph.py` and confirmed edges and an `explain_chain` output.

## Remaining / partly done items (recommended next steps)
- CyberStash webhook end-to-end
  - Files: `src/api/cyberstash_endpoints.py` (HMAC verification, webhook receiver). Pending: run signed POSTs and replay tests. Owner: you/me. Complexity: medium.
- Zeek/XDR demo flows
  - Files: `src/api/upload_endpoints.py` (PCAP/EVTX handlers) and frontend samples. Pending: feed Zeek samples and confirm ingestion / HopGraph mapping. Owner: you/me.
- Full test run and static diagnostics
  - Task: run `python -m pytest` (or the workspace task `pytest-new`) and triage failures (may require installing optional packages). Owner: you/me.
- BACKLOG_SUMMARY.md added (this file)

## Quick pointers (where to look)
- `src/api/csv_handler.py` — analysis logic
- `src/api/csv_endpoints.py` — endpoints and analyze_row implementation
- `src/api/upload_endpoints.py` — tabular session handling and file uploads
- `src/graph/hopgraph.py` — graph data model (`ingest_event`, `explain_chain`)
- `dump/` — sample CSV/XLSX and generated JSONL outputs
- `scripts/` — quick runners used in this session (see above)

## Notes and small risks
- The demo server depends on optional integrations (threat intel client, composer) which are best-effort and gracefully degrade; tests that assume them will fail unless the dependencies are present.
- Docker compose task `demo-up` requires a local Docker engine; in this environment Docker was unavailable and I ran uvicorn directly.

---
If you want I can:
- Produce a short CSV -> HopGraph ingestion report (counts per host/process/hash) from the current graph.
- Run the CyberStash webhook signed test next and show the server accepting and rejecting replays.

