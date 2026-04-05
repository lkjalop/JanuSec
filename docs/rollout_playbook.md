# JanuSec rollout playbook (Phases 1–5)

This playbook turns the phased plan into concrete steps, Windows-friendly commands, and measurable KPIs. It references existing API endpoints and scripts in this repo.

Prereqs
- API is running locally on http://localhost:8080 with DEFAULT_FRONTEND=console
- x-api-key is configured (dev default: devkey123)
- PowerShell v5.1+ available

Key schemas and endpoints
- IngestEvent schema: `src/api/schemas.py`
- LogEvent/LogBatch: `src/api/server.py` (classes `LogEvent`, `LogBatchRequest`)
- Per-event ingest: POST /api/v1/events
- Batch ingest: POST /api/v1/endpoints/log_batch
- Batch uploads: POST /api/v1/upload/files
- CSV/Excel analyzer: POST /api/v1/csv/upload; sessions: /api/v1/upload/tabular/sessions
- Decisions SSE: GET /api/v1/stream/decisions
- Writeback: POST /api/v1/integrations/{name}/writeback

## Phase 1 — Batch validation (EVTX/PCAP/CSV/Excel)

Goal: Validate parsing, decisioning, and report usefulness before streaming.

Do this
- Upload sample artifacts:
  - Use the UI “Upload Logs” or run the helper script below
- Inspect HTML ingestion report: /api/v1/report/ingestion?format=html&include_model=true&include_scenarios=true
- For CSV/Excel, use the CSV analyzer: `/static/csv_analyzer.html`

Helper (PowerShell)
- `scripts/phase1_batch_upload.ps1` uploads all files from a folder via /api/v1/upload/files

KPIs to record (see `docs/kpis.csv` for headers)
- Precision/recall on labeled sets (or proxy: analyst agreement rate)
- False positive reduction on common telemetry
- Report usefulness: do explanations enable faster triage? (analyst survey or time-to-understanding)

## Phase 2 — Telemetry mapping

Goal: Map your endpoint/network fields to JanuSec schemas.

Do this
- For per-event: map to IngestEvent (see `src/api/schemas.py`)
- For batches (Zeek/EDR): map to LogEvent and send with LogBatchRequest (`src/api/server.py`)
- Use Zeek helpers: `scripts/zeek_tail_forwarder.py`, `scripts/zeek_replay.py`

Example minimal IngestEvent
```
{
  "id": "evt-123",
  "domain": "example.org",
  "details": {
    "process": {"name": "powershell.exe", "parent_name": "winword.exe"}
  }
}
```

Example LogBatchRequest
```
{
  "events": [
    {"id": "z1", "host": "zeek1", "dns_rcode": 3, "process": {"name": "zeek:conn"}}
  ],
  "classify": true,
  "include_rules": true,
  "send_alerts": false,
  "tenant_id": "default"
}
```

KPIs
- Mapping completeness (% of fields mapped)
- Time to first live host or Zeek feed

## Phase 3 — Start streaming

Goal: Stream a subset of hosts/tenants through JanuSec.

Options
- Fluent Bit tail + HTTP output → /api/v1/events (single-event) or /api/v1/endpoints/log_batch (batched)
- Filebeat HTTP output → /api/v1/events or /api/v1/endpoints/log_batch
- Use Zeek forwarder: `scripts/zeek_tail_forwarder.py`

Samples included in repo
- `deploy/connectors/fluentbit_to_janusec.conf`
- `deploy/connectors/filebeat_http.yml`

Helpers
- `scripts/ingest_sample.ps1` — posts a small synthetic batch to /api/v1/endpoints/log_batch
- `scripts/measure_decision_latency.ps1` — measures mean decision latency via /api/v1/events

KPIs
- Mean decision latency (ingest → decision)
- Alert volume reduction before SIEM
- Analyst time-to-first-triage on new alerts

## Phase 4 — Wire writeback to playbooks

Goal: Push outcomes back to XDR/SIEM/SOAR or chat.

Do this
- Invoke POST /api/v1/integrations/{name}/writeback with tags/notes/severity
- Or use /api/v1/webhooks/test for chat POCs

Helper
- `scripts/writeback_example.ps1` — updates a vendor alert (e.g., Eclipse) with tags/notes

KPIs
- Adoption in analyst workflow (notes/tags added automatically)
- Mean time to enrichment/writeback

## Phase 5 — Hardening and scale

Goal: Operate reliably under load with guardrails.

Settings to review (env)
- MAX_UPLOAD_BYTES — batch upload size caps
- ALERT_DEDUP_TTL_SECONDS — alert deduplication window
- BATCH_SLOW_PATH_THRESHOLD — auto-disable heavy features for large batches
- ZEEK_NXDOMAIN_RATE_THRESHOLD, NX_RATE_TRACKER_ENABLED — NX tracking
- DEFAULT_TENANT, API_KEYS_JSON — tenancy and keys

Shippers
- Enable TLS and buffering in Fluent Bit/Filebeat/Logstash
- Add retry/backoff; verify delivery telemetry

Persistence
- If you need durable queues, back EVENT_QUEUE with a broker and enable DLQ monitoring (see /api/v1/dlq*)

KPIs
- Throughput sustained (events/sec)
- Error rate and retry success rate
- SIEM cost reduction (%) from filtered volume

## Try it quickly (PowerShell)

- Batch upload a file
```powershell
curl -X POST http://localhost:8080/api/v1/upload/files -H "x-api-key: devkey123" -F "files=@C:\\path\\to\\sample.evtx"
```

- Post a single event
```powershell
curl -X POST http://localhost:8080/api/v1/events -H "Content-Type: application/json" -H "x-api-key: devkey123" --data '{"id":"e-1","domain":"example.org","details":{"process":{"name":"powershell.exe","parent_name":"winword.exe"}}}'
```

- Stream Zeek logs
```powershell
python scripts/zeek_tail_forwarder.py --logs D:\Zeek\logs\current --api http://localhost:8080 --state zeek_forward_state.json
```

- Watch decisions (browser)
- http://localhost:8080/api/v1/stream/decisions

## KPI checklist
See `docs/kpis.csv` for a starter template and populate one row per phase.

---
Maintainer note: These steps mirror endpoints and scripts in `src/api` and `scripts/`. Adjust host, headers, and secrets for non-local environments.
