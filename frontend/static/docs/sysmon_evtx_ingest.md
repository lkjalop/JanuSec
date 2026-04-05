# Sysmon / WEF EVTX Ingestion

Two paths:
- `POST /api/v1/ingest/sysmon` — JSON payloads (Sysmon-forwarder style) with optional `{events:[...]}` wrapper.
- `POST /api/v1/ingest/wef` — file upload of EVTX-converted JSON lines or JSON payload with `{events:[...]}`.

Canonical fields used by the platform: `ts`, `host`, `user`, `process`, `pid`, `file_hash`, `event_id`, `raw`.

## JSON Example
```json
{"UtcTime":"2025-12-16T10:00:00Z","Computer":"host1","Image":"C:\\Windows\\System32\\cmd.exe","ProcessId":1234,"Hashes":"SHA256=...","EventID":1}
```

## Upload Example (curl)
```bash
curl -X POST "http://localhost:8080/api/v1/ingest/wef" \
  -H "x-api-key: devkey123" -H "x-tenant-id: demo" \
  -F "file=@wef_sysmon.jsonl"
```

See `frontend/static/csv_multi_analyzer.html` for manual mapping; the normalizer emits canonical fields compatible with the analyzer. 