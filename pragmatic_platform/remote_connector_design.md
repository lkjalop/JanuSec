# Remote Endpoint Connector Design

## Objectives
Provide a lightweight, secure channel for endpoint + host telemetry and targeted file sample delivery into the threat sifting pipeline with:
- Low operational footprint (single binary or scriptable agent)
- Resilience under intermittent connectivity
- Integrity, replay protection, and basic authenticity
- Bounded resource & rate usage per connector
- Extensible schema (versioned) with backward compatibility

## Operating Modes
| Mode | Description | Pros | Cons |
|------|-------------|------|------|
| Push (Agent → Server) | Agent batches events and POSTs JSONL/Compressed payloads | Simple firewall story, server stateless ingestion | Agent must handle backpressure locally |
| Pull (Server Tasks) | Agent periodically polls for work (upload URLs, file requests) | Central control over burst scheduling | Higher round-trip latency, requires task queue |
| Hybrid | Push telemetry + pull for on-demand file/sample or sandbox tasks | Optimizes steady telemetry + controlled heavy ops | Slightly more complex implementation |

Phase 1: Push-only + optional long poll for control messages.
Phase 2: Introduce task polling channel for on-demand file retrieval / memory snapshot tasks.

## Transport & Auth
- Endpoint: `POST /connector/ingest` (telemetry)
- Endpoint: `POST /connector/files` (file sample manifest or chunked upload reference)
- Auth Header: `X-Connector-ID` + `X-Connector-Signature`
- Shared secret per connector (rotated daily); signature = `HMAC_SHA256(timestamp + '.' + body)`
- Headers: `X-Timestamp` (unix seconds) with ±300s replay window
- Optional mTLS (Phase 2) for high assurance deployments
- Connectors receive server-issued short-lived secret via out-of-band provisioning API or console.

## Payload Structure (Telemetry Batch)
```
{
  "schema_version": "1.0",
  "connector_id": "win-east-01",
  "seq": 10231,              # monotonically increasing per connector
  "generated_ts": 1732471234, # agent generation time
  "events": [ EndpointEvent ... ],
  "metrics": {"queue_lag_ms": 20, "batch_events": 250},
  "integrity": {"sha256": "<hash_of_canonical_events_array>"}
}
```

### EndpointEvent (Minimal v1)
```
EndpointEvent {
  ts: int,
  host_id: string,
  user?: string,
  type: "process_start"|"file_write"|"net_conn"|"registry_mod"|"service_install",
  process?: { name, pid?, ppid?, hash?, path?, signed?, signature_valid? },
  parent?: { name?, hash? },
  file?: { path?, hash?, size?, entropy? },
  net?: { dst_ip?, dst_port?, protocol? },
  registry?: { path?, op? },
  service?: { name?, path? },
  cmdline?: string,
  meta?: { k: v }
}
```

### Canonicalization Rules
- Keys sorted lexicographically for hashing.
- Numeric timestamps in seconds (int). No floats.
- Absent optional blocks omitted (not null).

## Sequence & Replay
- Server stores last accepted `seq` per connector.
- Reject if `seq <= last_seq` unless `seq_wrap` flag (future 64-bit wrap case).
- Replay window on timestamp and duplicate batch digest check.

## Rate & Backpressure
| Control | Mechanism | Default |
|---------|-----------|---------|
| EPS soft cap | Token bucket per connector (refill r/s) | 50 events/s burst 100 |
| Batch size | Enforced max events per request | 500 |
| File sample size | Max single file 20MB (configurable) | 20MB |
| Concurrent uploads | Semaphore per connector | 2 |

Server responses may include `backoff_seconds` hint when near capacity.

## Error Responses (Simplified)
| Code | Reason | Client Action |
|------|--------|---------------|
| 401 | Auth/signature invalid | Re-auth or rotate secret |
| 409 | Sequence conflict | Re-send with higher seq / investigate clock skew |
| 429 | Rate limit | Honor `backoff_seconds` |
| 400 | Malformed payload | Fix serialization, do not retry same batch |

## Integrity & Custody
- Agent computes SHA256 over canonical JSON array of events: `integrity.sha256`.
- Server recomputes; mismatch = reject (400) with `integrity_mismatch` detail.
- Accepted batch events optionally appended to `data/connector_ingest/<connector_id>.jsonl` (rotated daily) with custody hash chain (prev_hash field).

## Security Considerations / Threat Model
| Threat | Mitigation |
|--------|-----------|
| Replay of old batch | Timestamp + sequence + digest cache |
| Tampered in transit (no TLS MITM) | HTTPS + signature over body | 
| Stolen connector secret | Short rotation interval, revoke connector ID, anomaly detection on geo/fingerprint |
| Flood / DoS | Token bucket + global queue high-water rejection |
| Payload inflation (zip bombs) | No compressed inline file content; file samples chunked or hashed first |
| Malicious field injection | Strict JSON schema validation + whitelist keys |
| Lateral movement via agent | Agent runs least-privilege, no shell command exec from server without explicit task spec approval |

## File Sample Flow (Phase 1.5)
1. Agent detects new executable with unknown hash.
2. Sends metadata in normal batch (`file.hash` + attributes).
3. Server may respond with `sample_request: true` in lightweight control response.
4. Agent performs separate `POST /connector/files` with multipart or pre-signed URL negotiation.

### File Upload Negotiation (Future)
```
POST /connector/file_request { hash, size }
<- { upload_url, expires_ts, max_parts }
```

## Control Channel (Future Poll)
`GET /connector/control?since=<last_ts>` returns tasks array:
```
{
  "tasks": [
    {"id":"t1","type":"fetch_file","hash":"...","priority":3},
    {"id":"t2","type":"sandbox_exec","hash":"...","timeout_s":120}
  ],
  "backoff_seconds": 0
}
```
Agent acknowledges with `POST /connector/control/ack { task_id, status }`.

## Schema Versioning
- `schema_version` major bump on incompatible change.
- Server maintains compatibility matrix; reject unsupported versions (406) with hint.

## Observability
Metrics (per connector labels):
- `connector_events_total{connector}`
- `connector_batches_total{connector,status}` (accepted/rejected)
- `connector_backoff_seconds{connector}` (gauge)
- `connector_ingest_latency_ms` (histogram)
- `connector_seq_gap_total` (count of non-contiguous sequences)

## Integration into Pipeline
1. Ingest converts EndpointEvent -> normalized event dict.
2. Adds to baseline & endpoint hunter (rare lineage / persistence).
3. File hash triage auto-attachment via `FILE_HASH_FACTORS` if already uploaded.
4. Future: dynamic analysis trigger if `endpoint:rare_lineage` + unknown file hash + SBOM critical exposure.

## Minimal Pydantic Stub (Server-side TODO)
```
class ConnectorBatch(BaseModel):
    schema_version: str
    connector_id: str
    seq: int
    generated_ts: int
    events: list[dict]
    metrics: dict | None = None
    integrity: dict
```

## Rollout Plan
1. Implement server endpoints without agent (manual curl tests).
2. Provide reference Python agent (proof-of-concept).
3. Add secret rotation + admin revocation endpoint.
4. Introduce file sample request handshake.
5. Add control polling channel for sandbox / targeted retrieval.

## Open Questions
1. Do we need per-event ack? (Not initially; rely on batch-level idempotency.)
2. Should we support compression (gzip) early? (Optional header `Content-Encoding: gzip` Phase 2.)
3. Multi-tenant connectors? (Tag connector with tenant_id; enforce isolation.)
