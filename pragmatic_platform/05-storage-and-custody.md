# Storage & Chain of Custody

## Goals
- Low-latency hot access, indexed warm investigation, cheap immutable cold archive.
- Verifiable integrity across promotions.
- Reasonable cost scaling path.

## Tier Model
| Tier | Tech (initial) | Retention | Contents |
|------|----------------|-----------|----------|
| Hot | Redis (in-memory) | ~1 hour | Active events, sliding windows, TI cache |
| Warm | PostgreSQL (JSONB partitions) | 7–30 days | Normalized events, decisions, playbook logs |
| Cold | Object storage (S3/GCS) | 90–365+ days | Compressed event & decision batches |

## Event Lifecycle
`INGEST → HOT (enriched) → WARM (decision persisted) → (aging) → COLD (archived batch)`

## Hashing & Custody
- Compute SHA256 over canonical JSON serialization of event + decision core (`event_id`, `ts`, factors, disposition, confidence, config digests).
- Store custody hash at each transition with `previous_hash` chain ref (simple linked sequence per event_id).

Schema (warm):
```
chain_custody (
  event_id UUID,
  stage TEXT,          -- ingest|decision|archive
  ts TIMESTAMPTZ,
  hash TEXT,
  prev_hash TEXT,
  actor TEXT DEFAULT 'system'
)
```

## Verification API
`GET /forensics/verify?event_id=<id>` → recompute chain & report mismatches.

## Promotion & Archival
- Batch archive daily: fetch warm rows older than retention, serialize newline-delimited JSON, compress (zstd), upload with manifest (hash list + global digest).
- Manifest structure:
```
{
  "archive_date": "2025-09-21",
  "file": "events-2025-09-20.zst",
  "count": 1250043,
  "sha256": "...",
  "entries_sha256": "<merkle_root_optional>"
}
```

## Indexing Strategy (Warm)
- Partition by day (event_date).
- GIN index on JSONB path for `factors` array.
- B-tree on `(disposition, ts)`.

## Performance Targets
| Operation | p95 Target |
|-----------|-----------|
| Hot read (current minute) | < 2ms |
| Warm insert | < 15ms |
| Decision query (24h window) | < 1s |
| Archive batch upload (1M events) | < 10 min |

## Failure Modes & Fallbacks
| Failure | Fallback |
|---------|----------|
| Redis down | In-process LRU for sliding windows; mark `hot_tier_degraded` |
| Postgres unreachable | Queue decisions locally (bounded) + backpressure; escalate if queue > threshold |
| Archive upload fail | Retry with exponential backoff; alert on 3 consecutive failures |

## Data Minimization
- Strip raw payload fields not used by any active rule before warm persistence (configurable allowlist) to reduce cost.

## Security Controls
- At-rest encryption (Postgres TDE or disk + key mgmt).
- Cold archive object lock (WORM) optional for compliance.
- Access logging: all read queries over warm tier recorded with purpose tag.

## Open Questions
1. Do we need Merkle tree hashing now or defer until multi-tenant forensic attestation? (Defer.)
2. Should we implement incremental compaction for cold batches (rebuild)? (Later optimization.)
