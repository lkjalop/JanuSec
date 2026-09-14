# Unified Event Schema (Version 1)

Goal: Provide a durable, multi-domain normalized envelope enabling factor enrichment, kill chain reconstruction (>96h horizon), and embedding generation.

## Envelope
```
{
  "event_id": "uuid",                // globally unique
  "tenant_id": "t123",               // multi-tenant partition key
  "ts": 1730956800.123,               // epoch seconds (float for ms)
  "ingest_source": "okta|aad|aws|gcp|o365|gmail|api_gateway|edr|netflow|dns|proxy|cloudtrail|custom",
  "domain": "iam|data|api|email|cloud|endpoint|network|remote|sbom",
  "kill_chain_hint": ["Recon","InitialAccess",...],
  "factors": [],                      // populated post-enrichment
  "raw": { ... },                     // source native record (lightweight subset)
  "actor": {                          // identity / principal normalization
    "principal_id": "user:alice",   // or svc:app123, host:WIN10-7
    "principal_type": "user|service|host|email|api_key",
    "account_age_days": 42,
    "mfa_enrolled": true
  },
  "network": {
    "src_ip": "1.2.3.4",
    "dst_ip": "8.8.8.8",
    "src_port": 51514,
    "dst_port": 443,
    "protocol": "TCP",
    "asn": 15169,
    "geo": "US"
  },
  "object": {                         // data / cloud / file object
    "type": "s3_object|file|db_row|mail",
    "name": "finance_q4.xlsx",
    "classification": "sensitive|pii|public",
    "size_bytes": 1048576,
    "hash": "sha256:..."
  },
  "api": {
    "method": "GET",
    "path": "/v1/payments",
    "status": 200,
    "latency_ms": 34,
    "auth_subject": "user:alice",
    "token_id": "tok_abc",
    "error_class": null,
    "param_names": ["customer_id","since"],
    "payload_entropy": 4.7
  },
  "cloud": {
    "provider": "aws|gcp|azure",
    "resource_id": "arn:aws:iam::123:role/Admin",
    "change_type": "policy_diff|acl_update|exposure",
    "old_value": "{...}",
    "new_value": "{...}",
    "risk_delta": 0.42
  },
  "email": {
    "from": "ceo@example.com",
    "to": ["finance@example.com"],
    "subject": "Payroll Update",
    "domain_age_days": 120,
    "spam_score": 0.12,
    "has_macro": false,
    "links": ["http://..."],
    "dkim_pass": true,
    "spf_pass": true,
    "dmarc_pass": true,
    "forward_rule_added": false
  },
  "iam": {
    "change_type": "role_grant|role_revoke|policy_attach|password_reset|mfa_disable",
    "target_principal": "user:bob",
    "roles_after": ["Admin","Billing"],
    "roles_before": ["Billing"],
    "privilege_delta_count": 12,
    "credential_age_days": 190,
    "mfa_state_change": "none|disabled|enabled"
  },
  "sequence": {                        // for chain linkage
    "prev_event_ids": ["uuid1","uuid2"],
    "session_id": "sess-abc",        // correlation window / HopGraph anchor
    "phase": "Execution|Exfiltration|Impact",
    "phase_order": 6
  },
  "metrics": {                         // numeric features for ML / embeddings
    "byte_out": 1048576,
    "byte_in": 2048,
    "entropy": 6.1,
    "anomaly_score": 0.83
  },
  "embedding_ref": "vec:event:uuid",  // pgvector row key (deferred)
  "tags": ["cloud:privilege_drift","iam:privilege_chain_escalation"],
  "confidence": 0.0                    // factor risk composition (post-process)
}
```

## Minimal Column Set (Relational Projection)
Recommended Postgres table `events` (partitioned by day & tenant):
```
tenant_id TEXT,
event_id UUID PRIMARY KEY,
ts TIMESTAMPTZ,
domain TEXT,
ingest_source TEXT,
actor_principal TEXT,
kill_chain_phase TEXT,
phase_order SMALLINT,
confidence REAL,
raw JSONB,
network JSONB,
object JSONB,
api JSONB,
cloud JSONB,
email JSONB,
iam JSONB,
metrics JSONB,
sequence JSONB,
factors TEXT[],
tags TEXT[],
embedding_ref TEXT
```
Indexes:
- `idx_events_tenant_ts` (tenant_id, ts)
- `idx_events_principal_ts` (actor_principal, ts DESC)
- GIN on factors/tags JSONB arrays.
- Partial index for high-risk: `WHERE confidence > 0.8`.

## Retention & Horizon
- Raw events retained 120 days (cold storage after 30).  
- Factor-only summarized rows in `events_summary` for >120 days chain continuity.

## Probe Fingerprint Store (Recon)
Table `recon_probes` capturing distinct (src_ip, asn, ports_scanned[], first_seen, last_seen, probe_count) with 180-day retention.

## Embedding Strategy
Two vectors per event:
- `event_semantic_vector`: embedding of concatenated normalized fields (principal, domain, change_type, path, subject).
- `factor_context_vector`: aggregated embedding of joined factor descriptions.

Stored via pgvector columns:
```
ALTER TABLE events ADD COLUMN event_semantic_vector vector(768);
ALTER TABLE events ADD COLUMN factor_context_vector vector(512);
```

## Streaming & Ordering
- Collectors append raw event → normalization → enqueue for enrichment → factor tagging → embedding generation (async) → final persistence (update confidence & vectors).

## Change Control
Version stamping via `events_meta` table (schema_version INT, applied_at TIMESTAMPTZ, notes TEXT). Current version: 1.

## Future Extensions
- Add `graph_snapshot_refs` linking to Neo4j path exports.
- Add `slo_violation` boolean for compliance overlays.
- Add `retention_policy` field per event (default, extended, legal_hold).
