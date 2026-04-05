# Multi-Tenant Implementation Notes

Phase 1 (current):
- Added nullable `tenant_id` TEXT columns to core tables via `0007_multi_tenant.sql`.
- Backward compatibility: existing rows keep NULL `tenant_id`; queries treat `(tenant_id = $X OR (tenant_id IS NULL AND $X IS NULL))` allowing legacy/global scope.
- Event IDs assumed globally unique across tenants for now (simplifies conflict handling). Future phase can migrate to composite PK `(tenant_id, id)` if per-tenant id collisions need isolation.
- Repository functions accept a `tenant_id` parameter; inserts pass it through, updates preserve existing tenant when absent.
- Access logging and factor weights now optionally scoped by tenant.

Phase 2 (future ideas):
- Enforce NOT NULL `tenant_id` for all new rows after cut-over date.
- Background job to backfill NULL -> 'default'.
- Introduce tenant quotas & rate limiting keyed by `tenant_id`.
- Per-tenant encryption keys for at-rest sensitive payload segments.
- Tenant-aware caching layer partitioning (Decision cache currently global, could shard).

Security Considerations:
- Sanitize tenant identifier (length + allowed charset) to mitigate log injection / SQL edge cases.
- Avoid reflecting raw tenant value in error responses where possible.

Operational:
- Add metric labels (`tenant_id`) only if cardinality manageable; otherwise sample or aggregate.
- For pgvector similarity search, index can be partitioned by tenant in future (separate table or include tenant in ANN index) if data volume grows.

Migration Safety:
- All `ALTER TABLE ADD COLUMN IF NOT EXISTS` operations are additive, safe for multiple applies.
- Index creation likewise idempotent.

Rollback:
- Columns can remain (no destructive rollback necessary). To revert behavior, ignore tenant parameters in repositories.
