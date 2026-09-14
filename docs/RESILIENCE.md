# Resilience Patterns (Stubs and Guidance)

This document outlines initial hooks and guidance for introducing circuit breakers, bulkheads, and an outbox/exactly-once pattern.

## Circuit Breakers

- Env flags:
  - CB_ENABLED, CB_SLACK_ENABLED, CB_ECLIPSE_ENABLED
  - CB_FAIL_THRESHOLD (default 3)
  - CB_RESET_SECONDS (default 30)
  - CB_HALF_OPEN_TRIALS (default 1)
- Current implementation:
  - Simple in-memory counters in dispatcher gate Slack/Eclipse calls when open
  - Open on consecutive failures; closes after reset window
  - Half-open trials not yet enforced (stub only)
- Next steps:
  - Move counters to a shared store if running multi-process
  - Add per-tenant/per-connector breakers
  - Implement half-open trial logic

## Bulkheads

- Recommendation: separate worker pools per sink (Slack/Eclipse)
- Token bucket per connector already provides coarse isolation
- Future: dedicated asyncio TaskGroups or process pools for isolation under load

## Outbox (Exactly-once-ish)

- Stub module: `core/outbox.py`
- Idea: Persist dispatch intents to a durable outbox before attempting delivery
- On success: mark done; on failure: retry via a background worker
- Storage: SQLite (`wal` mode) or Postgres
- Schema sketch:
  - outbox(id, tenant_id, connector, payload_json, created_at, attempts, last_error)
- Adapter hook:
  - Replace stub with DB-backed implementation and wire in dispatcher before/after sink calls

## Testing

- Start with unit tests using induced failures to ensure breakers open and recover
- Ensure retries back off and outbox does not drop messages without marking done
