# WebhookGuardMiddleware Instrumentation & Fallback Removal

Goal: Keep logic strictly in middleware; remove in-route fallback once dispatch is verified across TestClient and live server.

## Plan
- Add lightweight instrumentation to `WebhookGuardMiddleware` dispatch (path, vendor, decision branch).
- Re-run focused webhook tests with middleware-only.
- Confirm replay detection determinism; remove in-route fallback guard from `integrations_endpoints.py`.

## Acceptance Criteria
- `tests/test_webhook_guard.py` passes with middleware-only (no fallback).
- Audit entries created for missing headers, stale timestamp, bad signature, oversized payload, and replay.
- No regressions in `/api/v1/webhooks/{vendor}` routes.

## Notes
- Use `app.state` and process-global cache for test determinism.
- Keep audit logging best-effort (`src/audit/logger.py`).
- Coordinate with LIVE console routes per AGENTS.md (ensure headers `x-api-key`).
