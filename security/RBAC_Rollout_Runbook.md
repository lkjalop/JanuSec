# RBAC Rollout Runbook

This runbook describes how to roll out, verify, and (if necessary) back out scope/role-based access controls.

## Prereqs
- Environment variables configured:
  - ADMIN_UI_TOKEN (for admin-token path; rotate if compromised)
  - API_KEYS_JSON (JSON array with key+scopes)
  - JWT_SECRET or OIDC (OIDC_ISSUER, OIDC_CLIENT_ID) for JWT or SSO
  - Optional: JWT_TEST_SECRET for CI-internal tests only
- CI executes auth smoke tests (tests/test_auth_smoke.py)

## Rollout steps
1. Enable scopes for sensitive endpoints
   - Verify endpoints in security/api_endpoint_allowlist.csv enforce require_scopes() or admin check.
2. Deploy with audit logging enabled (default)
   - Audit JSONL path: audits/audit_events.jsonl
   - Confirm events for model_promote, model_alias_set, label_written, calibration_* are logged.
3. Shadow check: Review audit and metrics for 24–48h
   - Look for 401/403 spikes in logs and dashboard.
4. Gradual enforcement
   - If any endpoint was permissive, enable strict scopes and re-run smoke.

## Backout
- If legitimate traffic is blocked:
  - Temporarily relax the specific endpoint to viewer scope (read) or restore previous allowlist for that endpoint.
  - Redeploy and monitor metrics.

## Rotation guidance
- ADMIN_UI_TOKEN: rotate every 90 days or on suspicion; deploy via secret manager.
- API keys: rotate quarterly; use least-privilege scopes per key.
- JWT/OIDC: prefer OIDC; rotate signing keys via IdP policy; do not use JWT_TEST_SECRET outside CI.

## Auditing & forensics
- Primary trail: audits/audit_events.jsonl (JSONL). Use tools/audit_summary.py to summarize.
- Complementary logs: server stdout/stderr.

## Smoke checks
- Promote and alias model via admin-token path.
- Label write via API key with feedback.write scope.
- Verify 401/403 for missing/insufficient scope on the same endpoints.

## Contacts
- Security engineering oncall
- SRE oncall
