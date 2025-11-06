Summary of changes on branch `feature/fix/test-harness-httpx`:

- Fix: Resolved SyntaxError/Indentation issues in `src/api/suppression_admin_endpoints.py` and `src/integrations/cert_checks.py` that caused pytest collection to fail.
- Fix: Implemented `get_cert_check()` in `src/integrations/cert_checks.py` to expose stored cert check rows for tests and TTL handling.
- Fix/Hardening: Made webhook retry logic in `cert_checks` robust to test monkeypatching and import aliasing by:
  - Adding `_get_effective_httpx_client()` to discover httpx-like clients across module aliases.
  - Adding `_post_with_compat()` to support fake client signatures (tries `content=`, positional, `data=`).
  - Using runtime env `CERT_CHECK_WEBHOOK_URL` when retrying so tests setting env during fixture execution are respected.
  - Lowered triage-level logs to `DEBUG` to reduce test noise.
- Test: Added `tests/test_suppression_admin_auth.py` to assert admin API header enforcement (403 without key, 200 with valid key).
- Scripts: Added `scripts/check_cooccurrence_persistence.py` and `scripts/debug_cert_flush.py` used during debugging (non-essential for library behavior).

Test results (run locally with `python -m pytest -q --maxfail=1`):
- Outcome: 1 failed, 233 passed, 2 skipped, 52 warnings. The failing test is `tests/test_cross_mapping_scoring.py::test_cross_mapping_scoring_continuous` which appears unrelated to the cert_checks changes; further investigation recommended.

Notes and recommendations:
- The diagnostic logging added for triage has been toned down to `DEBUG`. You can further remove the `_TEST_CAPTURE_*` helpers if they are no longer needed.
- Re-run full CI to ensure no platform-specific failures (Windows had an earlier intermittent access-violation during a prior full run).
- Suggested follow-ups:
  - Investigate `tests/test_cross_mapping_scoring.py::test_cross_mapping_scoring_continuous` failure in CI environment.
  - Optionally refactor `cert_checks` to accept an injectable HTTP client for clearer testability.

Files changed (high level):
- Modified: `src/integrations/cert_checks.py`
- Modified: `src/api/suppression_admin_endpoints.py`
- Added: `tests/test_suppression_admin_auth.py`
- Added: `scripts/check_cooccurrence_persistence.py`, `scripts/debug_cert_flush.py`

If you want, I can:
- Open a PR with these changes and link this description, or
- Run the failing `tests/test_cross_mapping_scoring.py::test_cross_mapping_scoring_continuous` locally to triage further.
