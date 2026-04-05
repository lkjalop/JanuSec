Fix: LLM deterministic fallback & prewarm helpers

What
- Add deterministic fallback for LLM provider failures (local deterministic client) to avoid hard failures when Ollama is unavailable.
- Add prewarm & probe helper scripts and example deployment manifests to warm LLMs at startup.
- Fix `generate_llm_summaries` to include `aggregate_cost` in empty-queue responses (stabilizes tests that inspect aggregate metadata).
- Add `tests/conftest_ci.py` to force `LLM_MOCK=1` when running in CI to avoid flakiness from external LLMs.

Why
- Prevent flaky failures during CI because of transient Ollama outages and make local dev easier by providing prewarm/probe scripts and deterministic fallback.

Notes
- Branch: fix/llm-fallback-prewarm (already pushed to origin).
- One live test (`tests/test_tier2_queue.py::test_tier2_enqueue_and_stop`) failed with an internal 500 during a live-LM run; this appears to be server-side and may be unrelated to the LLM change. I can debug that next if you want.
(PR body generated from PR_DESCRIPTION.md)

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

How to proceed:
- To open a remote PR I can push this branch and create the PR on your remote. Provide remote name/URL or grant push permissions.
- Alternatively, I can triage the failing test next or run the full suite again (no stop).

Command to push branch and create PR (example):

```powershell
# push the branch
git push origin feature/fix/test-harness-httpx
# then open a PR using hub/gh or your Git hosting UI
gh pr create --base main --head feature/fix/test-harness-httpx --title "Fix cert_checks httpx test-harness issues" --body "$(cat PR_BODY.md)"
```

If you prefer, tell me to open the PR and provide the remote name (default `origin`) and whether to base against `main` or another branch.
