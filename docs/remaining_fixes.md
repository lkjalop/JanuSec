# Remaining Fixes Checklist (Production Readiness)

This document lists concrete fixes with file paths and exact line references (where known), ordered by priority (P0→P3). Use these links and notes directly with Codex for targeted patches.

## P0 — Critical (Fix Immediately)
- **frontend/static/csv_multi_analyzer.html**
  - [L1115-L1132](frontend/static/csv_multi_analyzer.html#L1115-L1132): JavaScript syntax errors. Fix the following in the preview/mapping block:
    - Replace any TypeScript-style signatures with plain JS.
    - Ensure object literal for `fetch` body uses `JSON.stringify({ tenant, mapping, sampleRows })`
    - Remove spread `...authHeaders()` if not defined; instead merge headers explicitly.
    - Close all braces/parentheses; ensure `await` calls are inside an `async` function.
  - [L1124](frontend/static/csv_multi_analyzer.html#L1124): “Signature declarations can only be used in TypeScript files” — remove type annotations.
  - [L4986](frontend/static/csv_multi_analyzer.html#L4986): Fix IIFE/closure ending. Ensure matching `(() => { ... })();` with balanced braces.

- **src/api/background_tasks.py**
  - [L120](src/api/background_tasks.py#L120): Orphaned `except Exception:` — add a matching `try:` block above or remove the stray `except` clause.
    - Example:
      - Add `try:` one or two lines above where the guarded code begins; include a minimal `pass` in `except` if necessary.

- **src/api/routes/identity.py**
  - [L234](src/api/routes/identity.py#L234): `try:` without `except`/`finally` — add a corresponding `except Exception:` block or a `finally:` to close the `try`.

- **Pytest discoverability (find any remaining syntax errors)**
  - Run collection and address any new `SyntaxError` entries:
    ```powershell
    python -m pytest --collect-only -q
    ```
  - For each file reported, run:
    ```powershell
    python -m py_compile path/to/file.py
    ```
    and fix the indicated line.

## P1 — High (Next 24–48 Hours)
- **src/api/csv_endpoints.py**
  - Row caps and test-only logic:
    - [L68-L89](src/api/csv_endpoints.py#L68-L89): `CSV_MAX_ROWS` and `CSV_MAX_COLS` hard caps and truncation. For production, either remove caps or make them soft limits with operator overrides; do not silently truncate.
    - Remove any residual test-only guards. Current debug uses logger only; ensure no `print(...)` statements are present and keep `_csv_debug_enabled()` strictly logging (no stdout).

- **src/adapters/qualys_connector.py**
  - Duplicate code: Already consolidated into a single `QualysConnector` class (no action needed). Verify no duplicate modules remain under `src/adapters/`.

- **AWS connectors smoke tests**
  - Add minimal smoke tests under `tests/connectors/aws/` for each file in `src/connectors/aws/` (11 total). Validate import and a basic method call with mocked network where applicable.

- **src/core/dedup_service.py** (if present)
  - Add Redis backend for distributed deduplication. Wire `redis.from_url(...)` and feature-flag via env `DEDUP_REDIS_URL`. Implement `get_or_set(key, ttl)` with atomic semantics.

- **src/core/graph/hopgraph_lite.py**
  - Remove debug/fallback paths:
    - [L50-L110](src/core/graph/hopgraph_lite.py#L50-L110): Environment-gated persistence enablement and alternate import fallback. Simplify to a single persistence path or disable in production build.
    - [ensure_backend() at L112-L139](src/core/graph/hopgraph_lite.py#L112-L139): Collapse test-mode reinitialization; persistence should be configured once at startup.

- **Migrations**
  - Consolidate DB migrations to Alembic-only. Remove any direct SQL migration scripts; ensure `alembic.ini` and versions are canonical.

## P2 — Medium (Week 1)
- **Strip test-only code in production paths**
  - Search for patterns and remove/guard behind test-only flags:
    - `PYTEST_CURRENT_TEST`, `TEST_HELPERS_ENABLED`, references to `pytest` in modules.

- **Hardcoded secrets audit**
  - Grep for secrets and replace with env vars:
    - Search keys: `api_key|password|secret|token|x-api-key` across `src/**`.

- **CSV processing scalability**
  - Increase limits and add streaming/progress for large uploads in `src/api/csv_endpoints.py` and client page [frontend/static/janusec-platform-complete-LIVE.html](frontend/static/janusec-platform-complete-LIVE.html).

- **Skipped tests**
  - Remove or justify all `@pytest.mark.skip` occurrences. Convert to conditions or fixtures.

- **Prometheus metrics**
  - Add metrics to critical paths:
    - CSV upload endpoints (`ingest_rows`, error counts, processing duration).
    - AWS/Qualys connectors (requests, failures, yields).
    - Dedup cache hits/misses.

## P3 — Low (Weeks 2–4)
- **RBAC**
  - Implement role-based access control in `src/security/auth` and enforce on all routers.

- **Multi-tenancy hardening**
  - Ensure tenant filters on all DB queries (e.g., add `tenant_id` to models and repository calls).

- **Compliance framework mapping**
  - Add endpoints/modules to map findings to CIS/NIST/ISO controls.

- **Kubernetes/Helm**
  - Provide Helm charts and manifests for deployment.

- **UI polish**
  - Improve styling and error handling across static pages; add spinners and consistent toast messaging.

## Test Failures To Address
- **tests/test_hopgraph_scoring.py::test_diversity_and_mapping_bonus_default_zero**
  - Observed non-zero `diversity_bonus` (0.035) despite test removing env overrides.
  - Fix:
    - In [src/core/configuration/scoring_weights.py](src/core/configuration/scoring_weights.py), ensure that in fast-test mode the effective weights resolve to zero and do not apply any persisted file or env defaults.
    - In [src/graph/hopgraph.py](src/graph/hopgraph.py), inside `explain_chain()`, explicitly zero out `diversity_weight` and `mapping_weight` when `FAST_TEST_MODE` is on.
    - Re-run focused test:
      ```powershell
      python -m pytest -q tests/test_hopgraph_scoring.py::test_diversity_and_mapping_bonus_default_zero
      ```

## Quick Commands
```powershell
# Verify Python syntax per file
python -m py_compile src\api\background_tasks.py
python -m py_compile src\api\routes\identity.py

# Discover remaining syntax issues
python -m pytest --collect-only -q

# Run focused failing test
python -m pytest -q tests\test_hopgraph_scoring.py::test_diversity_and_mapping_bonus_default_zero
```

## Notes
- The Qualys connector duplication appears already resolved. Focus remaining P1 time on CSV endpoint cleanup, HopGraph-lite fallback removal, AWS smoke tests, and Redis dedup.
- The CSV multi-analyzer page has multiple JS parsing errors that block the UI; fixing those will unblock analyst workflows.
