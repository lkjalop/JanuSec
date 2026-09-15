CI Test Guidance
----------------

To keep pytest collection fast and deterministic in CI, set the following environment variables for test runs:

- `FAST_TEST_MODE=1` or `PLATFORM_LITE_INIT=1` — enables lightweight initialization and disables background recompute threads.
- `SKIP_ISMS_SCAN=1` — skip heavy ISMS scans during import.
- `DB_DISABLE_NETWORK_CONNECT=1` or `DISABLE_DB=1` — prevent attempts to connect to a network Postgres instance and force sqlite fallback.
- `LOG_LEVEL=WARNING` — reduce noisy INFO logs (e.g., route inclusion messages).

Recommended pytest invocation in CI (Windows CMD example):

```powershell
set FAST_TEST_MODE=1
set SKIP_ISMS_SCAN=1
set DB_DISABLE_NETWORK_CONNECT=1
set LOG_LEVEL=WARNING
python -m pytest -q
```

Notes:
- The codebase includes a `create_app(config)` factory; tests should avoid importing `app` at module scope. Use the `test_app` fixture provided in `tests/conftest.py` or call `create_app({'mode':'test'})` in fixtures.
- We suppress route-audit and Included-router INFO logs during `FAST_TEST_MODE` to keep CI logs concise.
- If your CI needs to run integration tests against real dependencies (Postgres, Redis, HopGraph), unset `DB_DISABLE_NETWORK_CONNECT` and provide appropriate service endpoints.

If you want, I can add a small CI job snippet for GitHub Actions or Azure Pipelines that sets these environment variables. 
