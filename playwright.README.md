Playwright test guidance and stable test shim

Overview
--------
This repository includes a small, deterministic test shim for the CSV Analyzer used by Playwright tests. The shim helps stabilize E2E tests by providing a minimal, well-documented UI surface that is deterministic and independent from the live UI.

When to use the shim
- Use the shim for CI or when you want deterministic, fast E2E runs that don't depend on external integrations or evolving frontend code.
- Opt in by setting the environment variable: `PLAYWRIGHT_USE_TEST_SHIM=1`.

How to run
- Start the API server locally (recommended with diagnostics during debugging):

```powershell
$env:DEBUG_DIAGNOSTICS='1'
python -m uvicorn src.api.app:app --host 127.0.0.1 --port 8080
```

- Run Playwright tests using the shim (headed/traces optional):

```powershell
$env:PLAYWRIGHT_USE_TEST_SHIM='1'
$env:PLAYWRIGHT_BASE_URL='http://127.0.0.1:8080'
npx playwright test -g csv --trace on
```

Recommended CI settings
- Set `PLAYWRIGHT_BASE_URL` to the API server under test (recommended: `http://127.0.0.1:8080`) to avoid accidental fallbacks.
- Use the shim in CI for the CSV group to reduce flakiness:
  - Add `PLAYWRIGHT_USE_TEST_SHIM=1` to the job env.
  - Run `npx playwright test -g csv --reporter=html --trace on` and upload traces/artifacts for failing runs.

Running tests against the real UI
- To exercise the real UI, run tests without `PLAYWRIGHT_USE_TEST_SHIM` or create a separate Playwright profile that targets the canonical frontend. We recommend doing this in a nightly/acceptance pipeline rather than every PR to avoid flakiness.

Files
- `frontend/static/test_shims/csv_analyzer_shim.html` — deterministic test shim used by Playwright when opted-in.
- `tests/playwright/helpers/csv_helpers.js` — includes `gotoCsvAnalyzer(page)` which prefers the shim when `PLAYWRIGHT_USE_TEST_SHIM` is set.

Notes
- The shim is intentionally minimal. If you need more realistic data, extend the shim or add a non-deterministic integration test that runs against the canonical UI.
Playwright UI tests

Quick steps to run the Playwright UI specs included in `tests/playwright/`:

1. Install dev dependencies:

   npm install

2. Install Playwright browsers (required once):

   npx playwright install

3. Run the UI tests:

   npm run test:ui

If you prefer to run tests headed (with a visible browser):

   npm run test:ui:headed

VS Code: use the task "Playwright: Run UI tests" from the Command Palette -> Tasks: Run Task.

SheetJS local vendor helper
---------------------------
If your environment blocks CDNs or you want to run client-side `.xlsx` parsing offline, run the helper:

```powershell
./scripts/fetch_sheetjs.ps1
```

This will copy `node_modules\xlsx\dist\xlsx.full.min.js` into `frontend/static/vendor/` if present, or download a CDN copy. Alternatively, run the server parse path from `/static/csv_analyzer.html` (click "Upload (Server Parse)") after ensuring Python dependency `openpyxl` is installed in the server environment.

CSV / Tracing / Debugging notes
-------------------------------

- For CSV-specific smoke/debug runs, start the API with diagnostics enabled:

```powershell
$env:DEBUG_DIAGNOSTICS='1'
python -m uvicorn src.api.app:app --port 8080
```

- Run only CSV-tagged tests and collect Playwright traces:

```powershell
npx playwright test -g csv --trace on
```

- After a failing test, fetch server diagnostics to correlate stack traces:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8080/api/v1/debug/last-errors
```

- Use `tests/playwright/helpers/network_helpers.js` to centralize mocked upload/pipeline responses in tests.
