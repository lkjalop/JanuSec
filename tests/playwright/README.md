Playwright storageState and test-mode

This repository uses a global setup that writes a Playwright `storageState` file
(`tests/playwright/storageState.json`) to ensure `localStorage` entries used by
frontend pages (notably `testMode` and `apiKey`) are pre-populated for test
contexts.

Why we do this
- localStorage is origin-scoped (scheme+host+port). Tests may target
  `127.0.0.1` or `localhost`, and writing a single origin during global setup
  can lead to missing flags and flaky tests.
- Global-setup writes storage state for both `127.0.0.1` and `localhost` and the
  Playwright config uses this file via `use.storageState` so tests inherit the
  deterministic flags.

How to regenerate the storage state
1. Start the dev server (see `scripts/start_test_server.ps1`).
2. Run the global setup script manually with Node (this will write storageState):

```powershell
node tests/playwright/global-setup.js
```

3. Confirm `tests/playwright/storageState.json` exists and contains `localStorage`
   entries (e.g., `testMode` and `apiKey`).

Notes
- If you change the base URL (via `PLAYWRIGHT_BASE_URL`) re-run the global-setup
  to ensure storageState contains entries for the new origin.
- If you need to add extra localStorage keys for debugging locally, update
  `tests/playwright/global-setup.js`.
