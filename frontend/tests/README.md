Playwright tests for Integrations UI

Prereqs:
- Node.js (14+)
- npx and Playwright installed. Install with:
  - `npm install -D @playwright/test`
  - `npx playwright install`
- The local server serving static files must be running (default http://localhost:8080). Use `scripts/start_test_server.ps1` or the demo-up task.

Run tests:
- From repository root (after installing Playwright):
  - `npx playwright test frontend/tests/integrations.spec.js --project=chromium`

CI notes:
- Ensure the server is started (Start Test Server task) before running Playwright tests.
- The tests set `localStorage.apiKey = 'devkey123'` by default for demo mode.

Troubleshooting:
- If pages fail to load, confirm the API server is listening on port 8080 and static files are served under `/static`.
- Use `npx playwright show-trace` for failing runs to inspect.
