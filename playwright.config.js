// Minimal Playwright config for local runs
/** @type {import('@playwright/test').PlaywrightTestConfig} */
module.exports = {
  timeout: 60 * 1000,
  retries: process.env.CI ? 2 : 1,
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:8080',
    actionTimeout: 8 * 1000,
    navigationTimeout: 15 * 1000,
    headless: true,
    storageState: 'tests/playwright/storageState.json',
  },
  testDir: 'tests/playwright',
  globalSetup: require.resolve('./tests/playwright/global-setup.js'),
  webServer: process.env.PLAYWRIGHT_BASE_URL ? undefined : {
    command: 'cmd /c "set DEBUG_DIAGNOSTICS=1&& set JANUSEC_DEV_MODE=1&& set JANUSEC_INGEST_DB=data\\ingest\\pw_santos_webserver.duckdb&& set JANUSEC_DISABLE_T1_PREFILL=1&& set JANUSEC_ASYNC_LEGACY_HYDRATE=0&& C:\\AI\\janusec\\.venv\\Scripts\\python.exe -m uvicorn src.api.server:app --host 0.0.0.0 --port 8080"',
    port: 8080,
    timeout: 120_000,
    reuseExistingServer: !process.env.CI,
    env: {
      DEFAULT_FRONTEND: 'console',
      TEST_HELPERS_ENABLED: '0',
      FAST_TEST_MODE: '0',
      PLATFORM_LITE_INIT: '0',
      JANUSEC_INGEST_DB: 'data/ingest/pw_santos_webserver.duckdb',
      JANUSEC_DISABLE_T1_PREFILL: '1',
      JANUSEC_ASYNC_LEGACY_HYDRATE: '0',
      DEBUG_DIAGNOSTICS: '1',
      JANUSEC_DEV_MODE: '1',
      ENV: 'staging',
      API_KEYS_JSON: '[{"key":"janusec-playwright-local","scopes":["*"]}]'
    }
  }
};
