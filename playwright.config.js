// Minimal Playwright config for local runs
/** @type {import('@playwright/test').PlaywrightTestConfig} */
module.exports = {
  timeout: 60 * 1000,
  retries: process.env.CI ? 2 : 1,
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:8080',
    actionTimeout: 8 * 1000,
    navigationTimeout: 15 * 1000,
    headless: true,
    storageState: 'tests/playwright/storageState.json',
  },
  testDir: 'tests/playwright',
  globalSetup: require.resolve('./tests/playwright/global-setup.js'),
  webServer: process.env.PLAYWRIGHT_BASE_URL ? undefined : {
    command: 'python -m uvicorn src.api.app:app --host 0.0.0.0 --port 8080',
    port: 8080,
    timeout: 120_000,
    reuseExistingServer: !process.env.CI,
    env: {
      DEFAULT_FRONTEND: 'console',
      TEST_HELPERS_ENABLED: '0',
      FAST_TEST_MODE: '0',
      PLATFORM_LITE_INIT: '0',
      ENV: 'staging',
      API_KEYS_JSON: '[{"key":"janusec-playwright-local","scopes":["*"]}]'
    }
  }
};
