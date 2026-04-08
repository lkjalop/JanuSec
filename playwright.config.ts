import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: 'tests/playwright',
  timeout: 60_000,
  expect: { timeout: 5000 },
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    headless: true,
    viewport: { width: 1280, height: 800 },
    actionTimeout: 30_000,
    // Default to the demo app server port (uvicorn) used by the webServer block
    baseURL: process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:8080',
    trace: 'on-first-retry'
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } }
  ],
  // Only start the demo app server when PLAYWRIGHT_BASE_URL is not provided.
  // This lets CI or local runs point tests at a deterministic static shim.
  ...(process.env.PLAYWRIGHT_BASE_URL ? {} : {
    webServer: {
      command: 'python -m uvicorn src.api.app:app --host 0.0.0.0 --port 8080',
      port: 8080,
      timeout: 120_000,
      reuseExistingServer: !process.env.CI,
      env: {
        DEFAULT_FRONTEND: 'console',
        TEST_HELPERS_ENABLED: '0',
        FAST_TEST_MODE: '0',
        PLATFORM_LITE_INIT: '0',
        // Use 'dev' so TenantMiddleware falls back to DEFAULT_TENANT instead of 400ing
        ENV: 'dev',
        APP_ENV: 'dev',
        DEFAULT_TENANT: 'default',
        ALLOW_DEFAULT_TENANT: '1',
        TENANT_RATE_LIMIT_ENABLED: '0',
        RATE_LIMIT_ENABLED: '0',
        API_KEYS_JSON: '[{"key":"janusec-playwright-local","scopes":["*"]}]',
        PLAYWRIGHT_API_KEY: 'janusec-playwright-local',
        LLM_MOCK: '1',
        DISABLE_DB: '0',
        HOPGRAPH_PERSISTENCE_ENABLED: '0',
      }
    }
  })
});
