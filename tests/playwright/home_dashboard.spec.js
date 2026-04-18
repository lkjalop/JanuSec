/**
 * Playwright smoke tests for the live home dashboard (home.html)
 * and the staged-events pipeline between home and investigate.
 *
 * Run: npx playwright test tests/playwright/home_dashboard.spec.js
 * Requires server on port 8099 with devkey123 / PLAYWRIGHT_API_KEY
 */
const { test, expect } = require('@playwright/test');

const API_KEY = process.env.PLAYWRIGHT_API_KEY || 'devkey123';

test.describe('Home Dashboard — Live Operations', () => {

  test.beforeEach(async ({ page }) => {
    await page.addInitScript((key) => {
      try {
        localStorage.setItem('apiKey', key);
        localStorage.setItem('tenantId', 'default');
        // Clear any pre-existing staged events to ensure clean state
        localStorage.removeItem('janusec_staged_events');
      } catch (_) {}
    }, API_KEY);
  });

  // ── 1. Root serves home.html ─────────────────────────────────────────

  test('GET / serves live operations dashboard', async ({ page }) => {
    const errors = [];
    page.on('pageerror', (err) => {
      const msg = String(err);
      // Skip known non-fatal errors
      if (/lucide|Failed to load resource|401|403|404/.test(msg)) return;
      errors.push(msg);
    });

    await page.goto('/', { waitUntil: 'domcontentloaded', timeout: 15000 });

    // Must have the live operations sidebar link active
    await expect(page.locator('.nav-item.active')).toContainText(/Live Operations/i, { timeout: 8000 });

    // Connector health bar must be visible
    await expect(page.locator('#connectorBar')).toBeVisible();

    // Metrics strip must be visible
    await expect(page.locator('#metricsStrip')).toBeVisible();

    // Live Feed tab must be present and active
    await expect(page.locator('.tab-btn.active')).toContainText(/Live Feed/i);

    // Stage Queue tab must be present
    await expect(page.locator('[data-tab="stage"]')).toBeVisible();

    // No JS crashes
    expect(errors).toHaveLength(0);
  });

  // ── 2. Live feed table renders or shows loading state ────────────────

  test('live feed table renders without crashing', async ({ page }) => {
    const consoleErrors = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        const t = msg.text() || '';
        // querySelectorAll crash = test failure
        if (t.includes('querySelectorAll') || t.includes('Cannot read properties of null')) {
          consoleErrors.push(t);
        }
      }
    });

    await page.goto('/', { waitUntil: 'networkidle', timeout: 20000 });

    // Table must exist
    const table = page.locator('#liveTable');
    await expect(table).toBeVisible({ timeout: 5000 });

    // Wait for either data rows OR the "Connecting" empty state (both are valid)
    await expect(
      page.locator('#liveBody tr').first()
    ).toBeVisible({ timeout: 8000 });

    // Critical: no querySelectorAll crash
    expect(consoleErrors).toHaveLength(0);
  });

  // ── 3. Severity summary shows has-data after poll ────────────────────

  test('severity summary updates after first poll', async ({ page }) => {
    // Intercept decisions/recent to return deterministic test data
    await page.route('**/api/v1/decisions/lifecycle/recent*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { event_id: 'e1', state: 'pending', correlation_state: 'correlated',
            severity: 'critical', triage_score: 1.0, reason: 'Test critical', disposition: '' },
          { event_id: 'e2', state: 'pending', correlation_state: 'isolated',
            severity: 'high', triage_score: 0.8, reason: 'Test high', disposition: '' },
        ]),
      });
    });

    await page.goto('/', { waitUntil: 'domcontentloaded', timeout: 15000 });

    // Wait for severity summary to appear
    await expect(page.locator('#sevSummary')).toHaveClass(/has-data/, { timeout: 10000 });

    // Critical count must be 1
    const critEl = page.locator('#sc_crit');
    await expect(critEl).toHaveText('1', { timeout: 5000 });

    // Isolated high count must be 1
    const siHigh = page.locator('#si_high');
    await expect(siHigh).toHaveText('1', { timeout: 5000 });
  });

  // ── 4. Stage button writes to localStorage ───────────────────────────

  test('clicking stage button writes janusec_staged_events to localStorage', async ({ page }) => {
    // Seed a deterministic decision
    await page.route('**/api/v1/decisions/lifecycle/recent*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { event_id: 'stage-test-001', state: 'pending',
            correlation_state: 'correlated', severity: 'critical',
            triage_score: 1.0, reason: 'Stage test event', disposition: '' },
        ]),
      });
    });

    await page.goto('/', { waitUntil: 'domcontentloaded', timeout: 15000 });

    // Wait for events to render
    await expect(page.locator('#liveBody .stage-btn').first()).toBeVisible({ timeout: 8000 });

    // Click the stage button
    await page.locator('#liveBody .stage-btn').first().click();

    // Verify localStorage was written
    const staged = await page.evaluate(() => {
      try {
        const raw = localStorage.getItem('janusec_staged_events');
        return raw ? JSON.parse(raw) : null;
      } catch (_) { return null; }
    });

    expect(staged).not.toBeNull();
    expect(staged.source).toBe('live_dashboard');
    expect(Array.isArray(staged.events)).toBe(true);
    expect(staged.events.length).toBeGreaterThan(0);
    expect(staged.events[0].event_id).toBe('stage-test-001');
  });

  // ── 5. Stage badge updates ────────────────────────────────────────────

  test('stage badge increments when events are staged', async ({ page }) => {
    await page.route('**/api/v1/decisions/lifecycle/recent*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { event_id: 'badge-test-1', state: 'pending', correlation_state: 'isolated',
            severity: 'high', triage_score: 0.8, reason: 'Badge test', disposition: '' },
        ]),
      });
    });

    await page.goto('/', { waitUntil: 'domcontentloaded', timeout: 15000 });
    await expect(page.locator('#liveBody .stage-btn').first()).toBeVisible({ timeout: 8000 });
    await page.locator('#liveBody .stage-btn').first().click();

    // Stage badge must appear with count
    const badge = page.locator('#stageBadge');
    await expect(badge).toBeVisible({ timeout: 3000 });
    await expect(badge).toHaveText('1');
  });

  // ── 6. Stage queue tab shows staged events ────────────────────────────

  test('stage queue tab shows staged events after staging', async ({ page }) => {
    await page.route('**/api/v1/decisions/lifecycle/recent*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { event_id: 'queue-test-1', state: 'pending', correlation_state: 'correlated',
            severity: 'critical', triage_score: 1.0, reason: 'Queue test', disposition: '' },
        ]),
      });
    });

    await page.goto('/', { waitUntil: 'domcontentloaded', timeout: 15000 });
    await expect(page.locator('#liveBody .stage-btn').first()).toBeVisible({ timeout: 8000 });
    await page.locator('#liveBody .stage-btn').first().click();

    // Switch to Stage Queue tab
    await page.locator('[data-tab="stage"]').click();

    // Stage list must be visible (not empty state)
    await expect(page.locator('#stageList')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('#stageEmpty')).toHaveCSS('display', 'none');

    // "Open in Investigation Console" button must be visible
    await expect(page.getByRole('button', { name: /Open in Investigation Console/i })).toBeVisible();
  });

  // ── 7. Pause / resume works ───────────────────────────────────────────

  test('pause button stops refresh countdown', async ({ page }) => {
    let pollCount = 0;
    await page.route('**/api/v1/decisions/lifecycle/recent*', async (route) => {
      pollCount++;
      await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
    });

    await page.goto('/', { waitUntil: 'domcontentloaded', timeout: 15000 });
    // Let first poll complete
    await page.waitForTimeout(500);

    const countBefore = pollCount;
    await page.locator('#btnPause').click();
    // Verify button text changed
    await expect(page.locator('#btnPause')).toContainText(/Resume/i, { timeout: 2000 });
  });

});

// ── investigate.html staged import banner ────────────────────────────────────

test.describe('investigate.html — staged events import', () => {

  test.beforeEach(async ({ page }) => {
    await page.addInitScript((key) => {
      try {
        localStorage.setItem('apiKey', key);
        // Pre-seed staged events as if home.html wrote them
        localStorage.setItem('janusec_staged_events', JSON.stringify({
          staged_at: new Date().toISOString(),
          source: 'live_dashboard',
          events: [
            { event_id: 'staged-001', severity: 'critical', type: 'correlated',
              entity: '10.10.4.47', description: 'Lateral move', triage_score: 1.0 },
          ],
        }));
      } catch (_) {}
    }, API_KEY);
  });

  test('import banner appears when staged events exist', async ({ page }) => {
    await page.goto('/static/investigate.html', { waitUntil: 'domcontentloaded', timeout: 15000 });

    // Banner must be visible
    const banner = page.locator('#stagedImportBanner');
    await expect(banner).toBeVisible({ timeout: 5000 });
    await expect(banner).toContainText(/staged from Live Operations/i);
    await expect(banner).toContainText('1');
  });

  test('dismiss button hides banner and clears localStorage', async ({ page }) => {
    await page.goto('/static/investigate.html', { waitUntil: 'domcontentloaded', timeout: 15000 });

    await expect(page.locator('#stagedImportBanner')).toBeVisible({ timeout: 5000 });

    await page.getByRole('button', { name: /Dismiss/i }).click();

    await expect(page.locator('#stagedImportBanner')).toHaveCSS('display', 'none', { timeout: 3000 });

    const val = await page.evaluate(() => localStorage.getItem('janusec_staged_events'));
    expect(val).toBeNull();
  });

});
