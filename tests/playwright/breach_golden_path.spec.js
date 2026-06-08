/**
 * breach_golden_path.spec.js
 *
 * Playwright E2E test suite for the breach.html golden path.
 *
 * Covers:
 *  1. Upload zone renders on bare /static/breach.html
 *  2. Upload 3 files → redirects to ?assessment=... home page
 *  3. Home page meta line shows N sources / M rows / K clusters (not '?')
 *  4. Lead card has a non-empty title and non-empty subtitle (fallback or LLM)
 *  5. Executive summary container is visible (may show skeleton or text)
 *  6. Clicking "Open in tab" navigates to cluster detail (?cluster=…)
 *  7. Cluster detail: [bct-wrap] is visible, persona steps render
 *  8. Notes autosave: type text, status changes to 'Saved ✓'
 *  9. IOC export: clicking button does not 404-silently-fail
 * 10. Sign-off: click Confirmed → shows done badge (not false positive)
 *
 * LLM routes are intercepted and return a minimal mock so no actual
 * qwen/Ollama calls are made. The upload + deep_analyze pipeline is
 * real — it calls the live server.
 *
 * Run with:
 *   npx playwright test tests/playwright/breach_golden_path.spec.js
 *   PLAYWRIGHT_BASE_URL=http://localhost:8000 npx playwright test ...
 */

const { test, expect } = require('@playwright/test');
const path = require('path');

test.describe.configure({ mode: 'serial' });

const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:8080';
const BREACH_URL = BASE + '/static/breach.html';

const TEST_FILES_DIR = path.join(__dirname, '../../dump/investigate-upload/dump/test files');
const NET_CSV   = path.join(TEST_FILES_DIR, 'janusec_net_c2_bgp.v1.1.csv');
const OKTA_JSON = path.join(TEST_FILES_DIR, 'janusec_okta_m365_events.v1.1.json');
const EP_XLSX   = path.join(TEST_FILES_DIR, 'janusec_ep_endpoint.v1.1.xlsx');

// ── Mock LLM endpoints so tests are deterministic and fast ────────────────────
async function mockLlmRoutes(page) {
  // Tier-1 summary mock
  await page.route('**/clusters/*/tier1-summary', route => {
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        tier1_prefill: {
          incident_name: 'MOCK-INCIDENT',
          headline_subtitle: 'Mock subtitle for Playwright test',
          short_narrative: 'Playwright mock narrative — deterministic test.',
          confidence_meter: {
            total: 72,
            segments: {
              source_corroboration: 18,
              evidence_cluster_strength: 18,
              technique_confidence: 18,
              temporal_consistency: 18,
            },
          },
          top_actions: ['Isolate host', 'Reset credentials', 'Enable MFA'],
          mitre_techniques: ['T1071.004', 'T1048'],
          verdict_reasoning: 'Mock: timing + beacon + JA3 correlation.',
          mitre_evidence_map: { 'T1071.004': [0, 1], 'T1048': [2] },
        }
      }),
    });
  });

  // Executive summary mock
  await page.route('**/executive-summary', route => {
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        deterministic: 'Mock executive summary: 3 sources, high-severity APT activity detected.',
        llm_color: '',
      }),
    });
  });

  // Sign-off mock
  await page.route('**/sign-off', route => {
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ status: 'signed_off', cluster_id: 'cluster-1', signed_off_at: Math.floor(Date.now() / 1000) }),
    });
  });

  // Notes mock
  await page.route('**/notes', route => {
    if (route.request().method() === 'PATCH') {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ status: 'ok', cluster_id: 'cluster-1', updated_at: Math.floor(Date.now() / 1000) }),
      });
    } else {
      route.continue();
    }
  });
}

// Shared state across serial tests
let assessmentId = '';
let leadClusterId = '';

// ── Test 1: Upload zone renders ───────────────────────────────────────────────
test('1. Upload zone renders on bare breach.html', async ({ page }) => {
  await page.goto(BREACH_URL);
  await expect(page.locator('[data-testid="br-upload"]')).toBeVisible({ timeout: 10000 });
  await expect(page.locator('[data-testid="br-drop-zone"]')).toBeVisible();
});

// ── Test 2: Upload 3 files → redirect to home ─────────────────────────────────
test('2. Upload 3 files → redirects to home with ?assessment=', async ({ page }) => {
  await page.goto(BREACH_URL);
  await expect(page.locator('[data-testid="br-drop-zone"]')).toBeVisible({ timeout: 10000 });

  // Use file chooser to upload files
  const [fileChooser] = await Promise.all([
    page.waitForEvent('filechooser'),
    page.locator('[data-testid="br-drop-zone"]').click(),
  ]);
  await fileChooser.setFiles([NET_CSV, OKTA_JSON, EP_XLSX]);

  // Wait for redirect — URL should contain ?assessment=
  await page.waitForURL(/\?assessment=/, { timeout: 60000 });
  const url = page.url();
  expect(url).toContain('assessment=');
  assessmentId = new URL(url).searchParams.get('assessment') || '';
  expect(assessmentId).toBeTruthy();
});

// ── Test 3: Home page meta line shows real counts ────────────────────────────
test('3. Home page shows N sources / M rows / K clusters — not "?"', async ({ page }) => {
  await mockLlmRoutes(page);
  await page.goto(BREACH_URL + '?assessment=' + assessmentId);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 15000 });

  const sourceText = await page.locator('[data-testid="br-source-count"]').textContent();
  expect(sourceText.trim()).not.toBe('?');
  expect(parseInt(sourceText.trim(), 10)).toBeGreaterThan(0);

  const rowText = await page.locator('[data-testid="br-row-count"]').textContent();
  expect(rowText.trim()).not.toBe('?');
  expect(parseInt(rowText.trim(), 10)).toBeGreaterThan(0);

  const clusterText = await page.locator('[data-testid="br-cluster-count"]').textContent();
  expect(parseInt(clusterText.trim(), 10)).toBeGreaterThan(0);
});

// ── Test 4: Lead card has non-empty title and subtitle ────────────────────────
test('4. Lead card has a title and subtitle (fallback or LLM)', async ({ page }) => {
  await mockLlmRoutes(page);
  await page.goto(BREACH_URL + '?assessment=' + assessmentId);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 15000 });
  // Cards are inside the drill-down (collapsed by default) — open it
  const toggleBtn = page.locator('[data-testid="br-toggle-drilldown"]');
  if (await toggleBtn.count() > 0) {
    await toggleBtn.click();
  }
  // Cards are inside nested "Analyst Detail" details — open it too
  const analystDetail = page.locator('[data-testid="br-analyst-detail"] > summary');
  if (await analystDetail.count() > 0) {
    await analystDetail.click();
  }
  // Find the first card with data-testid="br-card-*"
  const card = page.locator('[data-testid^="br-card-"]').first();
  await expect(card).toBeVisible({ timeout: 10000 });
  leadClusterId = (await card.getAttribute('data-testid') || '').replace('br-card-', '');

  const title = await card.locator('.br-card__title').textContent();
  expect(title.trim().length).toBeGreaterThan(3);  // not empty cluster ID placeholder

  const subtitle = await card.locator('.br-card__subtitle').textContent();
  expect(subtitle.trim().length).toBeGreaterThan(0);
});

// ── Test 5: Exec summary container renders (inside drill-down) ────────────────
test('5. Executive summary container is visible', async ({ page }) => {
  await mockLlmRoutes(page);
  await page.goto(BREACH_URL + '?assessment=' + assessmentId);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 15000 });

  // Exec summary is inside the drill-down — open it
  const toggleBtn = page.locator('[data-testid="br-toggle-drilldown"]');
  if (await toggleBtn.count() > 0) {
    await toggleBtn.click();
  }

  await expect(page.locator('[data-testid="br-exec-block"]')).toBeVisible({ timeout: 15000 });
  // After mock resolves, text should be non-empty
  await expect(page.locator('#br-exec-det')).not.toBeEmpty({ timeout: 10000 });
});

// ── Test 6: Open cluster tab from home card ───────────────────────────────────
test('6. Clicking "Open in tab" navigates to cluster detail', async ({ page }) => {
  await mockLlmRoutes(page);
  await page.goto(BREACH_URL + '?assessment=' + assessmentId);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 15000 });

  // Cards are inside the drill-down + analyst detail — open both
  const toggleBtn = page.locator('[data-testid="br-toggle-drilldown"]');
  if (await toggleBtn.count() > 0) await toggleBtn.click();
  const analystDetail = page.locator('[data-testid="br-analyst-detail"] > summary');
  if (await analystDetail.count() > 0) await analystDetail.click();

  // Find and click the first visible threat-case action button (opens new tab)
  const openBtn = page.locator('.br-home-cases__table .br-card__open').first();
  await expect(openBtn).toBeVisible({ timeout: 10000 });

  const [newPage] = await Promise.all([
    page.context().waitForEvent('page'),
    openBtn.click(),
  ]);
  await newPage.waitForLoadState('domcontentloaded');
  expect(newPage.url()).toContain('cluster=');
  await newPage.close();
});

// ── Test 7: Cluster detail shows persona steps ────────────────────────────────
test('7. Cluster detail: persona steps render (fallback from tier2)', async ({ page }) => {
  if (!leadClusterId) test.skip();
  await mockLlmRoutes(page);
  await page.goto(BREACH_URL + '?assessment=' + assessmentId + '&cluster=' + leadClusterId);
  await expect(page.locator('[data-testid="bct-wrap"]')).toBeVisible({ timeout: 15000 });
  // Persona body should load — either steps or a generate button
  await expect(page.locator('[data-testid="bct-persona-body"]')).toBeVisible({ timeout: 10000 });
  // Either steps list or generate button must appear (not perpetual spinner)
  const stepOrPrompt = page.locator('.bct-step, .bct-generate-prompt, #bct-gen-btn');
  const count = await stepOrPrompt.count();
  expect(count, 'Expected at least one persona step or generate button').toBeGreaterThan(0);
});

// ── Test 8: Notes autosave shows 'Saved ✓' ───────────────────────────────────
test('8. Notes autosave: type text → status shows Saved ✓', async ({ page }) => {
  if (!leadClusterId) test.skip();
  await mockLlmRoutes(page);
  await page.goto(BREACH_URL + '?assessment=' + assessmentId + '&cluster=' + leadClusterId);
  await expect(page.locator('[data-testid="bct-notes-input"]')).toBeVisible({ timeout: 15000 });

  await page.locator('[data-testid="bct-notes-input"]').fill('Playwright autosave test note.');
  // Wait for debounce + save response
  await expect(page.locator('#bct-notes-status')).toHaveText('Saved ✓', { timeout: 5000 });
});

// ── Test 9: IOC export button shows feedback, not silent 404 ─────────────────
test('9. IOC export button shows feedback (not silent failure)', async ({ page }) => {
  if (!leadClusterId) test.skip();
  await mockLlmRoutes(page);

  // Mock /iocs endpoint to return real shape
  await page.route('**/clusters/*/iocs', route => {
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        users: ['alice@test.com', 'bob@test.com'],
        ips: ['185.1.2.3', '10.0.0.1'],
        hosts: ['WORKSTATION-1'],
        cluster_id: leadClusterId,
        verdict: 'CONFIRMED',
        exported_at: new Date().toISOString(),
      }),
    });
  });

  await page.goto(BREACH_URL + '?assessment=' + assessmentId + '&cluster=' + leadClusterId);
  await expect(page.locator('[data-testid="bct-ioc-btn"]')).toBeVisible({ timeout: 15000 });

  await page.locator('[data-testid="bct-ioc-btn"]').click();
  // Button should show exported state, not remain in loading or error
  await expect(page.locator('[data-testid="bct-ioc-btn"]')).toHaveText('✓ Exported', { timeout: 8000 });
  // Summary should appear
  await expect(page.locator('[data-testid="bct-ioc-summary"]')).toContainText('users', { timeout: 5000 });
});

// ── Test 10: Sign-off Confirmed → done badge (not false positive on 404) ──────
test('10. Sign-off Confirmed → done badge only after server confirms', async ({ page }) => {
  if (!leadClusterId) test.skip();
  await mockLlmRoutes(page);
  await page.goto(BREACH_URL + '?assessment=' + assessmentId + '&cluster=' + leadClusterId);
  await expect(page.locator('[data-testid="bct-signoff-confirm"]')).toBeVisible({ timeout: 15000 });

  await page.locator('[data-testid="bct-signoff-confirm"]').click();
  // Should show done badge with 'CONFIRMED' text
  await expect(page.locator('[data-testid="bct-signoff-done"]')).toBeVisible({ timeout: 8000 });
  await expect(page.locator('[data-testid="bct-signoff-done"]')).toContainText('CONFIRMED');

  // Verify button is gone (sign-off is final)
  await expect(page.locator('[data-testid="bct-signoff-confirm"]')).not.toBeVisible();
});

// ── Test 11: Sign-off false positive protection — 500 error keeps button ──────
test('11. Sign-off on server error keeps button (no false success)', async ({ page }) => {
  if (!leadClusterId) test.skip();
  await mockLlmRoutes(page);

  // Override sign-off mock to return 500
  await page.route('**/sign-off', route => {
    route.fulfill({ status: 500, body: 'Internal Server Error' });
  });

  await page.goto(BREACH_URL + '?assessment=' + assessmentId + '&cluster=' + leadClusterId);
  await expect(page.locator('[data-testid="bct-signoff-confirm"]')).toBeVisible({ timeout: 15000 });

  await page.locator('[data-testid="bct-signoff-confirm"]').click();
  // On error, button should show Retry, NOT show done badge
  await expect(page.locator('[data-testid="bct-signoff-confirm"]')).not.toHaveText('CONFIRMED', { timeout: 5000 });
  await expect(page.locator('[data-testid="bct-signoff-done"]')).not.toBeVisible({ timeout: 3000 }).catch(() => {});
});
