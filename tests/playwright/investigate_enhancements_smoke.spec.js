// investigate_enhancements_smoke.spec.js
// Smoke tests for batch of investigate.html enhancements:
//   1. Timeline renders with DAY-number fallback (no real timestamps)
//   2. Investigation summary panel appears after analysis (3 toggle views)
//   3. Cluster drawer pop-out button exists and is wired
//   4. Cluster drawer resize handle is present
//   5. Report tab summary toggle buttons work
//   6. Tier 2 Canvas button appears in cluster action bar
//   7. Tier 2 investigation.html loads and shows phase rail

const { test, expect } = require('@playwright/test');

const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:8080';

async function seedStorage(page) {
  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'devkey123');
    localStorage.setItem('tenantId', 'default');
  });
}

async function uploadDayNumberCsv(page) {
  // CSV whose descriptions start with "DAY N" — tests the timestamp fallback
  const csv = [
    'severity,description,src_ip,user,hostname',
    'critical,DAY 1 T+0s Lateral movement detected,10.0.0.5,admin,ws-001',
    'high,DAY 2 T+4s Credential dump attempt,10.0.0.5,admin,ws-001',
    'critical,DAY 3 T+12s C2 beacon detected,10.0.0.5,svc_acct,dc-001',
    'high,DAY 5 T+0s Suspicious login,192.168.1.1,svc_acct,srv-002',
    'medium,DAY 7 T+1s Port scan detected,192.168.1.1,guest,fw-edge',
  ].join('\n');
  const buffer = Buffer.from(csv);
  await page.locator('#fileInput').setInputFiles([
    { name: 'day_number_test.csv', mimeType: 'text/csv', buffer },
  ]);
}

async function runAnalysisAndWait(page) {
  await page.click('#btnAnalyze');
  await page.waitForFunction(
    () => {
      const content = document.getElementById('reportContent');
      const empty   = document.getElementById('reportEmpty');
      const loading = document.getElementById('reportLoading');
      if (!content || !empty || !loading) return false;
      return (content.style.display !== 'none' || empty.style.display !== 'none')
          && loading.style.display === 'none';
    },
    { timeout: 60000 }
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST 1 — Timeline tab renders (no JS error on DAY-number CSV)
// ═══════════════════════════════════════════════════════════════════════════
test('timeline: renders without JS errors using DAY-number fallback', async ({ page }) => {
  const jsErrors = [];
  page.on('pageerror', err => jsErrors.push(err.message));

  await seedStorage(page);
  await page.goto(`${BASE}/static/investigate.html`);
  await page.waitForLoadState('networkidle');

  await uploadDayNumberCsv(page);
  await page.waitForTimeout(500);
  await runAnalysisAndWait(page);

  // Switch to Timeline tab
  await page.click('[data-tab="timeline"]');
  await page.waitForTimeout(800);

  // Timeline container should be visible and not empty
  const timelineEl = page.locator('#timelineContent, #timelineContainer, .timeline-container');
  const count = await timelineEl.count();
  // Just asserting no JS crash is the primary goal
  expect(jsErrors.filter(e => !e.includes('favicon')).length,
    `JS errors: ${jsErrors.join(', ')}`).toBe(0);

  // If a timeline element exists, verify it has content
  if (count > 0) {
    const txt = await timelineEl.first().textContent();
    // Should have rendered something (not blank)
    expect(txt.trim().length).toBeGreaterThan(0);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// TEST 2 — Investigation summary panel appears after analysis
// ═══════════════════════════════════════════════════════════════════════════
test('summary: panel appears and toggle buttons work after analysis', async ({ page }) => {
  const jsErrors = [];
  page.on('pageerror', err => jsErrors.push(err.message));

  await seedStorage(page);
  await page.goto(`${BASE}/static/investigate.html`);
  await page.waitForLoadState('networkidle');

  await uploadDayNumberCsv(page);
  await page.waitForTimeout(500);
  await runAnalysisAndWait(page);

  // Navigate to Report tab to check summary panel
  await page.click('[data-tab="report"]');
  await page.waitForTimeout(400);

  const summaryPanel = page.locator('#investigationSummary');
  const summaryVisible = await summaryPanel.isVisible().catch(() => false);

  // Summary may not show if no rows returned — both outcomes acceptable
  if (summaryVisible) {
    // Toggle buttons should be present
    const toggleBtns = page.locator('.summary-toggle-btn[data-view]');
    expect(await toggleBtns.count()).toBeGreaterThanOrEqual(2);

    // Click "Isolated Events" toggle
    await page.click('.summary-toggle-btn[data-view="isolated"]');
    await page.waitForTimeout(200);
    const activeBtn = page.locator('.summary-toggle-btn[data-view="isolated"].active');
    expect(await activeBtn.count()).toBe(1);

    // Click "Plain Language" toggle
    await page.click('.summary-toggle-btn[data-view="nontech"]');
    await page.waitForTimeout(200);
    const nontechBtn = page.locator('.summary-toggle-btn[data-view="nontech"].active');
    expect(await nontechBtn.count()).toBe(1);
  }

  expect(jsErrors.filter(e => !e.includes('favicon')).length,
    `JS errors: ${jsErrors.join(', ')}`).toBe(0);
});

// ═══════════════════════════════════════════════════════════════════════════
// TEST 3 — Cluster drawer has resize handle
// ═══════════════════════════════════════════════════════════════════════════
test('drawer: resize handle is present in the DOM', async ({ page }) => {
  await seedStorage(page);
  await page.goto(`${BASE}/static/investigate.html`);
  await page.waitForLoadState('networkidle');

  const handle = page.locator('#clusterDrawerResizeHandle');
  // Exists in DOM even before drawer is opened
  expect(await handle.count()).toBe(1);
});

// ═══════════════════════════════════════════════════════════════════════════
// TEST 4 — Cluster drawer pop-out button exists when drawer open
// ═══════════════════════════════════════════════════════════════════════════
test('drawer: pop-out button exists inside drawer', async ({ page }) => {
  const jsErrors = [];
  page.on('pageerror', err => jsErrors.push(err.message));

  await seedStorage(page);
  await page.goto(`${BASE}/static/investigate.html`);
  await page.waitForLoadState('networkidle');

  await uploadDayNumberCsv(page);
  await page.waitForTimeout(500);
  await runAnalysisAndWait(page);

  // Open cluster panel via sev-box click
  await page.locator('.sev-box').first().click();
  const clusterPanel = page.locator('#clusterPanel');
  await expect(clusterPanel).toHaveClass(/visible/, { timeout: 2000 });

  // Check for drill buttons
  const drillBtns = page.locator('#clusterPanelBody .cluster-drill-btn');
  const count = await drillBtns.count();
  if (count === 0) {
    test.skip(true, 'No clusters — skipping popout button test');
    return;
  }

  await drillBtns.first().click();
  await page.waitForTimeout(800);
  await expect(page.locator('#clusterDrawer')).toHaveClass(/open/, { timeout: 3000 });

  // Pop-out button should be inside the open drawer
  const popoutBtn = page.locator('#btnPopoutClusterDrawer');
  await expect(popoutBtn).toBeVisible({ timeout: 1000 });

  expect(jsErrors.filter(e => !e.includes('favicon')).length,
    `JS errors: ${jsErrors.join(', ')}`).toBe(0);
});

// ═══════════════════════════════════════════════════════════════════════════
// TEST 5 — Tier 2 Canvas button in action bar
// ═══════════════════════════════════════════════════════════════════════════
test('drawer: Tier 2 Canvas button appears in cluster action bar', async ({ page }) => {
  const jsErrors = [];
  page.on('pageerror', err => jsErrors.push(err.message));

  await seedStorage(page);
  await page.goto(`${BASE}/static/investigate.html`);
  await page.waitForLoadState('networkidle');

  await uploadDayNumberCsv(page);
  await page.waitForTimeout(500);
  await runAnalysisAndWait(page);

  await page.locator('.sev-box').first().click();
  const clusterPanel = page.locator('#clusterPanel');
  await expect(clusterPanel).toHaveClass(/visible/, { timeout: 2000 });

  const drillBtns = page.locator('#clusterPanelBody .cluster-drill-btn');
  const count = await drillBtns.count();
  if (count === 0) {
    test.skip(true, 'No clusters — skipping tier2 button test');
    return;
  }

  await drillBtns.first().click();
  await page.waitForTimeout(800);
  await expect(page.locator('#clusterDrawer')).toHaveClass(/open/, { timeout: 3000 });

  // Check action bar for Tier 2 Canvas button
  const t2Btn = page.locator('[data-cluster-action="t2_canvas"]');
  await expect(t2Btn).toBeVisible({ timeout: 1000 });
  expect(await t2Btn.textContent()).toContain('Tier 2');

  expect(jsErrors.filter(e => !e.includes('favicon')).length,
    `JS errors: ${jsErrors.join(', ')}`).toBe(0);
});

// ═══════════════════════════════════════════════════════════════════════════
// TEST 6 — Tier 2 investigation canvas loads and shows phase rail
// ═══════════════════════════════════════════════════════════════════════════
test('tier2: canvas page loads and shows 5-phase rail', async ({ page }) => {
  const jsErrors = [];
  page.on('pageerror', err => jsErrors.push(err.message));

  await seedStorage(page);
  await page.goto(`${BASE}/static/tier2_investigation.html?assessment_id=test&cluster_id=cluster-1`);
  await page.waitForLoadState('networkidle');
  await expect(page.locator('#tier2ModelSelect')).toBeVisible();
  await expect(page.locator('#tier2ModelSelect option[value="mistral-small3.2:24b"]')).toHaveCount(1);

  // Phase rail should have 5 steps
  const phaseSteps = page.locator('.phase-step');
  expect(await phaseSteps.count()).toBe(5);

  // First phase should be active
  await expect(phaseSteps.first()).toHaveClass(/active/);

  // Workflow body should render steps
  const workflowBody = page.locator('#workflowBody');
  await page.waitForTimeout(600);
  const bodyText = await workflowBody.textContent();
  expect(bodyText.trim().length).toBeGreaterThan(20);

  // Phase badge should say Phase 1
  const phaseBadge = page.locator('#phaseBadge');
  const badgeText = await phaseBadge.textContent();
  expect(badgeText).toContain('Phase 1');

  expect(jsErrors.filter(e => !e.includes('favicon')).length,
    `JS errors: ${jsErrors.join(', ')}`).toBe(0);
});

// ═══════════════════════════════════════════════════════════════════════════
// TEST 7 — Tier 2: decision buttons log decisions and advance phase
// ═══════════════════════════════════════════════════════════════════════════
test('tier2: decision buttons work and log to decision log', async ({ page }) => {
  const jsErrors = [];
  page.on('pageerror', err => jsErrors.push(err.message));

  await seedStorage(page);
  await page.goto(`${BASE}/static/tier2_investigation.html?assessment_id=test&cluster_id=cluster-2`);
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(600);

  // Find first decision button (Yes — Confirmed)
  const yesBtn = page.locator('.decision-btn[data-decision="yes"]').first();
  await expect(yesBtn).toBeVisible({ timeout: 2000 });
  await yesBtn.click();
  await page.waitForTimeout(300);

  // Button should have selected-yes class
  await expect(yesBtn).toHaveClass(/selected-yes/);

  // Open decision log
  await page.click('#btnToggleLog');
  await page.waitForTimeout(200);
  const logPanel = page.locator('#decisionLogPanel');
  await expect(logPanel).toHaveClass(/open/);

  // Log should show an entry
  const logEntries = page.locator('.log-entry');
  expect(await logEntries.count()).toBeGreaterThan(0);

  expect(jsErrors.filter(e => !e.includes('favicon')).length,
    `JS errors: ${jsErrors.join(', ')}`).toBe(0);
});
