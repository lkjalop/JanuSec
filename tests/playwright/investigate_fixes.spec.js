// investigate_fixes.spec.js
// Regression tests for the three bugs fixed in investigate.html / investigate.js:
//   1. Persona chip switching shows empty content after analysis
//   2. History sidebar crashes with rebuildFilteredRows ReferenceError + 404 loop
//   3. handleSave ReferenceError on page load
//   4. Home page showing fake 98.2% / 1.2s placeholder stats when no data

const { test, expect } = require('@playwright/test');
const path = require('path');
const fs = require('fs');

const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:8080';

// ── Helper: set required localStorage keys before page loads
async function seedStorage(page) {
  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'devkey123');
    localStorage.setItem('tenantId', 'default');
  });
}

// ── Helper: seed localStorage with a stale history entry so the 4xx path is exercised
async function seedStaleHistory(page) {
  await page.evaluate(() => {
    const fakeHistory = [
      { id: 'stale-id-does-not-exist', ts: Date.now() - 86400000, headline: 'Old assessment', sources: ['test.csv'], rows: 5 }
    ];
    localStorage.setItem('janusec_history', JSON.stringify(fakeHistory));
  });
}

// ── Fixture: upload three test files that match the user's real session
const FIXTURES_DIR = path.join(__dirname, 'fixtures');
async function uploadTestFiles(page) {
  // Use the file input directly (headless drag-and-drop is unreliable)
  const fileInput = page.locator('#fileInput');
  await fileInput.setInputFiles([
    path.join(FIXTURES_DIR, 'janusec_ep_endpoint.xlsx'),
    path.join(FIXTURES_DIR, 'janusec_okta_m365_events.json'),
    path.join(FIXTURES_DIR, 'janusec_net_c2_bgp.csv'),
  ].filter(f => fs.existsSync(f)));
}

// ── Fixture: minimal CSV fallback when real test files not present
async function uploadMinimalCsv(page) {
  const csv = 'severity,description,src_ip\nhigh,Test alert,192.168.1.1\ncritical,Possible exfil,10.0.0.1\n';
  const buffer = Buffer.from(csv);
  await page.locator('#fileInput').setInputFiles([
    { name: 'test_events.csv', mimeType: 'text/csv', buffer }
  ]);
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 1 — handleSave ReferenceError should NOT appear on page load
// ════════════════════════════════════════════════════════════════════════════
test('investigate: no handleSave ReferenceError on load', async ({ page }) => {
  const errors = [];
  page.on('pageerror', err => errors.push(err.message));

  await seedStorage(page);
  await page.goto(`${BASE}/static/investigate.html`);
  await page.waitForLoadState('networkidle');

  const handleSaveError = errors.find(e => e.includes('handleSave'));
  expect(handleSaveError, `Unexpected handleSave error: ${handleSaveError}`).toBeUndefined();
});

// ════════════════════════════════════════════════════════════════════════════
// TEST 2 — History sidebar: stale 404 entry is removed, no crash
// ════════════════════════════════════════════════════════════════════════════
test('investigate: stale history 404 entry is removed gracefully', async ({ page }) => {
  const jsErrors = [];
  page.on('pageerror', err => jsErrors.push(err.message));

  await seedStorage(page);
  await page.goto(`${BASE}/static/investigate.html`);
  await page.waitForLoadState('networkidle');
  await seedStaleHistory(page);

  // Open history sidebar
  await page.click('#btnToggleHistory');
  await page.waitForSelector('#historySidebar:not([hidden])', { timeout: 3000 });

  // Click the stale entry — should trigger 404 handling, not a crash
  const historyItem = page.locator('#historyList .history-item').first();
  await expect(historyItem).toBeVisible({ timeout: 3000 });
  await historyItem.click();

  // Wait for the toast to appear (success or warn, not crash)
  await page.waitForTimeout(2000);

  // The stale entry should be gone from localStorage after the 404
  const remaining = await page.evaluate(() => {
    try { return JSON.parse(localStorage.getItem('janusec_history') || '[]'); } catch (_) { return []; }
  });
  const staleStillPresent = remaining.some(h => h.id === 'stale-id-does-not-exist');
  expect(staleStillPresent).toBe(false);

  // No rebuildFilteredRows ReferenceError should have occurred
  const rebuildError = jsErrors.find(e => e.includes('rebuildFilteredRows'));
  expect(rebuildError, `Unexpected rebuildFilteredRows error: ${rebuildError}`).toBeUndefined();
});

// ════════════════════════════════════════════════════════════════════════════
// TEST 3 — Persona switching shows content for every non-gated persona
// ════════════════════════════════════════════════════════════════════════════
test('investigate: all ungated personas show report content after analysis', async ({ page }) => {
  const jsErrors = [];
  page.on('pageerror', err => jsErrors.push(err.message));

  await seedStorage(page);
  await page.goto(`${BASE}/static/investigate.html`);
  await page.waitForLoadState('networkidle');

  // Upload a minimal file
  await uploadMinimalCsv(page);
  await page.waitForTimeout(800);

  // Run analysis
  await page.click('#btnAnalyze');
  // Wait for analysis: either reportContent is visible (has data) OR reportEmpty is visible (error)
  // Also accept reportLoading gone as a completion signal
  await page.waitForFunction(
    () => {
      const content = document.getElementById('reportContent');
      const empty = document.getElementById('reportEmpty');
      const loading = document.getElementById('reportLoading');
      if (!content || !empty || !loading) return false;
      const contentVis = content.style.display !== 'none';
      const emptyVis = empty.style.display !== 'none';
      const loadingHidden = loading.style.display === 'none';
      return (contentVis || emptyVis) && loadingHidden;
    },
    { timeout: 45000 }
  );

  // Must have actually completed with content, not error
  const analysisSucceeded = await page.locator('#reportContent').evaluate(
    el => el.style.display !== 'none'
  );
  expect(analysisSucceeded, 'Analysis should complete and show report content').toBe(true);

  // Test non-gated personas: forensics and mssp should show content (not empty state)
  // SOC Analyst, Threat Hunter, Compliance require NLP gate — skip those
  // CISO, Executive, Audit require human gate — skip those
  const ungatedPersonas = ['forensics', 'mssp'];

  for (const persona of ungatedPersonas) {
    // Click the persona chip
    const chip = page.locator('.persona-chip').filter({ hasText: new RegExp(persona, 'i') }).first();
    if (await chip.count() === 0) continue; // chip not rendered yet — skip
    await chip.click();
    await page.waitForTimeout(500);

    const reportContent = page.locator('#reportContent');
    const reportEmpty = page.locator('#reportEmpty');

    // reportContent should be visible, reportEmpty should be hidden
    const contentVisible = await reportContent.evaluate(el => el.style.display !== 'none');
    const emptyHidden = await reportEmpty.evaluate(el => el.style.display === 'none');

    expect(contentVisible, `Persona ${persona}: reportContent not visible`).toBe(true);
    expect(emptyHidden, `Persona ${persona}: reportEmpty still showing`).toBe(true);
  }

  // No JS errors throughout
  expect(jsErrors.length, `JS errors: ${jsErrors.join(', ')}`).toBe(0);
});

// ════════════════════════════════════════════════════════════════════════════
// TEST 3b — NLP-gated personas show report content FIRST, verdict form at bottom
// ════════════════════════════════════════════════════════════════════════════
test('investigate: NLP-gated personas show report content first, not a blocking gate', async ({ page }) => {
  const jsErrors = [];
  page.on('pageerror', err => jsErrors.push(err.message));

  await seedStorage(page);
  await page.goto(`${BASE}/static/investigate.html`);
  await page.waitForLoadState('networkidle');

  await uploadMinimalCsv(page);
  await page.waitForTimeout(800);

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
    { timeout: 45000 }
  );

  const analysisSucceeded = await page.locator('#reportContent').evaluate(el => el.style.display !== 'none');
  expect(analysisSucceeded, 'Analysis should complete with report content visible').toBe(true);

  // For each NLP-gated persona: report sections must be present AND the verdict form is at the bottom
  for (const persona of ['soc_analyst', 'threat_hunter', 'compliance']) {
    const chip = page.locator('.persona-chip').filter({ hasText: new RegExp(persona.replace('_', '[ _]'), 'i') }).first();
    if (await chip.count() === 0) continue;
    await chip.click();
    await page.waitForTimeout(500);

    // reportContent must be visible (not replaced by the gate)
    const contentVisible = await page.locator('#reportContent').evaluate(el => el.style.display !== 'none');
    expect(contentVisible, `${persona}: reportContent should be visible (not blocked by NLP gate)`).toBe(true);

    // At least one .report-section must be present (the actual report content)
    const sectionCount = await page.locator('.report-section').count();
    expect(sectionCount, `${persona}: should have at least 1 report section before the verdict form`).toBeGreaterThan(0);

    // The verdict textarea should be present at the bottom (not as the only content)
    const verdictForm = page.locator('#nlpGateInput');
    const formVisible = await verdictForm.count() > 0;
    expect(formVisible, `${persona}: verdict textarea should be present in the report for analyst input`).toBe(true);
  }

  expect(jsErrors.length, `JS errors: ${jsErrors.join(', ')}`).toBe(0);
});

// ════════════════════════════════════════════════════════════════════════════
// TEST 4 — Home page: no fake placeholder stats when backend has no data
// ════════════════════════════════════════════════════════════════════════════
test('home: detection rate shows dash when no real telemetry', async ({ page }) => {
  await page.goto(`${BASE}/`);
  await page.waitForLoadState('networkidle');

  // Give the metrics poll time to run
  await page.waitForTimeout(2000);

  const detRate = await page.locator('#mDetRate').textContent();
  const avgResp = await page.locator('#mAvgResp').textContent();

  // Should be either a real measured value OR the dash placeholder
  // It must NOT be the old hardcoded fake "98.2%" or "99.2%" or "1.2s" when no events have been processed
  // (If the server genuinely has events and returns 98.2, this test should be adjusted)
  const critCount = await page.locator('#mCrit').textContent();
  const highCount = await page.locator('#mHigh').textContent();

  if (critCount === '0' && highCount === '0') {
    // No real events → metrics should show dash
    expect(detRate, 'Detection rate should be "–" when no events processed').toBe('–');
    expect(avgResp, 'Avg response should be "–" when no events processed').toBe('–');
  }
  // If there are events, any non-dash value is acceptable
});

// ════════════════════════════════════════════════════════════════════════════
// TEST 5 — Home page: connector bar shows "no connectors" when none configured
// ════════════════════════════════════════════════════════════════════════════
test('home: connector bar shows setup link when no connectors configured', async ({ page }) => {
  await page.goto(`${BASE}/`);
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(2000);

  const connBar = page.locator('#connectorChips');
  const text = await connBar.textContent();

  // Should either show real connector chips OR the "no connectors" guidance message
  // Must NOT show the old fake "API" chip
  const hasFakeApiChip = text.includes('API') && text.trim() === 'API';
  expect(hasFakeApiChip, 'Should not show misleading fake "API" connector chip').toBe(false);
});

// ════════════════════════════════════════════════════════════════════════════
// TEST 6 — Sidebar nav links all return 200
// ════════════════════════════════════════════════════════════════════════════
test('home: sidebar nav links resolve to valid pages', async ({ page, request }) => {
  const links = [
    '/static/investigate.html',
    '/static/hunt_network.html',
    '/static/hunt_endpoint.html',
    '/static/mitre.html',
    '/static/metrics.html',
    '/static/sbom.html',
    '/static/integrations.html',
    '/static/admin.html',
  ];

  for (const link of links) {
    const resp = await request.get(`${BASE}${link}`);
    expect(resp.status(), `${link} returned ${resp.status()}`).toBe(200);
  }
});
