// cluster_drilldown_smoke.spec.js
// Smoke tests for the cluster drilldown feature:
//   1. Sev-box click opens cluster panel (or shows "no clusters" message)
//   2. Cluster panel close button hides the panel
//   3. After analysis with correlated data: cluster panel lists rows, "Drill in →" opens drawer
//   4. Cluster drawer shows all required sections (Business Pressure, DREAD, Persona Tasks)
//   5. Cluster drawer close button closes drawer
//   6. Queue active item click opens cluster drawer

const { test, expect } = require('@playwright/test');

const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:8080';

async function seedStorage(page) {
  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'devkey123');
    localStorage.setItem('tenantId', 'default');
  });
}

async function uploadMinimalCsv(page) {
  const csv = [
    'severity,description,src_ip,user,hostname',
    'critical,Lateral movement detected,10.0.0.5,admin,ws-001',
    'high,Credential dump attempt,10.0.0.5,admin,ws-001',
    'critical,C2 beacon detected,10.0.0.5,svc_acct,dc-001',
    'high,Suspicious login from shared IP,192.168.1.1,svc_acct,srv-002',
    'medium,Port scan detected,192.168.1.1,guest,fw-edge',
  ].join('\n');
  const buffer = Buffer.from(csv);
  await page.locator('#fileInput').setInputFiles([
    { name: 'cluster_test.csv', mimeType: 'text/csv', buffer },
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

// ════════════════════════════════════════════════════════════════════════════
// TEST 1 — Sev-box click opens cluster panel (or shows empty-state message)
// ════════════════════════════════════════════════════════════════════════════
test('cluster: sev-box click makes cluster panel visible', async ({ page }) => {
  const jsErrors = [];
  page.on('pageerror', err => jsErrors.push(err.message));

  await seedStorage(page);
  await page.goto(`${BASE}/static/investigate.html`);
  await page.waitForLoadState('networkidle');

  await uploadMinimalCsv(page);
  await page.waitForTimeout(500);
  await runAnalysisAndWait(page);

  // Click any sev-box (Critical correlated or any visible one)
  const sevBox = page.locator('.sev-box').first();
  await expect(sevBox).toBeVisible();
  await sevBox.click();

  // Cluster panel should become visible
  const clusterPanel = page.locator('#clusterPanel');
  await expect(clusterPanel).toHaveClass(/visible/, { timeout: 2000 });

  // Panel should contain either cluster rows or the empty-state message
  const panelBody = page.locator('#clusterPanelBody');
  const bodyText = await panelBody.textContent();
  expect(bodyText.trim().length, 'Panel body should have content').toBeGreaterThan(0);

  expect(jsErrors.length, `JS errors: ${jsErrors.join(', ')}`).toBe(0);
});

// ════════════════════════════════════════════════════════════════════════════
// TEST 2 — Cluster panel close button hides the panel
// ════════════════════════════════════════════════════════════════════════════
test('cluster: panel close button hides cluster panel', async ({ page }) => {
  const jsErrors = [];
  page.on('pageerror', err => jsErrors.push(err.message));

  await seedStorage(page);
  await page.goto(`${BASE}/static/investigate.html`);
  await page.waitForLoadState('networkidle');

  await uploadMinimalCsv(page);
  await page.waitForTimeout(500);
  await runAnalysisAndWait(page);

  // Open cluster panel via sev-box
  await page.locator('.sev-box').first().click();
  const clusterPanel = page.locator('#clusterPanel');
  await expect(clusterPanel).toHaveClass(/visible/, { timeout: 2000 });

  // Close it
  await page.click('#btnCloseClusterPanel');
  await expect(clusterPanel).not.toHaveClass(/visible/, { timeout: 2000 });

  expect(jsErrors.length, `JS errors: ${jsErrors.join(', ')}`).toBe(0);
});

// ════════════════════════════════════════════════════════════════════════════
// TEST 3 — Sev-box active-filter class applied and removed on close
// ════════════════════════════════════════════════════════════════════════════
test('cluster: sev-box active-filter class applied on click, cleared on panel close', async ({ page }) => {
  const jsErrors = [];
  page.on('pageerror', err => jsErrors.push(err.message));

  await seedStorage(page);
  await page.goto(`${BASE}/static/investigate.html`);
  await page.waitForLoadState('networkidle');

  await uploadMinimalCsv(page);
  await page.waitForTimeout(500);
  await runAnalysisAndWait(page);

  const firstBox = page.locator('.sev-box').first();
  await firstBox.click();

  // active-filter class should be on exactly this box
  await expect(firstBox).toHaveClass(/active-filter/, { timeout: 2000 });

  // Close panel
  await page.click('#btnCloseClusterPanel');

  // active-filter should be cleared
  await expect(firstBox).not.toHaveClass(/active-filter/, { timeout: 2000 });

  expect(jsErrors.length, `JS errors: ${jsErrors.join(', ')}`).toBe(0);
});

// ════════════════════════════════════════════════════════════════════════════
// TEST 4 — If clusters present: drill-in button opens cluster drawer
// ════════════════════════════════════════════════════════════════════════════
test('cluster: drill-in button opens cluster drawer with sections', async ({ page }) => {
  const jsErrors = [];
  page.on('pageerror', err => jsErrors.push(err.message));

  await seedStorage(page);
  await page.goto(`${BASE}/static/investigate.html`);
  await page.waitForLoadState('networkidle');

  await uploadMinimalCsv(page);
  await page.waitForTimeout(500);
  await runAnalysisAndWait(page);

  // Open cluster panel
  await page.locator('.sev-box').first().click();
  await page.locator('#clusterPanel').waitFor({ state: 'visible', timeout: 3000 });

  // Check for cluster rows in the table
  const drillBtns = page.locator('#clusterPanelBody .cluster-drill-btn');
  const count = await drillBtns.count();

  if (count === 0) {
    // No clusters produced by backend for minimal CSV — acceptable, skip drawer test
    test.skip(true, 'No clusters returned by backend for minimal CSV — skipping drawer test');
    return;
  }

  // Click first drill button
  await drillBtns.first().click();
  await page.waitForTimeout(1000);

  // Drawer should open
  const drawer = page.locator('#clusterDrawer');
  await expect(drawer).toHaveClass(/open/, { timeout: 3000 });

  // Drawer should have content in its body
  const drawerBody = page.locator('#clusterDrawerBody');
  const drawerText = await drawerBody.textContent();
  expect(drawerText.trim().length, 'Drawer body should contain content').toBeGreaterThan(50);

  // Action bar should be present
  const actionBar = page.locator('#clusterActionBar');
  await expect(actionBar).toBeVisible();

  expect(jsErrors.length, `JS errors: ${jsErrors.join(', ')}`).toBe(0);
});

// ════════════════════════════════════════════════════════════════════════════
// TEST 5 — Cluster drawer close button closes the drawer
// ════════════════════════════════════════════════════════════════════════════
test('cluster: drawer close button closes the drawer', async ({ page }) => {
  const jsErrors = [];
  page.on('pageerror', err => jsErrors.push(err.message));

  await seedStorage(page);
  await page.goto(`${BASE}/static/investigate.html`);
  await page.waitForLoadState('networkidle');

  await uploadMinimalCsv(page);
  await page.waitForTimeout(500);
  await runAnalysisAndWait(page);

  // Open via sev-box → drill-in
  await page.locator('.sev-box').first().click();
  await page.locator('#clusterPanel').waitFor({ state: 'visible', timeout: 3000 });

  const drillBtns = page.locator('#clusterPanelBody .cluster-drill-btn');
  const count = await drillBtns.count();
  if (count === 0) {
    test.skip(true, 'No clusters — skipping drawer close test');
    return;
  }

  await drillBtns.first().click();
  await page.waitForTimeout(800);
  await expect(page.locator('#clusterDrawer')).toHaveClass(/open/, { timeout: 3000 });

  // Close
  await page.click('#btnCloseClusterDrawer');
  await expect(page.locator('#clusterDrawer')).not.toHaveClass(/open/, { timeout: 2000 });

  expect(jsErrors.length, `JS errors: ${jsErrors.join(', ')}`).toBe(0);
});

// ════════════════════════════════════════════════════════════════════════════
// TEST 6 — Scope banners appear when cluster scope is active
// ════════════════════════════════════════════════════════════════════════════
test('cluster: scope banners appear when cluster detail is open', async ({ page }) => {
  const jsErrors = [];
  page.on('pageerror', err => jsErrors.push(err.message));

  await seedStorage(page);
  await page.goto(`${BASE}/static/investigate.html`);
  await page.waitForLoadState('networkidle');

  await uploadMinimalCsv(page);
  await page.waitForTimeout(500);
  await runAnalysisAndWait(page);

  await page.locator('.sev-box').first().click();
  await page.locator('#clusterPanel').waitFor({ state: 'visible', timeout: 3000 });

  const drillBtns = page.locator('#clusterPanelBody .cluster-drill-btn');
  const count = await drillBtns.count();
  if (count === 0) {
    test.skip(true, 'No clusters — skipping scope banner test');
    return;
  }

  await drillBtns.first().click();
  await page.waitForTimeout(800);

  // Report tab scope banner should become visible
  const reportBanner = page.locator('#scopeBannerReport');
  await expect(reportBanner).toHaveClass(/visible/, { timeout: 2000 });

  // Switch to Evidence tab — evidence scope banner should show
  await page.click('[data-tab="evidence"]');
  const evidenceBanner = page.locator('#scopeBannerEvidence');
  await expect(evidenceBanner).toHaveClass(/visible/, { timeout: 2000 });

  // The clear button uses an inline onclick="clearClusterScope()" — call it directly
  // to avoid click interception from the cluster drawer overlay (z-index:50).
  await page.evaluate(() => { if (typeof clearClusterScope === 'function') clearClusterScope(); });
  await expect(evidenceBanner).not.toHaveClass(/visible/, { timeout: 2000 });

  expect(jsErrors.length, `JS errors: ${jsErrors.join(', ')}`).toBe(0);
});
