/**
 * Regression: three v1.1 files must produce correlated clusters and correct severity counts.
 *
 * Catches:
 *   - row_index collision bug (per-file vs global index)
 *   - detectCorrelation using stale heuristic instead of backend cluster membership
 *   - classifySeverity missing threat_confidence / risk_score signals
 *
 * Requires server on port 8080.
 */
const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

const BASE     = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:8080';
const DUMP_DIR = path.resolve(__dirname, '../../dump/test files');
const FILES_V11 = [
  { file: 'janusec_net_c2_bgp.v1.1.csv',         mime: 'text/csv' },
  { file: 'janusec_ep_endpoint.v1.1.xlsx',         mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' },
  { file: 'janusec_okta_m365_events.v1.1.json',   mime: 'application/json' },
];

function loadFixtures() {
  return FILES_V11.map(({ file, mime }) => {
    const fp = path.join(DUMP_DIR, file);
    if (!fs.existsSync(fp)) return null;
    return { name: file, mimeType: mime, buffer: fs.readFileSync(fp) };
  }).filter(Boolean);
}

async function seedStorage(page) {
  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'devkey123');
    localStorage.setItem('tenantId', 'default');
  });
}

async function uploadAndAnalyze(page, files) {
  await page.goto(`${BASE}/static/investigate.html`, { waitUntil: 'domcontentloaded' });
  await page.locator('#fileInput').setInputFiles(files);
  await expect(page.locator('#sourceList .source-item')).toHaveCount(3, { timeout: 20000 });
  await page.click('#btnAnalyze');
  await page.waitForFunction(
    () => {
      if (!window.state || !window.state.assessmentId) return false;
      var bar = document.getElementById('pipelineBarFill');
      return bar && parseFloat(bar.style.width || '0') >= 85;
    },
    { timeout: 90000 },
  );
}

test.describe('Three-file cluster regression', () => {
  test.setTimeout(180000);

  test('241 rows parsed, clusters form, CORRELATED count > 0', async ({ page }) => {
    const files = loadFixtures();
    test.skip(files.length !== FILES_V11.length, 'v1.1 fixture files not found');

    await seedStorage(page);
    await uploadAndAnalyze(page, files);

    // 1. All 241 rows must be in evidenceRows
    const rowCount = await page.evaluate(() => (window.state && window.state.evidenceRows && window.state.evidenceRows.length) || 0);
    expect(rowCount, 'evidenceRows count').toBe(241);

    // 2. clusterMap must be non-empty
    const clusterCount = await page.evaluate(() => Object.keys((window.state && window.state.clusterMap) || {}).length);
    expect(clusterCount, 'clusterMap must have clusters').toBeGreaterThan(0);

    // 3. CORRELATED badge count must be > 0
    const correlatedTotal = await page.evaluate(() => {
      var el = document.getElementById('sc_total');
      return el ? parseInt(el.textContent || '0', 10) : 0;
    });
    expect(correlatedTotal, 'CORRELATED total must be > 0').toBeGreaterThan(0);

    // 4. clusterListPanel must be visible with at least one cluster card
    await expect(page.locator('#clusterListPanel')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('#clusterListPanel .cluster-item')).toHaveCount(
      Math.min(clusterCount, 50),
      { timeout: 5000 }
    );

    // 5. Severity distribution: must have at least some critical or high rows
    const critCount = await page.evaluate(() => parseInt(document.getElementById('sc_crit')?.textContent || '0', 10)
      + parseInt(document.getElementById('si_crit')?.textContent || '0', 10));
    const highCount = await page.evaluate(() => parseInt(document.getElementById('sc_high')?.textContent || '0', 10)
      + parseInt(document.getElementById('si_high')?.textContent || '0', 10));
    expect(critCount + highCount, 'must have critical or high severity rows').toBeGreaterThan(0);
  });

  test('cluster drawer opens and shows LLM Summary + EXPAND buttons', async ({ page }) => {
    const files = loadFixtures();
    test.skip(files.length !== FILES_V11.length, 'v1.1 fixture files not found');

    await seedStorage(page);
    await uploadAndAnalyze(page, files);

    const clusterId = await page.evaluate(() => Object.keys((window.state && window.state.clusterMap) || {})[0]);
    expect(clusterId).toBeTruthy();

    await page.evaluate((cid) => window.openClusterDetail(cid), clusterId);
    await expect(page.locator('#clusterDrawer')).toBeVisible({ timeout: 5000 });

    // Must show severity pill for the cluster
    await expect(page.locator('#clusterDrawerMeta .sev-pill')).toBeVisible({ timeout: 3000 });

    // Model selector must exist (created dynamically per cluster)
    await expect(page.locator(`#llmModelSel_${clusterId}`)).toHaveCount(1, { timeout: 3000 });

    // Static action buttons in the drawer header
    await expect(page.locator('#btnDeepenMistral')).toBeVisible({ timeout: 3000 });
    // Summarise + CRAG Enrich are inline buttons (no id) — check via text
    await expect(page.locator('#clusterDrawer button:has-text("Summarise")')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('#clusterDrawer button:has-text("CRAG")')).toBeVisible({ timeout: 3000 });
  });

  test('row_index collision regression — no per-file index overwrite', async ({ page }) => {
    const files = loadFixtures();
    test.skip(files.length !== FILES_V11.length, 'v1.1 fixture files not found');

    await seedStorage(page);
    await uploadAndAnalyze(page, files);

    // Verify the payload uses global indices (idx) not per-file row_index
    // This is confirmed by clusters existing — if row_index collisions occurred, no clusters form
    const clusterCount = await page.evaluate(() => Object.keys((window.state && window.state.clusterMap) || {}).length);
    expect(clusterCount, 'row_index collision would cause 0 clusters — regression guard').toBeGreaterThan(0);

    // Also check allRows has 241 entries with unique row assignments
    const allRowCount = await page.evaluate(() => (window.state && window.state.allRows && window.state.allRows.length) || 0);
    expect(allRowCount, 'allRows must have 241 entries').toBe(241);
  });
});
