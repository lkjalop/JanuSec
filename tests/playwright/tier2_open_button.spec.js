/**
 * "Open Tier 2" button test
 *
 * Uploads three v1.1 fixture files, analyzes, opens a cluster drawer,
 * clicks "Open Tier 2", and asserts the popup URL contains the required params.
 *
 * Requires server on port 8080.
 */
const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

const BASE     = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:8080';
const DUMP_DIR = path.resolve(__dirname, '../../dump/test files');
const FILES_V11 = [
  { file: 'janusec_net_c2_bgp.v1.1.csv',          mime: 'text/csv' },
  { file: 'janusec_ep_endpoint.v1.1.xlsx',          mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' },
  { file: 'janusec_okta_m365_events.v1.1.json',    mime: 'application/json' },
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

test.describe('Open Tier 2 button', () => {
  test.setTimeout(180000);

  test('clicking Open Tier 2 opens popup with correct URL params', async ({ page, context }) => {
    const files = loadFixtures();
    test.skip(files.length !== FILES_V11.length, 'v1.1 fixture files not found in dump/test files/');

    await seedStorage(page);
    await uploadAndAnalyze(page, files);

    // Get first cluster
    const cluster = await page.evaluate(() => {
      const ids = Object.keys((window.state && window.state.clusterMap) || {});
      return { assessmentId: window.state && window.state.assessmentId, clusterId: ids[0] };
    });
    expect(cluster.clusterId).toBeTruthy();
    expect(cluster.assessmentId).toBeTruthy();

    // Open cluster drawer
    await page.evaluate(({ cid }) => window.openClusterDetail(cid), { cid: cluster.clusterId });
    await expect(page.locator('#clusterDrawer')).toBeVisible({ timeout: 5000 });

    // Intercept the new popup page
    const [popup] = await Promise.all([
      context.waitForEvent('page', { timeout: 15000 }),
      page.evaluate(({ cid }) => window.openTier2Canvas(cid), { cid: cluster.clusterId }),
    ]);

    // Assert popup URL contains all required params
    const popupUrl = popup.url();
    expect(popupUrl).toContain('assessment_id=');
    expect(popupUrl).toContain('cluster_id=');
    expect(popupUrl).toContain('persona=');
    expect(popupUrl).toContain('llm_model=');

    // Verify param values are not empty
    const url = new URL(popupUrl);
    expect(url.searchParams.get('assessment_id')).toBeTruthy();
    expect(url.searchParams.get('cluster_id')).toBeTruthy();
    expect(url.searchParams.get('persona')).toBeTruthy();
    expect(url.searchParams.get('llm_model')).toBeTruthy();

    // assessment_id must match what we uploaded
    expect(url.searchParams.get('assessment_id')).toBe(cluster.assessmentId);
    expect(url.searchParams.get('cluster_id')).toBe(cluster.clusterId);

    await popup.close();
  });
});
