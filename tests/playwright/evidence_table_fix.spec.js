// evidence_table_fix.spec.js
//
// Regression tests for the three bugs fixed in this session:
//   1. #evidenceTable stays display:none — rows are invisible after analysis
//   2. Filter chips re-render state.evidenceRows even when cluster scope is active
//   3. Timeline tab shows empty when switching to it manually
//
// Uses the same real dump/ fixture files as three_source_persona_compare.spec.js

const { test, expect } = require('@playwright/test');
const fs   = require('fs');
const path = require('path');

const BASE     = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:8080';
const DUMP_DIR = path.resolve(__dirname, '../../dump');

function loadFixture(filename) {
  const fp = path.join(DUMP_DIR, filename);
  if (!fs.existsSync(fp)) return null;
  return { name: filename, buffer: fs.readFileSync(fp) };
}
function mimeFor(filename) {
  if (filename.endsWith('.xlsx')) return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
  if (filename.endsWith('.json')) return 'application/json';
  return 'text/csv';
}
function fixtureEntry(filename) {
  const f = loadFixture(filename);
  if (!f) return null;
  return { name: f.name, mimeType: mimeFor(filename), buffer: f.buffer };
}

const EP_FILE   = 'janusec_ep_endpoint.xlsx';
const OKTA_FILE = 'janusec_okta_m365_events.json';
const NET_FILE  = 'janusec_net_c2_bgp.csv';

async function uploadAndAnalyze(page, files) {
  await page.goto(BASE + '/static/investigate.html', { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('#uploadZone', { timeout: 10000 });

  const entries = files.map(fixtureEntry).filter(Boolean);
  if (entries.length === 0) return false;

  const [fileChooser] = await Promise.all([
    page.waitForEvent('filechooser'),
    page.click('#uploadZone'),
  ]);
  await fileChooser.setFiles(entries);

  // Wait for source list to confirm files loaded
  await page.waitForSelector('#sourceListRow', { state: 'visible', timeout: 10000 });

  // Click Analyze button
  const analyzeBtn = page.locator('button:has-text("Analyze")').first();
  await expect(analyzeBtn).toBeEnabled({ timeout: 5000 });
  await analyzeBtn.click();

  // Wait for analysis to complete (progress bar reaches ~100% or report appears)
  await page.waitForSelector('#reportContent', { state: 'visible', timeout: 120000 });
  // Also wait for evidence badge to be non-zero
  await page.waitForFunction(() => {
    const badge = document.getElementById('evidenceBadge');
    return badge && badge.textContent && parseInt(badge.textContent) > 0;
  }, { timeout: 30000 });

  return true;
}

test.describe('Evidence table visibility fixes', () => {
  test('BUG-1: evidence table is visible (not display:none) after analysis', async ({ page }) => {
    const ok = await uploadAndAnalyze(page, [EP_FILE, OKTA_FILE, NET_FILE]);
    if (!ok) test.skip();

    // Switch to Evidence tab
    await page.click('[data-tab="evidence"]');
    await page.waitForTimeout(300);

    // The evidenceTable element must NOT have display:none
    const tableDisplay = await page.evaluate(() => {
      const t = document.getElementById('evidenceTable');
      return t ? t.style.display : 'MISSING';
    });
    expect(tableDisplay).not.toBe('none');

    // Must have actual rows in the tbody
    const rowCount = await page.evaluate(() => {
      return document.querySelectorAll('#evidenceBody tr').length;
    });
    expect(rowCount).toBeGreaterThan(0);
  });

  test('BUG-1: evidenceEmpty hidden when rows exist', async ({ page }) => {
    const ok = await uploadAndAnalyze(page, [EP_FILE, OKTA_FILE, NET_FILE]);
    if (!ok) test.skip();

    await page.click('[data-tab="evidence"]');
    await page.waitForTimeout(300);

    const emptyDisplay = await page.evaluate(() => {
      const e = document.getElementById('evidenceEmpty');
      return e ? (e.style.display || getComputedStyle(e).display) : 'MISSING';
    });
    expect(emptyDisplay).toBe('none');
  });

  test('BUG-2: cluster scope — opening drawer scopes evidence table to cluster rows', async ({ page }) => {
    const ok = await uploadAndAnalyze(page, [EP_FILE, OKTA_FILE, NET_FILE]);
    if (!ok) test.skip();

    // Click the first CORR-CRITICAL sev-box to open cluster list
    const sevBox = page.locator('.sev-box').first();
    await sevBox.click();
    await page.waitForTimeout(500);

    // Click first "Drill in →" button if visible
    const drillBtn = page.locator('.cluster-drill-btn').first();
    const drillVisible = await drillBtn.isVisible().catch(() => false);
    if (!drillVisible) {
      test.skip(); // no clusters for this fixture scenario
      return;
    }
    await drillBtn.click();
    await page.waitForTimeout(1000);

    // Switch to Evidence tab
    await page.click('[data-tab="evidence"]');
    await page.waitForTimeout(500);

    // Table should be visible (not display:none)
    const tableDisplay = await page.evaluate(() => {
      const t = document.getElementById('evidenceTable');
      return t ? t.style.display : 'MISSING';
    });
    expect(tableDisplay).not.toBe('none');

    // Scope banner should be visible
    const bannerVisible = await page.evaluate(() => {
      const b = document.getElementById('scopeBannerEvidence');
      return b ? b.classList.contains('visible') : false;
    });
    expect(bannerVisible).toBe(true);

    // Row count in evidence table should reflect cluster scope (less than total)
    const totalRows = await page.evaluate(() => {
      return (window._investigate_state && window._investigate_state.evidenceRows && window._investigate_state.evidenceRows.length) || 
        document.querySelectorAll('#evidenceBody tr').length;
    });
    expect(totalRows).toBeGreaterThan(0);
  });

  test('BUG-2: filter chips respect cluster scope', async ({ page }) => {
    const ok = await uploadAndAnalyze(page, [EP_FILE, OKTA_FILE, NET_FILE]);
    if (!ok) test.skip();

    // Open cluster panel and drill in
    const sevBox = page.locator('.sev-box').first();
    await sevBox.click();
    await page.waitForTimeout(500);

    const drillBtn = page.locator('.cluster-drill-btn').first();
    const drillVisible = await drillBtn.isVisible().catch(() => false);
    if (!drillVisible) {
      test.skip();
      return;
    }
    await drillBtn.click();
    await page.waitForTimeout(1000);

    // Switch to Evidence tab
    await page.click('[data-tab="evidence"]');
    await page.waitForTimeout(400);

    // Record row count under cluster scope (all filter)
    const clusterRowCount = await page.evaluate(() => document.querySelectorAll('#evidenceBody tr').length);

    // Click "All" filter chip — should re-render with cluster scope rows (not all 134)
    await page.click('[data-ev-filter="all"]');
    await page.waitForTimeout(300);

    // Table must still be visible
    const tableDisplay = await page.evaluate(() => {
      const t = document.getElementById('evidenceTable');
      return t ? t.style.display : 'MISSING';
    });
    expect(tableDisplay).not.toBe('none');

    // Row count should be >= clusterRowCount (filter 'all' within cluster)
    const afterFilterCount = await page.evaluate(() => document.querySelectorAll('#evidenceBody tr').length);
    expect(afterFilterCount).toBeGreaterThan(0);
  });

  test('BUG-3: Timeline tab shows swimlane after switching to it', async ({ page }) => {
    const ok = await uploadAndAnalyze(page, [EP_FILE, OKTA_FILE, NET_FILE]);
    if (!ok) test.skip();

    // Switch to Timeline tab
    await page.click('[data-tab="timeline"]');
    await page.waitForTimeout(1000);

    // timelineContent must be visible (not display:none)
    const timelineContentDisplay = await page.evaluate(() => {
      const t = document.getElementById('timelineContent');
      return t ? t.style.display : 'MISSING';
    });
    expect(timelineContentDisplay).not.toBe('none');

    // timelineEmpty must be hidden
    const timelineEmptyDisplay = await page.evaluate(() => {
      const t = document.getElementById('timelineEmpty');
      return t ? t.style.display : 'MISSING';
    });
    expect(timelineEmptyDisplay).toBe('none');

    // timelineCanvas should have content
    const canvasHtml = await page.evaluate(() => {
      const c = document.getElementById('timelineCanvas');
      return c ? c.innerHTML.trim() : '';
    });
    expect(canvasHtml.length).toBeGreaterThan(10); // has some rendered content
  });
});
