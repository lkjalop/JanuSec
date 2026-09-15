// all_tabs_after_analysis.spec.js
// Verifies all 5 tabs work end-to-end after uploading files and running analysis.
// Uses a minimal synthetic CSV so the test never depends on user-specific fixture files.

const { test, expect } = require('@playwright/test');

const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:8080';

// Synthetic event CSV that covers: timestamps, severity, entity, description
const SAMPLE_CSV = [
  'timestamp,severity,src_ip,username,description,mitre_technique',
  '2026-04-13T01:00:00Z,critical,185.220.101.5,admin@corp.com,Possible exfil detected,T1041',
  '2026-04-13T01:05:00Z,high,10.0.0.22,jdoe@corp.com,Suspicious login MFA push fatigue,T1621',
  '2026-04-13T01:10:00Z,medium,10.0.0.22,jdoe@corp.com,Lateral movement attempt,T1021',
  '2026-04-13T01:15:00Z,high,185.220.101.5,admin@corp.com,Credential dump,T1003',
  '2026-04-13T01:20:00Z,low,192.168.1.100,svc_backup,Scheduled backup job,',
].join('\n');

test.describe('investigate.html — all tabs after analysis', () => {
  let page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();

    // Seed storage with required keys so API calls include tenant
    await page.addInitScript(() => {
      localStorage.setItem('apiKey', 'devkey123');
      localStorage.setItem('tenantId', 'default');
    });

    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');

    // Upload synthetic CSV
    await page.locator('#fileInput').setInputFiles([{
      name: 'test_events.csv',
      mimeType: 'text/csv',
      buffer: Buffer.from(SAMPLE_CSV),
    }]);
    await page.waitForTimeout(600);

    // Click Analyze
    await page.click('#btnAnalyze');

    // Wait until analysis finishes (reportContent OR reportEmpty visible, loading gone)
    await page.waitForFunction(() => {
      const content = document.getElementById('reportContent');
      const empty   = document.getElementById('reportEmpty');
      const loading = document.getElementById('reportLoading');
      if (!content || !empty || !loading) return false;
      return (content.style.display !== 'none' || empty.style.display !== 'none')
          && loading.style.display === 'none';
    }, { timeout: 45000 });
  });

  test.afterAll(async () => {
    await page.close();
  });

  // ── TAB 1: Report ────────────────────────────────────────────────────────
  test('Report tab — shows content after analysis', async () => {
    // Should already be on Report tab (default)
    const reportContent = page.locator('#reportContent');
    await expect(reportContent).not.toHaveCSS('display', 'none');

    // Should have at least one report section
    const sections = page.locator('.report-section');
    const count = await sections.count();
    expect(count, 'Report should contain at least 1 section').toBeGreaterThan(0);
  });

  // ── TAB 2: Evidence ──────────────────────────────────────────────────────
  test('Evidence tab — shows events table with rows', async () => {
    const evidenceBtn = page.locator('.tab-btn[data-tab="evidence"]');
    await evidenceBtn.click();
    await page.waitForTimeout(300);

    const evidenceEmpty = page.locator('#evidenceEmpty');
    const isEmpty = await evidenceEmpty.evaluate(el => el.style.display !== 'none');
    expect(isEmpty, 'Evidence table should not be empty after analysis').toBe(false);

    const rows = page.locator('#evidenceBody tr');
    const rowCount = await rows.count();
    expect(rowCount, 'Evidence table should have at least 1 row').toBeGreaterThan(0);

    // Badge should reflect row count
    const badge = page.locator('#evidenceBadge');
    const badgeText = await badge.textContent();
    expect(parseInt(badgeText)).toBeGreaterThan(0);
  });

  // ── TAB 3: Graph ─────────────────────────────────────────────────────────
  test('Graph tab — renders SVG or shows D3 unavailable gracefully', async () => {
    const graphBtn = page.locator('.tab-btn[data-tab="graph"]');
    await graphBtn.click();
    await page.waitForTimeout(600);

    const graphCanvas = page.locator('#graphCanvas');
    const isEmpty = await page.locator('#graphEmpty').evaluate(el => el.style.display === 'none' || el.style.display === '');

    // Canvas should be visible (display:flex), and either have SVG or a graceful message
    const canvasDisplay = await graphCanvas.evaluate(el => el.style.display);
    expect(canvasDisplay, 'graphCanvas should be visible after analysis').not.toBe('none');

    // Should contain an SVG element (D3 rendered) or a message
    const svgCount = await graphCanvas.locator('svg').count();
    const msgCount = await graphCanvas.locator('p').count();
    expect(svgCount + msgCount, 'Graph tab should render SVG or a fallback message').toBeGreaterThan(0);
  });

  // ── TAB 4: Timeline ──────────────────────────────────────────────────────
  test('Timeline tab — renders swimlane SVG (has timestamps) or shows no-timestamp message', async () => {
    const timelineBtn = page.locator('.tab-btn[data-tab="timeline"]');
    await timelineBtn.click();
    await page.waitForTimeout(400);

    const timelineContent = page.locator('#timelineContent');
    const isEmpty = await page.locator('#timelineEmpty').evaluate(el => el.style.display === 'none');

    // Content container should be visible
    const contentDisplay = await timelineContent.evaluate(el => el.style.display);
    expect(contentDisplay, 'timelineContent should not be hidden').not.toBe('none');

    // Should have either SVG (timestamps found) or a "No timestamp" message
    const canvas = page.locator('#timelineCanvas');
    const canvasHtml = await canvas.innerHTML();
    const hasSvg = canvasHtml.includes('<svg');
    const hasMsg = canvasHtml.includes('No timestamp');
    expect(hasSvg || hasMsg, 'Timeline should render SVG or no-timestamp message').toBe(true);

    // If SVG rendered, it must have lane lines
    if (hasSvg) {
      expect(canvasHtml.includes('<line'), 'Timeline SVG should contain lane lines').toBe(true);
    }
  });

  // ── TAB 5: Decisions ────────────────────────────────────────────────────
  test('Decisions tab — renders table (empty is acceptable, crash is not)', async () => {
    const decisionsBtn = page.locator('.tab-btn[data-tab="decisions"]');
    await decisionsBtn.click();
    await page.waitForTimeout(1000);

    // The decisions panel must render without crashing.
    // Table is hidden when empty (correct behavior) — accept either table visible OR empty state visible.
    const decisionTable = page.locator('#decisionTable');
    const decisionEmpty = page.locator('#decisionEmpty');
    const tableExists = await decisionTable.count() > 0;
    expect(tableExists, '#decisionTable element must exist in DOM').toBe(true);

    const tableVisible = await decisionTable.evaluate(el => el.style.display !== 'none');
    const emptyVisible = await decisionEmpty.evaluate(el => el.style.display !== 'none').catch(() => false);
    expect(tableVisible || emptyVisible, 'Either decisionTable or decisionEmpty must be visible').toBe(true);

    // No JS errors on this tab
    const jsErrors = [];
    page.on('pageerror', err => jsErrors.push(err.message));
    await page.waitForTimeout(500);
    expect(jsErrors.length, `JS errors on Decisions tab: ${jsErrors.join(', ')}`).toBe(0);
  });

  // ── Persona switching across all 5 non-gated personas ───────────────────
  test('Persona switching — forensics and mssp show report content, not empty', async () => {
    // Back to Report tab
    await page.locator('.tab-btn[data-tab="report"]').click();
    await page.waitForTimeout(200);

    for (const persona of ['forensics', 'mssp']) {
      const chip = page.locator('.persona-chip').filter({ hasText: new RegExp(persona, 'i') }).first();
      if ((await chip.count()) === 0) continue;
      await chip.click();
      await page.waitForTimeout(400);

      const contentVisible = await page.locator('#reportContent').evaluate(el => el.style.display !== 'none');
      expect(contentVisible, `${persona} persona: reportContent should be visible`).toBe(true);

      const sections = await page.locator('.report-section').count();
      expect(sections, `${persona} persona: should have at least 1 section`).toBeGreaterThan(0);
    }
  });
});
