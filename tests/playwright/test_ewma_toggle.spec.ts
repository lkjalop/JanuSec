import { test, expect } from '@playwright/test';

// Validates Adaptive EWMA toggle behavior and summary chips update in CSV Multi-Analyzer
// Assumes dev key 'devkey123' and local server at http://localhost:8080

test.describe('CSV EWMA toggles', () => {
  test.beforeEach(async ({ context }) => {
    // Pre-set API key and tenant to avoid auth banners
    await context.addInitScript(() => {
      try {
        localStorage.setItem('apiKey', 'devkey123');
        localStorage.setItem('tenantId', 'demo-tenant');
      } catch {}
    });
  });

  test('Adaptive on/off affects EWMA chips after build', async ({ page }) => {
    await page.goto('http://localhost:8080/static/csv_multi_analyzer.html');

    // Ensure controls are present
    const ewmaChk = page.locator('#chkEWMA');
    const adaptiveChk = page.locator('#chkAdaptiveEWMA');
    const alphaInput = page.locator('#ewmaAlpha');
    const buildBtn = page.locator('#btnBuildGraph');

    await expect(ewmaChk).toBeVisible();
    await expect(adaptiveChk).toBeVisible();
    await expect(alphaInput).toBeVisible();

    // Upload a tiny CSV inline via JS (simulate parsedRows) by creating a Blob URL and triggering file input
    const content = 'user,host,domain\nalice,host1,example.com\nbob,host2,example.org';
    const buffer = Buffer.from(content, 'utf-8');
    await page.setInputFiles('#fileInput', { name: 'mini.csv', mimeType: 'text/csv', buffer });

    // Wait until Build is enabled
    await expect(buildBtn).toBeEnabled();

    // Case 1: Adaptive ON (default ON), expect EWMA alpha chip to show 'auto' or server-provided value; Adaptive chip 'on'
    await ewmaChk.check();
    await adaptiveChk.check();
    await buildBtn.click();

    const chipAlpha = page.locator('#csvChipEwmaAlpha');
    const chipAdaptive = page.locator('#csvChipEwmaAdaptive');

    await expect(chipAdaptive).toContainText(/Adaptive:\s*on/i);
    await expect(chipAlpha).toContainText(/EWMA\s*α:/i);

    // Case 2: Adaptive OFF, set alpha to 0.3 and rebuild; expect chips reflect alpha and Adaptive off
    await adaptiveChk.uncheck();
    await alphaInput.fill('0.3');
    await page.click('#btnRebuildEwma');

    await expect(chipAdaptive).toContainText(/Adaptive:\s*off/i);
    await expect(chipAlpha).toContainText(/0\.3/);

    // HopGraph link should be enabled (session built)
    const hopLink = page.locator('#csvChipHopGraph');
    await expect(hopLink).toHaveAttribute('href', /graph_explain\.html\?session_id=/);
  });
});
