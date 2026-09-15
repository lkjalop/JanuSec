// Production CSV Analyzer smoke test (non-shim)
// Ensures the dark themed page loads and core interactive elements exist.
// Does NOT assert deterministic enrichment specifics used by shim tests.
// Guard: skip if PLAYWRIGHT_USE_TEST_SHIM=1 to avoid conflicting environments.

import { test, expect } from '@playwright/test';

const USE_SHIM = process.env.PLAYWRIGHT_USE_TEST_SHIM === '1';

test.describe('CSV Analyzer Production Page', () => {
  test.skip(USE_SHIM, 'Skipping production CSV analyzer smoke when shim env active');

  test('loads page and renders controls', async ({ page }) => {
    await page.goto('/static/csv_analyzer.html');
    await expect(page.locator('#csv_title')).toHaveText(/CSV Analyzer/i);
    await expect(page.locator('[data-test="csv-file-input"]')).toBeVisible();
    await expect(page.locator('[data-test="csv-btn-load"]')).toBeVisible();
    await expect(page.locator('[data-test="csv-btn-explain"]')).toBeVisible();
    await expect(page.locator('[data-test="csv-btn-deep-analyze"]')).toBeVisible();
    // No rows yet
    await expect(page.locator('#tbody')).toContainText(/No rows|No results/);
  });

  test('uploads small CSV and produces a row', async ({ page }) => {
    await page.goto('/static/csv_analyzer.html');
    const csvContent = 'header1,header2\nprocA,/opt/a.txt\n';
    await page.setInputFiles('[data-test="csv-file-input"]', { name: 'sample.csv', mimeType: 'text/csv', buffer: Buffer.from(csvContent) });
    await page.click('[data-test="csv-btn-load"]');
    // Wait for the ready marker to be attached to the DOM (less brittle than visible)
    await page.waitForSelector('#csv_results_ready', { state: 'attached', timeout: 5000 });
    // Then wait for the first data row to appear and contain expected text
    const firstCell = page.locator('#tbody tr:first-child td[data-col="process_name"]');
    await firstCell.waitFor({ state: 'visible', timeout: 3000 }).catch(()=>{});
    // Fallback: poll for the cell text if it's not yet visible
    await page.waitForFunction(() => {
      try{ const td = document.querySelector('#tbody tr:first-child td:first-child'); return !!(td && td.innerText && td.innerText.trim().length>0); }catch(e){ return false; }
    }, { timeout: 3000 });
    await expect(firstCell).toHaveText(/procA|unknown/);
  });

  test('deep analyze enriches first row', async ({ page }) => {
    await page.goto('/static/csv_analyzer.html');
    const csvContent = 'h1,h2\nprocDeep,/opt/deep.txt\n';
    await page.setInputFiles('[data-test="csv-file-input"]', { name: 'sample.csv', mimeType: 'text/csv', buffer: Buffer.from(csvContent) });
    await page.click('[data-test="csv-btn-load"]');
    await page.waitForSelector('#csv_results_ready', { state: 'attached', timeout: 5000 });
    // Trigger deep analyze
    await page.click('[data-test="csv-btn-deep-analyze"]');
    // Open details of row 0
    await page.click('#tbody tr:first-child button[title="Why flagged / details"]');
    // Expect details body to include a known section from full details render
    await expect(page.locator('#csvDrillBody')).toContainText(/Raw row preview|DREAD|Signals/i);
  });
});
