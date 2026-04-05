import { test, expect } from '@playwright/test';
import path from 'path';

// This test requires the demo server to be running at http://localhost:8080
// Run: npx playwright test tests/playwright/csv_analyzer.spec.ts

test('CSV Analyzer: load XLSX and open suspicious details', async ({ page }) => {
  const filePath = path.resolve(__dirname, '../../../dump/Cyberstash_csv2.xlsx');
  await page.goto('http://localhost:8080/static/csv_analyzer.html');
  // attach file
  const fileInput = await page.locator('input[type=file]#fileInput');
  await expect(fileInput).toBeVisible();
  await fileInput.setInputFiles(filePath);
  // click load
  await page.locator('#btnLoad').click();
  // wait for results-ready
  await page.waitForSelector('#csv_results_ready', { state: 'visible', timeout: 15000 });
  // click suspicious filter
  await page.locator('#btnFilterSuspicious').click();
  // wait for table rows to appear (excluding the initial empty hint)
  await page.waitForSelector('#tbody tr[data-row]', { timeout: 15000 });
  // click first visible Details button
  const detailsBtn = page.locator('#tbody tr[data-row] button[title="Why flagged / details"]').first();
  if(await detailsBtn.count() === 0){
    // fallback: try any Details button
    await page.locator('#tbody tr[data-row] .btn').first().click();
  } else {
    await detailsBtn.click();
  }
  // ensure inline details row inserted
  await expect(page.locator('#tbody tr.csv-inline-details')).toHaveCount(1);
});
