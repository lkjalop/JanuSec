import { test, expect } from '@playwright/test';
import path from 'path';

// Adjust baseURL in Playwright config if needed. This test assumes the dev server
// serves static files at http://localhost:8080 and the API at the same host.

test('CSV analyzer end-to-end shows HopGraph Top-5', async ({ page }) => {
  const csvPath = path.join(__dirname, '..', 'fixtures', 'sample_upload.csv');
  // Navigate to static CSV analyzer page
  await page.goto('http://localhost:8080/static/csv_analyzer.html');
  // Wait for page to load file input
  const fileInput = await page.waitForSelector('input[type=file]#csv-upload', { timeout: 5000 });
  // Set file (Playwright requires the input to be attached to the page)
  await fileInput.setInputFiles(csvPath);
  // Wait for upload/enrichment to finish: expect a results table row
  await page.waitForSelector('.csv-results-row', { timeout: 10000 });
  // Click the first Details button
  await page.click('.csv-results-row:first-child .details-button');
  // Wait for right-side HopGraph panel to appear
  const panel = await page.waitForSelector('#hopgraph-panel', { timeout: 5000 });
  expect(await panel.isVisible()).toBeTruthy();
  // Toggle Top-5
  await page.click('#hopgraph-panel .topk-toggle[data-topk="5"]');
  // Ensure the top-k list loaded
  const list = await page.waitForSelector('#hopgraph-panel .topk-list .topk-item', { timeout: 5000 });
  const items = await page.$$('#hopgraph-panel .topk-list .topk-item');
  expect(items.length).toBeGreaterThanOrEqual(1);
});
