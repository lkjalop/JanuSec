import { test, expect } from '@playwright/test';

test('debug csv file input wiring', async ({ page }) => {
  await page.goto('/static/csv_analyzer.html');
  // ensure the page loaded
  await expect(page.locator('#csv_title')).toHaveText(/CSV Analyzer/i);

  const csvContent = 'header1,header2\nprocDBG,/opt/dbg.txt\n';
  await page.setInputFiles('[data-test="csv-file-input"]', { name: 'dbg.csv', mimeType: 'text/csv', buffer: Buffer.from(csvContent) });

  // inspect file input file count from the page
  const filesCount = await page.evaluate(() => {
    const inp = document.getElementById('fileInput');
    try { return inp && inp.files && inp.files.length || 0; } catch(e){ return 'err:' + e.message; }
  });

  console.log('DEBUG: fileInput.files.length =', filesCount);

  // click load and wait briefly, then inspect LAST_RESULTS and csv_results_ready display
  await page.click('[data-test="csv-btn-load"]');
  // wait a little for FileReader to process
  await page.waitForTimeout(400);

  const lastResults = await page.evaluate(() => {
    try{ return { lastResults: window.LAST_RESULTS || null, readyDisplay: document.getElementById('csv_results_ready').style.display || '' }; }catch(e){ return { err: e.message }; }
  });

  console.log('DEBUG: window.LAST_RESULTS =', JSON.stringify(lastResults));

  expect(filesCount).toBeGreaterThan(0);
  expect(lastResults && lastResults.lastResults).not.toBeNull();
  expect(lastResults && lastResults.readyDisplay).toBe('block');
});
