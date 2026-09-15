import { test, expect } from '@playwright/test';

test('backfill start and per-row cancel updates UI', async ({ page }) => {
  // Assumes the dev server is serving the static UI at http://localhost:8080
  await page.goto('http://localhost:8080/static/csv_analyzer.html');
  // Pretend an assessment id is present in localStorage
  await page.evaluate(() => { localStorage.setItem('csv_last_parent_assessment', 'e2e-assess-1'); localStorage.setItem('apiKey','devkey123'); });
  // Start the backfill via ribbon button
  const startBtn = await page.locator('#deepBackfillToggleGlobal');
  await expect(startBtn).toBeVisible();
  await startBtn.click();
  // Wait for ribbon to show running state
  await page.waitForSelector('#deepBackfillState:text("running")', { timeout: 5000 });
  // Render a synthetic table row so the per-row cancel button is present
  await page.evaluate(() => {
    window.LAST_RESULTS = [{ row_index: 0, process_name: 'p', file_path: '/f', sha256:'dead', host:'h', verdict:'SUSPICIOUS', factors:[], _dread:{score:5} }];
    window.ensureTbodyRowsFromList(window.LAST_RESULTS);
  });
  await page.waitForSelector('button.row-cancel-btn', { timeout: 2000 });
  // Click per-row cancel which should open confirm modal
  await page.click('button.row-cancel-btn');
  await page.waitForSelector('#cancelConfirmModal', { state: 'visible' });
  await page.click('#cancelConfirmYes');
  // After confirm, the button text should become 'Requested'
  await expect(page.locator('button.row-cancel-btn')).toHaveText('Requested');
});
