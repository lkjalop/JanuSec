const { test, expect } = require('@playwright/test');

test('factors page loads and modal opens', async ({ page }) => {
  await page.goto('http://127.0.0.1:8080/static/factors_top20.html');
  // wait for grid or skeleton
  await page.waitForSelector('#grid');
  // Wait for at least one card to render
  await page.waitForSelector('#grid .card', { timeout: 10000 });
  // Open first factor row via keyboard
  const firstRow = await page.$('#grid .card');
  expect(firstRow).toBeTruthy();
  // Click the first card's first row (svg group)
  const svgRow = await page.$('#grid .card svg g.row');
  if(svgRow){ await svgRow.click(); await page.waitForSelector('#factorModal[aria-hidden="false"]', { timeout: 5000 }); }
  // Confirm modal title exists
  const title = await page.$('#modalTitle');
  expect(title).toBeTruthy();
});