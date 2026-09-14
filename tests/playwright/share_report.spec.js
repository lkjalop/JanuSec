const { test, expect } = require('@playwright/test');
const path = require('path');

test('CSV Analyzer: generate report and share upload', async ({ page }) => {
  const filePath = path.resolve(__dirname, '../../dump/fixture_simple.csv');
  await page.goto('http://localhost:8080/static/csv_analyzer.html');
  await page.setInputFiles('#fileInput', filePath);
  await page.locator('#btnLoad').click();
  await page.waitForSelector('#tbody tr[data-row]', { timeout: 10000 });
  // Generate report
  await page.locator('#btnExportReport').click();
  await page.context().waitForEvent('page', { timeout: 20000 }).catch(()=>{});
  // Click Share
  await page.locator('#btnShareReport').click();
  await page.fill('#shareTarget', 'test@example.com');
  await page.selectOption('#shareChannel', 'email');
  await page.click('#shareSend');
  // Expect upload endpoint to accept and return JSON
  await page.waitForResponse(resp => resp.url().endsWith('/api/v1/report/upload') && resp.status() === 200, { timeout: 10000 });
});
