// Simple smoke test to verify mapping presets apply sensible defaults
const { test, expect } = require('@playwright/test');

test('csv_multi_analyzer preset maps sha256 to file_hash', async ({ page }) => {
  page.on('pageerror', err => console.log('PAGEERROR', err.message));
  page.on('console', msg => { if (msg.type() === 'error') console.log('CONSOLE', msg.text()); });
  await page.goto('http://localhost:8080/static/csv_multi_analyzer.html');

  await page.setInputFiles('#fileInput', 'tests/playwright/fixtures/test_row.csv');
  await page.evaluate(() => { try { window.__forceCsvMultiMapping && window.__forceCsvMultiMapping(); } catch(e) {} });

  // Apply EDR preset
  await page.selectOption('#presetSelect', 'edr');
  await page.click('#btnApplyPreset');

  // Verify mapping selects were created and sha256 maps to file_hash
  const selSha = page.locator('select[data-col="sha256"]');
  await expect(selSha).toHaveValue('file_hash');

  const selHost = page.locator('select[data-col="host"]');
  await expect(selHost).toHaveValue('host');
});
