import { test, expect } from '@playwright/test';
import path from 'path';

test('mapping modal appears after upload when enabled', async ({ page }) => {
  // Serve the local LIVE console root
  await page.goto('http://localhost:8080/');
  // enable the offer setting in localStorage
  await page.evaluate(() => { localStorage.setItem('offerMappingOnUploadConfirm','1'); localStorage.setItem('lastTenant','test-tenant'); });
  // navigate to csv analyzer page
  await page.goto('http://localhost:8080/static/csv_multi_analyzer.html');
  const filePath = path.resolve(__dirname, '..', 'fixtures', 'sample_upload.csv');
  const input = await page.waitForSelector('#fileInput');
  await input.setInputFiles(filePath);
  // wait for modal to appear
  const modal = await page.waitForSelector('#mappingSaveModal', { state: 'visible', timeout: 5000 });
  expect(modal).toBeTruthy();
  // cleanup localStorage
  await page.evaluate(() => { localStorage.removeItem('offerMappingOnUploadConfirm'); localStorage.removeItem('lastTenant'); });
});

// NOTE: This is a smoke/integration test scaffold. It assumes a local server
// is running at http://localhost:8080 and that the LIVE console is available.

test('open mapping modal, preview and save preset', async ({ page }) => {
  await page.goto('http://localhost:8080/static/csv_multi_analyzer.html');
  // wait for mapping panel to be ready
  await page.waitForSelector('#btnSavePreset');
  // Click Save Preset to open modal
  await page.click('#btnSavePreset');
  await page.fill('#modalTenant', 'test-tenant');
  const suggested = await page.$eval('#modalName', el => (el as HTMLInputElement).value);
  // Click preview (server) - note: backend must be running and ingest_rows endpoint present
  await page.click('#modalPreview');
  // Wait for preview area to populate
  await page.waitForSelector('#modalPreviewArea .table, #modalPreviewArea:has-text("No preview results")', { timeout: 5000 });
  // Save preset
  await page.click('#modalSave');
  // Modal should close
  await expect(page.locator('#saveModal')).toBeHidden({ timeout: 3000 });
});
