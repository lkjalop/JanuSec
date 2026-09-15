const { test, expect } = require('@playwright/test');

// Verifies the LIVE console renders the KEV status card and the resync button is clickable.
test('LIVE console shows KEV status card and resync link', async ({ page, baseURL }) => {
  // Ensure API key is present for all XHRs made by the console
  await page.addInitScript(() => {
    try { localStorage.setItem('apiKey', 'devkey123'); } catch(_) {}
  });

  const url = baseURL ? baseURL : 'http://localhost:8080';
  await page.goto(url + '/console');

  // Wait for right panel to render
  await page.waitForSelector('.right-panel', { timeout: 15000 });

  // Expect the KEV status section to be present
  const kevHeader = await page.locator('#kevStatusSection .section-title');
  await expect(kevHeader).toContainText('SBOM KEV Status');

  // Buttons and fields
  await expect(page.locator('#btnKevRefresh')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Open SBOM' })).toBeVisible();

  // Try clicking the resync; backend may return 503 in network-restricted CI, but click should not error
  await page.click('#btnKevRefresh');

  // The counters exist (may remain placeholder if backend unavailable)
  await expect(page.locator('#kevCount')).toBeVisible();
  await expect(page.locator('#kevAge')).toBeVisible();
});
