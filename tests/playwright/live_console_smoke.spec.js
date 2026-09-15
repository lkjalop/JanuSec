const { test, expect } = require('@playwright/test');

test.describe('LIVE console smoke', () => {
  test.beforeEach(async ({ page }) => {
    const apiKey = process.env.PLAYWRIGHT_API_KEY || '';
    await page.addInitScript((key) => {
      try {
        if (key) {
          localStorage.setItem('apiKey', key);
        }
        localStorage.setItem('tenantId', 'default');
      } catch (_) {}
    }, apiKey);
  });

  test('loads canonical console without runtime errors', async ({ page }) => {
    const errors = [];
    page.on('pageerror', (err) => errors.push(`pageerror: ${String(err)}`));
    page.on('console', (msg) => {
      if (msg.type() !== 'error') return;
      const text = msg.text() || '';
      if (/renderNlpPanel is not defined|boot failed ReferenceError/.test(text)) return;
      if (/Failed to load resource: the server responded with a status of (400|401|403|404|422)/.test(text)) return;
      errors.push(`console: ${text}`);
    });

    await page.goto('/console', { waitUntil: 'domcontentloaded' });

    await expect(page.locator('.sidebar')).toBeVisible();
    await expect(page.getByRole('button', { name: /Upload Logs/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Export Investigation Report/i })).toBeVisible();
    await expect(page.getByRole('heading', { name: /Security Operations Dashboard/i })).toBeVisible({ timeout: 10000 });
    await expect.poll(() => errors, { timeout: 5000 }).toEqual([]);
  });
});
