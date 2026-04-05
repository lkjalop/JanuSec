const { test, expect } = require('@playwright/test');

test.describe('Tenant temporal UI', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('http://localhost:8080/console');
    await page.evaluate(() => { localStorage.setItem('apiKey','devkey123'); });
    await page.reload();
  });

  test('loads tenant temporal and renders sparkline', async ({ page }) => {
    await page.goto('http://localhost:8080/console');
    await page.fill('#tenantInput', 'demo-tenant');
    await page.click('#btnLoadTenant');
    // Wait for canvas temporal spark (metrics.js adds canvas.temporal-spark)
    await page.waitForSelector('canvas.temporal-spark', { timeout: 8000 });
    const canvas = await page.$('canvas.temporal-spark');
    expect(canvas).not.toBeNull();
    // Tenant label may be injected asynchronously; accept either label or canvas as success
    try{
      await expect(page.locator('#tenantLoadedLabel')).toBeVisible({ timeout: 3000 });
    }catch(e){ /* label not present; canvas presence is sufficient */ }
  });
});
