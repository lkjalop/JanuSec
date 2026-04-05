import { test, expect } from '@playwright/test';

test.describe('Tenant temporal UI', () => {
  test.beforeEach(async ({ page }) => {
    // set dev api key in localStorage
    await page.goto('http://localhost:8080/console');
    await page.evaluate(() => { localStorage.setItem('apiKey','devkey123'); });
    await page.reload();
  });

  test('loads tenant temporal and renders sparkline', async ({ page }) => {
    // Ensure dev flag and api key before navigation
    await page.addInitScript(() => { try{ localStorage.setItem('apiKey','devkey123'); }catch(e){} });
    await page.goto('http://localhost:8080/console');
    // enter a tenant id and click Load
    await page.fill('#tenantInput', 'demo-tenant');
    // intercept temporal endpoint to return synthetic series
    await page.route('**/api/v1/metrics/temporal*', route => {
      const now = Math.floor(Date.now()/1000);
      const series = [{ entity: 'demo', values: Array.from({length:20}).map((_,i)=>({ t: now - (20-i)*60, v: Math.sin(i/3) })) }];
      route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ series, summary: { count: 20 } }) });
    });
    await page.click('#btnLoadTenant');
    // Wait for deterministic test-ready indicator
    await page.waitForSelector('#test_ready', { timeout: 3000 }).catch(()=>{});
    // Wait for deterministic temporal drawn event or canvas with data-drawn
    await page.waitForSelector('#test_ready', { timeout: 3000 }).catch(()=>{});
    await page.waitForFunction(() => { try{ const c = document.querySelector('canvas.temporal-spark'); return !!(c && (c.getAttribute('data-drawn') === '1' || (window as any)['__temporalDrawn'])); }catch(e){ return false; } }, { timeout: 5000 });
    const canvas = await page.$('canvas.temporal-spark');
    expect(canvas).not.toBeNull();
    // Ensure tenant label is visible
    await expect(page.locator('#tenantLoadedLabel')).toBeVisible();
  });
});
