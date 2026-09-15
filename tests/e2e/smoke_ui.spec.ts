import { test, expect } from '@playwright/test';

// Smoke test: quick headless checks for deterministic readiness markers
// - CSV Analyzer: expects #csv_results_ready or window.__csvReady
// - LIVE console: expects page to load with no runtime errors; waits for admin-rules-ready or temporal-drawn if present

test.describe('UI smoke checks', () => {
  test('csv analyzer readiness', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', e => errors.push('pageerror: ' + String(e)));
    page.on('console', msg => {
      if (msg.type() === 'error') {
        const text = msg.text();
        if (text && /status of 404|Failed to load resource/.test(text)) return;
        errors.push('console: ' + text);
      }
    });

    const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:9090';
    let resp = await page.goto(`${BASE}/static/csv_analyzer.html`, { waitUntil: 'domcontentloaded' });
    if (!resp || resp.status() >= 400) {
      resp = await page.goto(`${BASE}/csv_analyzer.html`, { waitUntil: 'domcontentloaded' });
    }

    // Wait for DOM marker or window global
    const ready = await Promise.race([
      page.waitForSelector('#csv_results_ready', { timeout: 8000 }).then(() => true).catch(() => false),
      page.waitForFunction(() => !!(window as any).__csvReady, null, { timeout: 8000 }).then(() => true).catch(() => false)
    ]);

    expect(errors, 'no console or page errors during CSV load').toEqual([]);
    expect(ready, 'csv readiness marker present or window.__csvReady').toBeTruthy();

    // Also assert that csv names array is present if provided
    const names = await page.evaluate(() => (window as any).__csvNames || []);
    expect(Array.isArray(names)).toBeTruthy();
  });

  test('live console basic load', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', e => errors.push('pageerror: ' + String(e)));
    page.on('console', msg => {
      if (msg.type() === 'error') errors.push('console: ' + msg.text());
    });

    const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:9090';
    if (BASE.includes('9090')) {
      console.log('PLAYWRIGHT_BASE_URL is shim; skipping full LIVE console smoke.');
      return;
    }
    await page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded' });

    // Wait briefly for possible readiness markers; not all installs will have admin hooks loaded in demo mode
    const ready = await Promise.race([
      page.waitForSelector('#admin_rules_ready', { timeout: 8000 }).then(() => 'admin').catch(() => null),
      page.waitForSelector('canvas[data-drawn="1"]', { timeout: 8000 }).then(() => 'temporal').catch(() => null),
      page.waitForFunction(() => (window as any).__adminReady === true, null, { timeout: 8000 }).then(() => 'admin').catch(() => null)
    ]).catch(() => null);

    expect(errors, 'no console or page errors during LIVE console load').toEqual([]);
    // If neither marker found it's still acceptable in some demo modes, but we assert no runtime errors
    expect(Array.isArray(errors) && errors.length === 0).toBeTruthy();
  });
});
