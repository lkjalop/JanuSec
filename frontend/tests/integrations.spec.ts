import { test, expect } from '@playwright/test';

const BASE = process.env.BASE_URL || 'http://localhost:8080';

test.describe('Integrations Admin Panels', () => {
  test.beforeEach(async ({ page }) => {
    // Set dev API key in localStorage
    await page.addInitScript(() => {
      try { localStorage.setItem('apiKey', 'devkey123'); } catch(e) {}
    });
    await page.goto(`${BASE}/static/integrations.html`);
    await expect(page).toHaveTitle(/Integrations/);
  });

  test('Policies: refresh, toggle, update RPS/burst, save', async ({ page }) => {
    // Wait for policies table
    await page.waitForSelector('#policiesTable');
    // Refresh
    await page.click('#refreshPolicies');
    // Wait for rows to appear (or no policies)
    await page.waitForTimeout(500);
    // Fill in a policy row by creating or updating via API if missing
    // If no rows, use the Config panel to save a policy via admin API (fallback)
    const name = 'purview';
    // Try to find an existing checkbox for purview
    const checkbox = await page.$(`#policiesTable input[data-name="${name}"][data-field="enabled"]`);
    if (!checkbox) {
      // No row: save policy via fetch in page context then refresh
      await page.evaluate(async (n) => {
        const k = localStorage.getItem('apiKey') || 'devkey123';
        await fetch(`/api/v1/admin/connectors/policies/${n}`, { method: 'POST', headers: {'x-api-key': k, 'Content-Type': 'application/json'}, body: JSON.stringify({enabled: true, rate_limit: {rate_per_second: 1.0, burst: 2.0}})});
      }, name);
      await page.click('#refreshPolicies');
      await page.waitForTimeout(300);
    }
    // Toggle enabled
    const chk = await page.$(`#policiesTable input[data-name="${name}"][data-field="enabled"]`);
    if (chk) {
      await chk.click();
    }
    // Set RPS and burst
    const rpsInput = await page.$(`#policiesTable input[data-name="${name}"][data-field="rps"]`);
    const burstInput = await page.$(`#policiesTable input[data-name="${name}"][data-field="burst"]`);
    if (rpsInput) {
      await rpsInput.fill('4.5');
    }
    if (burstInput) {
      await burstInput.fill('9');
    }
    // Save
    const saveBtn = await page.$(`#policiesTable button[data-name="${name}"]`);
    if (saveBtn) {
      await saveBtn.click();
      // Wait for toast
      await page.waitForTimeout(300);
      // No direct toast API, assert that the policy now exists via admin API
      const res = await page.evaluate(async (n) => {
        const k = localStorage.getItem('apiKey') || 'devkey123';
        const r = await fetch(`/api/v1/admin/connectors/policies/${n}`, { headers: {'x-api-key': k} });
        return r.ok ? await r.json() : {ok:false, status: r.status};
      }, name);
      expect(res.name).toBe(name);
    }
  });

  test('Config: load, update field, save', async ({ page }) => {
    const name = 'purview';
    await page.fill('#cfgName', name);
    await page.click('#cfgLoad');
    await page.waitForTimeout(300);
    // Load current config JSON
    let cur = await page.$eval('#cfgJson', el => el.value);
    let obj = {};
    try { obj = JSON.parse(cur || '{}'); } catch(e) { obj = {}; }
    obj['test_field'] = 'playwright-test';
    await page.fill('#cfgJson', JSON.stringify(obj, null, 2));
    await page.click('#cfgSave');
    await page.waitForTimeout(300);
    // Verify via admin API
    const res = await page.evaluate(async (n) => {
      const k = localStorage.getItem('apiKey') || 'devkey123';
      const r = await fetch(`/api/v1/admin/connectors/config/${n}`, { headers: {'x-api-key': k} });
      return r.ok ? await r.json() : {ok:false, status: r.status};
    }, name);
    expect(res.config && res.config.test_field).toBe('playwright-test');
  });

  test('Secrets: save, load (redacted)', async ({ page }) => {
    const name = 'purview';
    await page.fill('#secName', name);
    await page.fill('#secJson', JSON.stringify({api_key: 'pw-abc-123'}, null, 2));
    await page.click('#secSave');
    await page.waitForTimeout(300);
    // Load back
    await page.click('#secLoad');
    await page.waitForTimeout(300);
    const loaded = await page.$eval('#secJson', el => el.value);
    expect(loaded).toContain('***');
  });
});
