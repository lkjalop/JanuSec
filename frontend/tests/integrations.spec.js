const { test, expect } = require('@playwright/test');

const BASE = process.env.BASE_URL || 'http://localhost:8080';

test.describe('Integrations Admin Panels', () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      try { localStorage.setItem('apiKey', 'devkey123'); } catch(e) {}
    });
    await page.goto(`${BASE}/static/integrations.html`);
    await expect(page).toHaveTitle(/Integrations/);
  });

  test('Policies: refresh, toggle, update RPS/burst, save', async ({ page }) => {
    await page.waitForSelector('#policiesTable');
    await page.click('#refreshPolicies');
    await page.waitForTimeout(500);
    const name = 'purview';
    const checkbox = await page.$(`#policiesTable input[data-name="${name}"][data-field="enabled"]`);
    if (!checkbox) {
      await page.evaluate(async (n) => {
        const k = localStorage.getItem('apiKey') || 'devkey123';
        await fetch(`/api/v1/admin/connectors/policies/${n}`, { method: 'POST', headers: {'x-api-key': k, 'Content-Type': 'application/json'}, body: JSON.stringify({enabled: true, rate_limit: {rate_per_second: 1.0, burst: 2.0}})});
      }, name);
      await page.click('#refreshPolicies');
      await page.waitForTimeout(300);
    }
    const chk = await page.$(`#policiesTable input[data-name="${name}"][data-field="enabled"]`);
    if (chk) {
      await chk.click();
    }
    const rpsInput = await page.$(`#policiesTable input[data-name="${name}"][data-field="rps"]`);
    const burstInput = await page.$(`#policiesTable input[data-name="${name}"][data-field="burst"]`);
    if (rpsInput) {
      await rpsInput.fill('4.5');
    }
    if (burstInput) {
      await burstInput.fill('9');
    }
    const saveBtn = await page.$(`#policiesTable button[data-name="${name}"]`);
    if (saveBtn) {
      await saveBtn.click();
      await page.waitForTimeout(300);
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
    let cur = await page.$eval('#cfgJson', el => el.value);
    let obj = {};
    try { obj = JSON.parse(cur || '{}'); } catch(e) { obj = {}; }
    obj['test_field'] = 'playwright-test';
    await page.fill('#cfgJson', JSON.stringify(obj, null, 2));
    await page.click('#cfgSave');
    await page.waitForTimeout(300);
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
    await page.click('#secLoad');
    await page.waitForTimeout(300);
    const loaded = await page.$eval('#secJson', el => el.value);
    expect(loaded).toContain('***');
  });
});
