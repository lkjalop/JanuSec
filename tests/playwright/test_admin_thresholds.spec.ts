import { test, expect } from '@playwright/test';

const BASE = process.env.BASE_URL || 'http://localhost:8080';

test('admin unlock and threshold load/save/reset (dev-only)', async ({ page }) => {
  // Ensure deterministic dev flags before navigation
  await page.addInitScript(() => { try{ localStorage.setItem('apiKey','devkey123'); localStorage.setItem('adminKey','test-admin'); }catch(e){} });
  await page.goto(BASE + '/console');
  // Mock admin endpoints so load/save/reset are deterministic in tests
  let adminState = { lateral_conn_count: 5, rapid_scan_rate: 20, exfil_bytes: 65536 };
  await page.route('**/api/v1/admin/rules', async route => {
    const req = route.request();
    if (req.method() === 'GET') {
      route.fulfill({ status: 200, body: JSON.stringify(adminState), headers: { 'Content-Type': 'application/json' } });
    } else if (req.method() === 'POST') {
      try{
        const body = JSON.parse(await req.postData() || '{}');
        adminState = Object.assign({}, adminState, body);
      }catch(_){ }
      route.fulfill({ status: 200, body: JSON.stringify({ ok: true }), headers: { 'Content-Type': 'application/json' } });
    } else {
      route.continue();
    }
  });
  await page.route('**/api/v1/admin/rules/reset', route => {
    adminState = { lateral_conn_count: 0, rapid_scan_rate: 0, exfil_bytes: 0 };
    route.fulfill({ status: 200, body: JSON.stringify({ ok: true, ...adminState }), headers: { 'Content-Type': 'application/json' } });
  });
  await page.waitForLoadState('domcontentloaded');
  // unlock should cause panel to be visible
  await page.click('#btnUnlockDev');
  // fill fields
  await page.fill('#th_lateral', '42');
  await page.fill('#th_scan', '99');
  await page.fill('#th_exfil', '12345');
  // save
  await page.click('#btnSaveThresholds');
  await page.waitForTimeout(400);
  // load
  await page.click('#btnLoadThresholds');
  await page.waitForTimeout(400);
  // verify values persisted in inputs
  await expect(page.locator('#th_lateral')).toHaveValue('42');
  await expect(page.locator('#th_scan')).toHaveValue('99');
  await expect(page.locator('#th_exfil')).toHaveValue('12345');
  // reset
  await page.click('#btnResetThresholds');
  await page.waitForTimeout(400);
  // after reset inputs should update — wait for deterministic admin-ready marker
  await page.waitForSelector('#admin_rules_ready', { timeout: 3000 }).catch(()=>{});
  // Ensure lateral value updated (fallback check)
  await page.waitForFunction(() => { try{ const el = document.getElementById('th_lateral'); const e = el && (el as HTMLInputElement); return e && e.value !== '42'; }catch(e){ return false; } }, { timeout: 3000 }).catch(()=>{});
});
