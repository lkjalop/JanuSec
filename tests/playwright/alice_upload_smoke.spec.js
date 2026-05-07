const { test, expect } = require('@playwright/test');
const path = require('path');
const fs = require('fs');

const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:8080';
const API_KEY = process.env.JANUSEC_PLAYWRIGHT_API_KEY || 'devkey123';
const AUTH = { 'x-api-key': API_KEY, 'x-tenant-id': 'default' };

const ALICE_DIR = path.join(__dirname, '../../dump/test files/Alice');
const FILE_JSON = path.join(ALICE_DIR, 'janusec_okta_m365_events.v1.1.json');
const FILE_CSV = path.join(ALICE_DIR, 'janusec_net_c2_bgp.v1.1.csv');
const FILE_XLSX = path.join(ALICE_DIR, 'janusec_ep_endpoint.v1.1.xlsx');

async function pollReady(request, aid, timeoutMs = 300000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const r = await request.get(`${BASE}/api/v1/assessments/${aid}/progress/poll`, { headers: AUTH });
    if (r.ok()) {
      const b = await r.json();
      if (b.status === 'ready') return b;
      if (b.status === 'failed') throw new Error(`assessment failed: ${b.error || 'unknown'}`);
    }
    await new Promise(res => setTimeout(res, 2500));
  }
  throw new Error('timeout waiting for assessment ready');
}

test('alice upload smoke: upload + ready + breach page renders', async ({ request, page }) => {
  test.setTimeout(420000);

  for (const f of [FILE_JSON, FILE_CSV, FILE_XLSX]) {
    expect(fs.existsSync(f), `missing file: ${f}`).toBe(true);
  }

  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'devkey123');
    localStorage.setItem('tenantId', 'default');
  });
  await page.goto(`${BASE}/static/breach.html`);
  await expect(page.locator('[data-testid="br-drop-zone"]')).toBeVisible({ timeout: 15000 });

  const [chooser] = await Promise.all([
    page.waitForEvent('filechooser'),
    page.locator('[data-testid="br-drop-zone"]').click(),
  ]);
  await chooser.setFiles([FILE_JSON, FILE_CSV, FILE_XLSX]);

  await page.waitForURL(/\?assessment=/, { timeout: 360000 });
  const aid = new URL(page.url()).searchParams.get('assessment') || '';
  expect(aid).toBeTruthy();

  const done = await pollReady(request, aid, 360000);
  expect(done.status).toBe('ready');
  expect((done.row_count || 0) > 0).toBe(true);

  await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(aid)}`);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 60000 });

  const cards = await page.locator('[data-testid^="br-card-"]').count();
  expect(cards).toBeGreaterThan(0);
});
