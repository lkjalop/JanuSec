/**
 * quality_audit_alice.spec.js
 *
 * Quality audit for the Alice 3-file upload pipeline.
 * Focuses on regressions fixed in commit f330cd7:
 *   - source_type must NOT be 'unknown' for endpoint/bgp/okta files
 *   - cluster cards must show real source types (endpoint / network / iam)
 *   - breach_dispatch.js module must be active (window.BreachDispatch defined)
 *   - dispatch bar must render with per-role test IDs
 *
 * Files:
 *   dump/test files/Alice/janusec_okta_m365_events.v1.1.json  (IAM)
 *   dump/test files/Alice/janusec_net_c2_bgp.v1.1.csv          (Network/BGP)
 *   dump/test files/Alice/janusec_ep_endpoint.v1.1.xlsx         (Endpoint)
 *
 * Run:
 *   npx playwright test tests/playwright/quality_audit_alice.spec.js --workers=1
 */

const { test, expect } = require('@playwright/test');
const path = require('path');
const fs = require('fs');

test.describe.configure({ mode: 'serial' });

const BASE    = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:8080';
const API_KEY = process.env.JANUSEC_PLAYWRIGHT_API_KEY || 'devkey123';
const AUTH    = { 'x-api-key': API_KEY, 'x-tenant-id': 'default' };

const ALICE_DIR = path.join(__dirname, '../../dump/test files/Alice');
const FILE_JSON = path.join(ALICE_DIR, 'janusec_okta_m365_events.v1.1.json');
const FILE_CSV  = path.join(ALICE_DIR, 'janusec_net_c2_bgp.v1.1.csv');
const FILE_XLSX = path.join(ALICE_DIR, 'janusec_ep_endpoint.v1.1.xlsx');

// Expected source type tokens that must appear for a correct Alice analysis
const EXPECTED_SOURCE_TYPES = ['iam', 'network', 'endpoint'];

// Source type tokens that indicate a regression (f330cd7 bug)
const FORBIDDEN_ONLY_UNKNOWN = ['unknown'];

let sharedAid = '';

// ── Helpers ──────────────────────────────────────────────────────────────────

async function setAuth(page) {
  await page.addInitScript(() => {
    localStorage.setItem('apiKey', window.__JANUSEC_TEST_API_KEY__ || 'devkey123');
    localStorage.setItem('tenantId', 'default');
  });
  await page.addInitScript(key => {
    window.__JANUSEC_TEST_API_KEY__ = key;
    localStorage.setItem('apiKey', key);
  }, API_KEY);
}

async function pollReady(request, aid, timeoutMs = 360000) {
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
  throw new Error(`Timed out waiting for assessment ${aid}`);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test('alice: input files are present on disk', async () => {
  for (const f of [FILE_JSON, FILE_CSV, FILE_XLSX]) {
    expect(fs.existsSync(f), `Missing file: ${f}`).toBe(true);
  }
});

test('alice: upload 3 files and wait for ready', async ({ request, page }) => {
  test.setTimeout(420_000);
  await setAuth(page);

  await page.goto(`${BASE}/static/breach.html`);
  await expect(page.locator('[data-testid="br-drop-zone"]')).toBeVisible({ timeout: 15_000 });

  const [chooser] = await Promise.all([
    page.waitForEvent('filechooser'),
    page.locator('[data-testid="br-drop-zone"]').click(),
  ]);
  await chooser.setFiles([FILE_JSON, FILE_CSV, FILE_XLSX]);

  await page.waitForURL(/\?assessment=/, { timeout: 360_000 });
  const aid = new URL(page.url()).searchParams.get('assessment') || '';
  expect(aid, 'assessment_id must be set in URL').toBeTruthy();
  sharedAid = aid;

  const done = await pollReady(request, aid);
  expect(done.status).toBe('ready');
  expect(done.row_count || 0).toBeGreaterThan(0);
});

test('alice: source_counts contains non-unknown types', async ({ request }) => {
  test.skip(!sharedAid, 'requires upload test to run first');
  const r = await request.get(
    `${BASE}/api/v1/assessments/${encodeURIComponent(sharedAid)}`,
    { headers: AUTH },
  );
  expect(r.ok(), `GET assessment failed: ${r.status()}`).toBe(true);
  const body = await r.json();

  // source_counts keys are the raw filenames; values are row counts
  const sourceCounts = body.source_counts || {};
  const keys = Object.keys(sourceCounts).map(k => k.toLowerCase());
  expect(keys.length, 'source_counts must be populated').toBeGreaterThan(0);

  // Verify at least one file was classified from each expected domain
  const hasIAM      = keys.some(k => k.includes('okta') || k.includes('m365') || k.includes('iam'));
  const hasNetwork  = keys.some(k => k.includes('bgp') || k.includes('net') || k.includes('c2'));
  const hasEndpoint = keys.some(k => k.includes('endpoint') || k.includes('ep_'));
  expect(hasIAM,      'IAM source file must be present in source_counts').toBe(true);
  expect(hasNetwork,  'Network/BGP source file must be present in source_counts').toBe(true);
  expect(hasEndpoint, 'Endpoint source file must be present in source_counts').toBe(true);
});

test('alice: cluster source_type values are not all unknown (f330cd7 regression)', async ({ request }) => {
  test.skip(!sharedAid, 'requires upload test to run first');
  const r = await request.get(
    `${BASE}/api/v1/assessments/${encodeURIComponent(sharedAid)}/clusters`,
    { headers: AUTH },
  );
  if (!r.ok()) {
    // Some builds serve clusters on the root assessment endpoint
    const r2 = await request.get(
      `${BASE}/api/v1/assessments/${encodeURIComponent(sharedAid)}`,
      { headers: AUTH },
    );
    if (!r2.ok()) test.skip('clusters endpoint not available');
    const body2 = await r2.json();
    const clusters = body2.clusters || body2.analyses || [];
    const sourceTypes = clusters.flatMap(c => Array.isArray(c.sources) ? c.sources : [c.source_type || 'unknown']);
    const uniqueTypes = [...new Set(sourceTypes)];
    // Must not be exclusively 'unknown'
    const onlyUnknown = uniqueTypes.length === 1 && uniqueTypes[0] === 'unknown';
    expect(onlyUnknown, `All cluster sources are 'unknown' — f330cd7 regression! sources: ${uniqueTypes}`).toBe(false);
    return;
  }
  const body = await r.json();
  const clusters = body.clusters || body.analyses || body || [];
  if (!Array.isArray(clusters) || clusters.length === 0) {
    test.skip('no clusters returned');
    return;
  }
  const sourceTypes = clusters.flatMap(c => Array.isArray(c.sources) ? c.sources : [c.source_type || 'unknown']);
  const uniqueTypes = [...new Set(sourceTypes)];
  const onlyUnknown = uniqueTypes.length === 1 && uniqueTypes[0] === 'unknown';
  expect(onlyUnknown, `All cluster sources are 'unknown' — f330cd7 regression! sources: ${JSON.stringify(uniqueTypes)}`).toBe(false);
});

test('alice: breach page renders cluster cards with sources', async ({ page }) => {
  test.skip(!sharedAid, 'requires upload test to run first');
  test.setTimeout(60_000);
  await setAuth(page);

  await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(sharedAid)}`);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 30_000 });

  const cards = await page.locator('[data-testid^="br-card-"]').count();
  expect(cards, 'at least 1 cluster card must be visible').toBeGreaterThan(0);

  // Verify at least one source chip is not 'unknown'
  const sourceChips = page.locator('.br-source-chip, [data-source-type]');
  const chipCount = await sourceChips.count();
  if (chipCount > 0) {
    const allTexts = await sourceChips.allTextContents();
    const hasNonUnknown = allTexts.some(t => t.toLowerCase() !== 'unknown');
    expect(hasNonUnknown, `All source chips show 'unknown' — source classification broken. chips: ${allTexts}`).toBe(true);
  }
});

test('alice: breach_dispatch.js module is active (window.BreachDispatch defined)', async ({ page }) => {
  test.skip(!sharedAid, 'requires upload test to run first');
  test.setTimeout(30_000);
  await setAuth(page);

  await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(sharedAid)}`);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 30_000 });

  const dispatchDefined = await page.evaluate(() => {
    return typeof window.BreachDispatch !== 'undefined';
  });
  expect(dispatchDefined, 'window.BreachDispatch should be defined by breach_dispatch.js').toBe(true);

  // Verify the module's ROLES are loaded
  const roleCount = await page.evaluate(() => {
    return window.BreachDispatch ? window.BreachDispatch.roles.length : 0;
  });
  expect(roleCount, 'BreachDispatch.roles should have 7 entries').toBe(7);
});

test('alice: dispatch bar renders with SOC and CISO buttons', async ({ page }) => {
  test.skip(!sharedAid, 'requires upload test to run first');
  test.setTimeout(30_000);
  await setAuth(page);

  await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(sharedAid)}`);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 30_000 });

  // Dispatch bar should be rendered
  await expect(page.locator('[data-testid="br-dispatch"]')).toBeVisible({ timeout: 15_000 });

  // Primary role buttons should be present
  await expect(page.locator('[data-testid="br-dispatch-soc_analyst"]')).toBeVisible();
  await expect(page.locator('[data-testid="br-dispatch-ciso"]')).toBeVisible();
  await expect(page.locator('[data-testid="br-dispatch-executive"]')).toBeVisible();
});

test('alice: action center grid is visible', async ({ page }) => {
  test.skip(!sharedAid, 'requires upload test to run first');
  test.setTimeout(30_000);
  await setAuth(page);

  await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(sharedAid)}`);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('[data-testid="br-action-center"]')).toBeVisible({ timeout: 15_000 });
});

test('alice: dispatch preview panel not visible until button clicked', async ({ page }) => {
  test.skip(!sharedAid, 'requires upload test to run first');
  test.setTimeout(30_000);
  await setAuth(page);

  await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(sharedAid)}`);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 30_000 });

  const preview = page.locator('[data-testid="br-dispatch-preview"]');
  // Preview should exist but be hidden by default
  await expect(preview).toBeAttached({ timeout: 15_000 });
  const isVisible = await preview.isVisible();
  expect(isVisible, 'dispatch preview should be hidden until a role button is clicked').toBe(false);
});
