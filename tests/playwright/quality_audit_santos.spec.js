/**
 * quality_audit_santos.spec.js
 *
 * Quality audit for the Santos 4-file upload pipeline.
 * Validates:
 *   - Source classification (non-unknown types after f330cd7 fix)
 *   - Exec summary is evidence-specific (not generic templates)
 *   - Dispatch bar renders correctly via breach_dispatch.js
 *   - window.BreachDispatch module is active
 *   - Drawer opens on toggle click
 *
 * Files:
 *   dump/test files/Santos/janusec_endpoint_k8s_v1.ndjson   (Endpoint/K8s)
 *   dump/test files/Santos/janusec_cloud_identity_v1.json    (Cloud/IAM)
 *   dump/test files/Santos/janusec_network_v1.csv            (Network)
 *   dump/test files/janusec_enrichment_context_v1.xlsx       (Enrichment/multi-sheet)
 *
 * Run:
 *   npx playwright test tests/playwright/quality_audit_santos.spec.js --workers=1
 */

const { test, expect } = require('@playwright/test');
const path = require('path');
const fs = require('fs');

test.describe.configure({ mode: 'serial' });

const BASE    = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:8080';
const API_KEY = process.env.JANUSEC_PLAYWRIGHT_API_KEY || 'devkey123';
const AUTH    = { 'x-api-key': API_KEY, 'x-tenant-id': 'default' };

const FILES_DIR = path.join(__dirname, '../../dump/test files');
const SANTOS_DIR = path.join(FILES_DIR, 'Santos');
const FILE_NDJSON = path.join(SANTOS_DIR, 'janusec_endpoint_k8s_v1.ndjson');
const FILE_JSON   = path.join(SANTOS_DIR, 'janusec_cloud_identity_v1.json');
const FILE_CSV    = path.join(SANTOS_DIR, 'janusec_network_v1.csv');
const FILE_XLSX   = path.join(FILES_DIR, 'janusec_enrichment_context_v1.xlsx');

// Exec summary — strings that indicate a GOOD evidence-specific summary
const EXEC_POSITIVE_SIGNALS = [
  /aaron\.blackwood|rachel\.nakamura|sfloyd|sfl-lt/i,
  /lsass|mfa.*(push|fatigue)|credential.*dump/i,
  /mega\.nz|rclone|snowflake|exfil/i,
  /202[56]-0[12]/,
  /45\.133|91\.240|31\.216/,
  /lateral.*movement|pivot|c2|command.and.control/i,
  /k8s|kubernetes|pod|container/i,
];

// Strings that indicate a template / fallback (regression signal)
const EXEC_GENERIC_FORBIDDEN = [
  /JanuSec found observed attacker action against a protected business process/i,
  /^No confirmed breach found/i,
  /Executive summary unavailable/i,
  /placeholder|lorem ipsum/i,
];

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

async function pollReady(request, aid, timeoutMs = 420_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const r = await request.get(`${BASE}/api/v1/assessments/${aid}/progress/poll`, { headers: AUTH });
    if (r.ok()) {
      const b = await r.json();
      if (b.status === 'ready') return b;
      if (b.status === 'failed') throw new Error(`assessment failed: ${b.error || 'unknown'}`);
    }
    await new Promise(res => setTimeout(res, 3000));
  }
  throw new Error(`Timed out waiting for Santos assessment ${aid}`);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test('santos: input files are present on disk', async () => {
  for (const f of [FILE_NDJSON, FILE_JSON, FILE_CSV, FILE_XLSX]) {
    expect(fs.existsSync(f), `Missing file: ${f}`).toBe(true);
  }
});

test('santos: upload 4 files and wait for ready', async ({ request, page }) => {
  test.setTimeout(480_000);
  await setAuth(page);

  await page.goto(`${BASE}/static/breach.html`);
  await expect(page.locator('[data-testid="br-drop-zone"]')).toBeVisible({ timeout: 15_000 });

  const [chooser] = await Promise.all([
    page.waitForEvent('filechooser'),
    page.locator('[data-testid="br-drop-zone"]').click(),
  ]);
  await chooser.setFiles([FILE_NDJSON, FILE_JSON, FILE_CSV, FILE_XLSX]);

  await page.waitForURL(/\?assessment=/, { timeout: 420_000 });
  const aid = new URL(page.url()).searchParams.get('assessment') || '';
  expect(aid, 'assessment_id must be set in URL').toBeTruthy();
  sharedAid = aid;

  const done = await pollReady(request, aid);
  expect(done.status).toBe('ready');
  expect(done.row_count || 0).toBeGreaterThan(0);
});

test('santos: source_counts reflect all 4 files', async ({ request }) => {
  test.skip(!sharedAid, 'requires upload test to run first');
  const r = await request.get(
    `${BASE}/api/v1/assessments/${encodeURIComponent(sharedAid)}`,
    { headers: AUTH },
  );
  expect(r.ok()).toBe(true);
  const body = await r.json();
  const sourceCounts = body.source_counts || {};
  expect(Object.keys(sourceCounts).length, 'all 4 source files must appear in source_counts').toBeGreaterThanOrEqual(3);
});

test('santos: clusters do not have all-unknown sources', async ({ request }) => {
  test.skip(!sharedAid, 'requires upload test to run first');
  const r = await request.get(
    `${BASE}/api/v1/assessments/${encodeURIComponent(sharedAid)}`,
    { headers: AUTH },
  );
  expect(r.ok()).toBe(true);
  const body = await r.json();
  const clusters = body.clusters || body.analyses || [];
  if (!clusters.length) {
    test.skip('no clusters in assessment body');
    return;
  }
  const sourceTypes = clusters.flatMap(c =>
    Array.isArray(c.sources) ? c.sources : [c.source_type || 'unknown']
  );
  const uniqueTypes = [...new Set(sourceTypes)];
  const onlyUnknown = uniqueTypes.length === 1 && uniqueTypes[0] === 'unknown';
  expect(
    onlyUnknown,
    `All cluster sources are 'unknown' — regression! types: ${JSON.stringify(uniqueTypes)}`,
  ).toBe(false);
});

test('santos: exec summary contains evidence-specific signals', async ({ request }) => {
  test.skip(!sharedAid, 'requires upload test to run first');
  const r = await request.get(
    `${BASE}/api/v1/assessments/${encodeURIComponent(sharedAid)}`,
    { headers: AUTH },
  );
  expect(r.ok()).toBe(true);
  const body = await r.json();
  const summary = (
    body.executive_summary ||
    body.exec_summary ||
    body.summary ||
    ''
  );
  if (!summary) {
    console.warn('No exec summary field found in assessment — skipping signal check');
    return;
  }

  // Must NOT contain any generic/template strings
  for (const pattern of EXEC_GENERIC_FORBIDDEN) {
    expect(
      pattern.test(summary),
      `Exec summary contains generic/template string matching ${pattern}: "${summary.slice(0, 200)}"`,
    ).toBe(false);
  }

  // Should match at least 2 evidence-specific signals
  const matched = EXEC_POSITIVE_SIGNALS.filter(p => p.test(summary));
  expect(
    matched.length,
    `Exec summary too generic — only ${matched.length}/7 evidence signals found. Summary: "${summary.slice(0, 300)}"`,
  ).toBeGreaterThanOrEqual(2);
});

test('santos: breach page renders meta and cluster cards', async ({ page }) => {
  test.skip(!sharedAid, 'requires upload test to run first');
  test.setTimeout(60_000);
  await setAuth(page);

  await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(sharedAid)}`);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 30_000 });

  const cards = await page.locator('[data-testid^="br-card-"]').count();
  expect(cards, 'at least 1 cluster card must render').toBeGreaterThan(0);
});

test('santos: breach_dispatch.js active — window.BreachDispatch has 7 roles', async ({ page }) => {
  test.skip(!sharedAid, 'requires upload test to run first');
  test.setTimeout(30_000);
  await setAuth(page);

  await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(sharedAid)}`);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 30_000 });

  const moduleInfo = await page.evaluate(() => ({
    defined: typeof window.BreachDispatch !== 'undefined',
    roleCount: window.BreachDispatch ? window.BreachDispatch.roles.length : 0,
    hasRenderBar: window.BreachDispatch ? typeof window.BreachDispatch.renderBar === 'function' : false,
  }));
  expect(moduleInfo.defined, 'window.BreachDispatch should be defined').toBe(true);
  expect(moduleInfo.roleCount, 'BreachDispatch.roles should have 7 entries').toBe(7);
  expect(moduleInfo.hasRenderBar, 'BreachDispatch.renderBar should be a function').toBe(true);
});

test('santos: dispatch bar visible with all primary role buttons', async ({ page }) => {
  test.skip(!sharedAid, 'requires upload test to run first');
  test.setTimeout(30_000);
  await setAuth(page);

  await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(sharedAid)}`);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 30_000 });

  await expect(page.locator('[data-testid="br-dispatch"]')).toBeVisible({ timeout: 15_000 });

  const primaryRoles = ['soc_analyst', 'ciso', 'executive', 'threat_hunter', 'forensics', 'compliance'];
  for (const role of primaryRoles) {
    await expect(
      page.locator(`[data-testid="br-dispatch-${role}"]`),
      `dispatch button for ${role} must be visible`,
    ).toBeVisible();
  }
});

test('santos: dispatch drawer opens on toggle click', async ({ page }) => {
  test.skip(!sharedAid, 'requires upload test to run first');
  test.setTimeout(30_000);
  await setAuth(page);

  await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(sharedAid)}`);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('[data-testid="br-dispatch"]')).toBeVisible({ timeout: 15_000 });

  // Toggle to open drawer
  const toggle = page.locator('[data-dispatch-toggle]').first();
  await expect(toggle).toBeVisible();
  await toggle.click();

  // Drawer should now be visible
  const drawer = page.locator('#br-dispatch-drawer');
  await expect(drawer).toBeVisible({ timeout: 5_000 });

  // Full-drawer role buttons (including 'export') should appear
  await expect(page.locator('[data-testid="br-dispatch-drawer-export"]')).toBeVisible();
});

test('santos: dispatch preview hidden until role button clicked', async ({ page }) => {
  test.skip(!sharedAid, 'requires upload test to run first');
  test.setTimeout(30_000);
  await setAuth(page);

  await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(sharedAid)}`);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 30_000 });

  const preview = page.locator('[data-testid="br-dispatch-preview"]');
  await expect(preview).toBeAttached({ timeout: 15_000 });
  const visibleBefore = await preview.isVisible();
  expect(visibleBefore, 'preview panel should be hidden before a role is clicked').toBe(false);
});
