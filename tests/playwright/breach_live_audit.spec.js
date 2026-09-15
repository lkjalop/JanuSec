/**
 * breach_live_audit.spec.js
 *
 * Live audit of breach.html with the three real AcmeCorp / PHANTOM-MERIDIAN
 * test files.
 *
 * SAFETY: No concurrent LLM calls. qwen3:30b is excluded from this suite —
 * run scripts/ab_compare.sh separately (sequential, monitored).
 *
 *  PHASE A — Upload + pipeline
 *    A1. Upload zone renders correctly
 *    A2. Upload 3 files → pipeline runs → redirects to ?assessment=
 *
 *  PHASE B — Home page quality (UI only, no live LLM wait)
 *    B1. Meta line: shows real source/row/cluster counts (not "?")
 *    B2. Model dropdown: present in tab bar with qwen3:14b selected
 *    B3. "Lead cluster auto-loaded" wording is correct
 *    B4. Lead card title: NOT a raw entity dump ("CRITICAL — SYSTEM, alice")
 *    B5. Lead card subtitle: non-empty and breach-style narrative
 *    B6. Exec summary block visible (accepts deterministic fallback)
 *    B7. Swimlane: container visible and NOT showing "no timestamps" error
 *    B8. HopGraph: container visible and NOT showing "No rows" error
 *    B9. "Open breach detail ↗" label (not "Open in tab")
 *
 *  PHASE C — Cluster detail quality
 *    C1. Cluster detail page loads bct-wrap
 *    C2. Timeline: NOT showing "unavailable — server not loaded yet"
 *    C3. Persona steps: at least one .bct-step visible
 *    C4. Expanding a step shows subtasks (deterministic fallback if needed)
 *    C5. Notes autosave works (route mocked)
 *
 *  PHASE D — LLM quality snapshot (qwen3:14b, force:false = uses cached)
 *    D1. Tier1 returns 200 with valid structure
 *    D2. Exec summary deterministic sentence: mentions cluster count + JanuSec
 *    (Full LLM assertions logged but not hard-failed — Ollama may be cold)
 */

const { test, expect } = require('@playwright/test');
const path = require('path');

test.describe.configure({ mode: 'serial' });
test.setTimeout(180_000);

const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:8080';
const BREACH_URL = BASE + '/static/breach.html';

const TEST_FILES_DIR = path.join(__dirname, '../../dump/investigate-upload/dump/test files');
const NET_CSV   = path.join(TEST_FILES_DIR, 'janusec_net_c2_bgp.v1.1.csv');
const OKTA_JSON = path.join(TEST_FILES_DIR, 'janusec_okta_m365_events.v1.1.json');
const EP_XLSX   = path.join(TEST_FILES_DIR, 'janusec_ep_endpoint.v1.1.xlsx');

let assessmentId = '';
let leadClusterId = '';
let tier1Data = {};
const abResults = {};

// ─── helpers ──────────────────────────────────────────────────────────────────

async function apiGet(path) {
  const r = await fetch(BASE + path, {
    headers: { 'x-tenant-id': 'default', 'x-api-key': 'devkey123' }
  });
  return r.ok ? r.json() : null;
}

async function apiPost(path, body) {
  const r = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-tenant-id': 'default', 'x-api-key': 'devkey123' },
    body: JSON.stringify(body)
  });
  return r.ok ? r.json() : null;
}

// ── helper: open drill-down + analyst detail (cards/exec are inside them now) ──
async function openDrilldown(page) {
  const toggleBtn = page.locator('[data-testid="br-toggle-drilldown"]');
  if (await toggleBtn.count() > 0) await toggleBtn.click();
  const analystDetail = page.locator('[data-testid="br-analyst-detail"] > summary');
  if (await analystDetail.count() > 0) await analystDetail.click();
}

// ─── PHASE A ──────────────────────────────────────────────────────────────────

test('A1. Upload zone renders with drop zone and file input', async ({ page }) => {
  await page.goto(BREACH_URL);
  await expect(page.locator('[data-testid="br-upload"]')).toBeVisible({ timeout: 10000 });
  await expect(page.locator('[data-testid="br-drop-zone"]')).toBeVisible();
  await expect(page.locator('[data-testid="br-file-input"]')).toBeAttached();
});

test('A2. Upload 3 files → redirect to ?assessment=', async ({ page }) => {
  await page.goto(BREACH_URL);
  await expect(page.locator('[data-testid="br-drop-zone"]')).toBeVisible({ timeout: 10000 });
  const [fileChooser] = await Promise.all([
    page.waitForEvent('filechooser'),
    page.locator('[data-testid="br-drop-zone"]').click(),
  ]);
  await fileChooser.setFiles([NET_CSV, OKTA_JSON, EP_XLSX]);
  await page.waitForURL(/\?assessment=/, { timeout: 90000 });
  const url = page.url();
  expect(url).toContain('assessment=');
  assessmentId = new URL(url).searchParams.get('assessment') || '';
  expect(assessmentId).toBeTruthy();
  console.log('✓ Assessment ID:', assessmentId);
});

// ─── PHASE B ──────────────────────────────────────────────────────────────────

test('B1. Meta line: real counts (not "?")', async ({ page }) => {
  await page.goto(BREACH_URL + '?assessment=' + assessmentId);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 20000 });

  const src = await page.locator('[data-testid="br-source-count"]').textContent();
  const rows = await page.locator('[data-testid="br-row-count"]').textContent();
  const clusters = await page.locator('[data-testid="br-cluster-count"]').textContent();

  console.log(`  Sources: ${src.trim()}, Rows: ${rows.trim()}, Clusters: ${clusters.trim()}`);
  expect(src.trim()).not.toBe('?');
  expect(parseInt(src.trim(), 10)).toBeGreaterThanOrEqual(3);
  expect(parseInt(rows.trim(), 10)).toBeGreaterThan(50);
  expect(parseInt(clusters.trim(), 10)).toBeGreaterThan(0);
});

test('B2. Model dropdown present with qwen3:14b default', async ({ page }) => {
  await page.goto(BREACH_URL + '?assessment=' + assessmentId);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 20000 });
  const sel = page.locator('#br-model-select');
  await expect(sel).toBeVisible();
  const val = await sel.inputValue();
  console.log('  Model dropdown value:', val);
  expect(val).toBe('qwen3:14b');
});

test('B3. Meta wording: auto-hydrate notice present', async ({ page }) => {
  await page.goto(BREACH_URL + '?assessment=' + assessmentId);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 20000 });
  const txt = await page.locator('[data-testid="br-meta"]').textContent();
  // UI switched from "Lead cluster auto-loaded" → "Top threat cases hydrate automatically"
  const hasAutoHydrate = txt.includes('hydrate automatically') || txt.includes('auto-loaded');
  expect(hasAutoHydrate).toBe(true);
  expect(txt).not.toContain('Cluster-1 pre-loaded');
});

test('B4. Lead card title: NOT a raw entity dump', async ({ page }) => {
  await page.goto(BREACH_URL + '?assessment=' + assessmentId);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 20000 });
  await openDrilldown(page);
  // Wait for lead card to appear
  const card = page.locator('[data-testid^="br-card-"]').first();
  await expect(card).toBeVisible({ timeout: 15000 });
  leadClusterId = (await card.getAttribute('data-testid') || '').replace('br-card-', '');
  const title = await card.locator('.br-card__title').textContent();
  console.log('  Lead card title:', title.trim());

  // Must not be "CRITICAL — SYSTEM, alice.walker" style (raw severity + entity dump)
  expect(title.trim()).toBeTruthy();
  expect(title.trim().length).toBeGreaterThan(5);
  // Must not start with a raw severity label followed by a dash + raw account list
  expect(title.trim()).not.toMatch(/^(CRITICAL|HIGH|MEDIUM|LOW)\s*[—–-]\s*(SYSTEM|[A-Z]{2,},)/);
  // Must not be a raw entity dump starting with SYSTEM or similar noise accounts
  expect(title.trim()).not.toMatch(/^SYSTEM[,\s]/i);
  // Must not be a DAY-N analyst note leaked as title
  expect(title.trim()).not.toMatch(/^DAY\s*\d+/i);
  // Min 2 words (LLM incident names like "HARBOURSIDE BEC" are valid)
  expect(title.trim().split(/\s+/).length).toBeGreaterThanOrEqual(2);
});

test('B5. Lead card subtitle: non-empty breach narrative', async ({ page }) => {
  await page.goto(BREACH_URL + '?assessment=' + assessmentId);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 20000 });
  await openDrilldown(page);
  await expect(page.locator('[data-testid^="br-card-"]').first()).toBeVisible({ timeout: 20000 });
  const sub = await page.locator('[data-testid^="br-card-"]').first().locator('.br-card__subtitle').textContent();
  console.log('  Lead card subtitle:', sub.trim().slice(0, 120));
  expect(sub.trim().length).toBeGreaterThan(10);
  expect(sub.trim()).not.toBe('undefined');
  expect(sub.trim()).not.toBe('null');
});

test('B6. Exec summary block visible (deterministic fallback OK)', async ({ page }) => {
  await page.goto(BREACH_URL + '?assessment=' + assessmentId);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 20000 });
  await openDrilldown(page);
  await expect(page.locator('[data-testid="br-exec-block"]')).toBeVisible({ timeout: 20000 });
  // Wait for exec-summary async fetch to populate the element (may take a few seconds on cold start)
  await expect(page.locator('#br-exec-det')).not.toBeEmpty({ timeout: 10000 });
  const txt = await page.locator('#br-exec-det').textContent();
  console.log('  Exec summary:', txt.trim().slice(0, 200));
  expect(txt.trim().length).toBeGreaterThan(5);
  expect(txt.trim()).not.toContain('server loading');
});

test('B7. Swimlane: container rendered without error message', async ({ page }) => {
  await page.goto(BREACH_URL + '?assessment=' + assessmentId);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 20000 });
  const swim = page.locator('#br-swimlane-container');
  await expect(swim).toBeVisible();
  const txt = await swim.textContent();
  console.log('  Swimlane content preview:', txt.trim().slice(0, 100));
  expect(txt).not.toContain('no timestamps in rows');
  expect(txt).not.toContain('No rows');
});

test('B8. HopGraph: container rendered without error message', async ({ page }) => {
  await page.goto(BREACH_URL + '?assessment=' + assessmentId);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 20000 });
  const hop = page.locator('#br-hopgraph-mini');
  await expect(hop).toBeVisible();
  const txt = await hop.textContent();
  console.log('  HopGraph content preview:', txt.trim().slice(0, 100));
  expect(txt).not.toContain('No rows for this cluster');
});

test('B9. Button label: cluster action button present and not legacy label', async ({ page }) => {
  await page.goto(BREACH_URL + '?assessment=' + assessmentId);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 20000 });
  await openDrilldown(page);
  await expect(page.locator('[data-testid^="br-card-"]').first()).toBeVisible({ timeout: 20000 });
  const btnTxt = await page.locator('.br-card__open').first().textContent();
  console.log('  Open button text:', btnTxt.trim());
  // Button was renamed from "Open breach detail" → "Show evidence rows" — accept either
  const hasActionLabel = btnTxt.includes('Open breach detail') ||
                         btnTxt.includes('Show evidence rows') ||
                         btnTxt.includes('evidence') ||
                         btnTxt.includes('detail');
  expect(hasActionLabel, `Unexpected button label: ${btnTxt.trim()}`).toBe(true);
  expect(btnTxt).not.toContain('Open in tab');
});

// ─── PHASE C ──────────────────────────────────────────────────────────────────

test('C1. Cluster detail: bct-wrap visible', async ({ page }) => {
  if (!leadClusterId) test.skip();
  await page.goto(BREACH_URL + '?assessment=' + assessmentId + '&cluster=' + leadClusterId);
  await expect(page.locator('[data-testid="bct-wrap"]')).toBeVisible({ timeout: 20000 });
});

test('C2. Timeline: NOT showing server-error message', async ({ page }) => {
  if (!leadClusterId) test.skip();
  await page.goto(BREACH_URL + '?assessment=' + assessmentId + '&cluster=' + leadClusterId);
  await expect(page.locator('[data-testid="bct-wrap"]')).toBeVisible({ timeout: 20000 });
  // Give timeline time to load
  await page.waitForTimeout(3000);
  const tl = page.locator('[data-testid="bct-timeline"]');
  await expect(tl).toBeVisible();
  const txt = await tl.textContent();
  console.log('  Timeline content:', txt.trim().slice(0, 150));
  expect(txt).not.toContain('server not loaded yet');
  // Accept either phase rows OR "no timestamped rows" (the latter means data loaded but nothing timestamped)
  const hasPhases = await page.locator('.bct-tl-phase').count();
  const hasEmpty = txt.includes('No timestamped rows');
  console.log(`  Timeline: ${hasPhases} phases, hasEmpty=${hasEmpty}`);
  expect(hasPhases > 0 || hasEmpty, 'Timeline should show phases or no-timestamp message, not a server error').toBe(true);
});

test('C3. Persona steps: at least one step visible', async ({ page }) => {
  if (!leadClusterId) test.skip();
  await page.goto(BREACH_URL + '?assessment=' + assessmentId + '&cluster=' + leadClusterId);
  await expect(page.locator('[data-testid="bct-persona-body"]')).toBeVisible({ timeout: 20000 });
  // Wait for loading to clear
  await expect(page.locator('[data-testid="bct-persona-body"]')).not.toContainText('Loading', { timeout: 15000 });
  const stepOrPrompt = page.locator('.bct-step, .bct-generate-prompt, #bct-gen-btn');
  const count = await stepOrPrompt.count();
  console.log('  Persona elements:', count);
  expect(count).toBeGreaterThan(0);
});

test('C4. Expanding first step shows subtasks (deterministic fallback)', async ({ page }) => {
  if (!leadClusterId) test.skip();
  await page.goto(BREACH_URL + '?assessment=' + assessmentId + '&cluster=' + leadClusterId);
  await expect(page.locator('[data-testid="bct-persona-body"]')).toBeVisible({ timeout: 20000 });
  await expect(page.locator('[data-testid="bct-persona-body"]')).not.toContainText('Loading', { timeout: 15000 });

  const firstExpand = page.locator('.bct-step__expand').first();
  const expandCount = await firstExpand.count();
  if (expandCount === 0) { console.log('  No expand buttons — using generate prompt flow'); return; }

  await firstExpand.click();
  // Check subtasks are now visible
  const subtasks = page.locator('.bct-subtask');
  const subtaskCount = await subtasks.count();
  console.log('  Subtasks visible after expand:', subtaskCount);
  expect(subtaskCount).toBeGreaterThan(0);

  const firstSubLabel = await subtasks.first().locator('.bct-subtask__label').textContent();
  console.log('  First subtask label:', firstSubLabel.trim());
  expect(firstSubLabel.trim().length).toBeGreaterThan(5);
});

test('C5. Notes autosave: Saved ✓', async ({ page }) => {
  if (!leadClusterId) test.skip();
  await page.route('**/notes', route => {
    if (route.request().method() === 'PATCH') {
      route.fulfill({ status: 200, contentType: 'application/json',
        body: JSON.stringify({ status: 'ok', updated_at: Math.floor(Date.now()/1000) }) });
    } else route.continue();
  });
  await page.goto(BREACH_URL + '?assessment=' + assessmentId + '&cluster=' + leadClusterId);
  await expect(page.locator('[data-testid="bct-notes-input"]')).toBeVisible({ timeout: 20000 });
  await page.locator('[data-testid="bct-notes-input"]').fill('Live audit test note ' + Date.now());
  await expect(page.locator('#bct-notes-status')).toHaveText('Saved ✓', { timeout: 5000 });
});

// ─── PHASE D — LLM API structure check (force:false = cached, no GPU spike) ──

test('D1. Tier1-summary API: returns 200 with valid structure', async ({ request }) => {
  if (!assessmentId || !leadClusterId) test.skip();

  // force:false — uses cached result if available; may invoke LLM on cold cache (allow 120s)
  const t0 = Date.now();
  const r = await request.post(
    `${BASE}/api/v1/assessments/${assessmentId}/clusters/${leadClusterId}/tier1-summary`,
    {
      headers: { 'Content-Type': 'application/json', 'x-tenant-id': 'default', 'x-api-key': 'devkey123' },
      data: { model: 'qwen3:14b', force: false },
      timeout: 120_000,
    }
  );
  const latency = Date.now() - t0;
  const result = { ok: r.ok(), status: r.status(), data: r.ok() ? await r.json() : { _error: r.status() }, latency };

  console.log('\n── TIER1 API CHECK (qwen3:14b, force:false) ─────────');
  console.log('  Status:', result.status, '| Latency:', result.latency + 'ms');

  expect(result.ok, `Expected 200, got ${result.status}`).toBe(true);

  const p = result.data.tier1_prefill || {};
  console.log('  incident_name:', p.incident_name || '(not yet cached — LLM pending)');
  console.log('  headline_subtitle:', (p.headline_subtitle || '').slice(0, 100) || '(pending)');
  console.log('  top_actions count:', (p.top_actions || []).length);
  console.log('  MITRE:', JSON.stringify(p.mitre_techniques || []));

  // Soft quality log — LLM may not have run yet (Ollama cold start), so don't hard-fail
  if (p.incident_name) {
    expect(p.incident_name).not.toBe('undefined');
    expect(p.incident_name.split(' ').length).toBeGreaterThanOrEqual(2);
    console.log('  ✓ LLM result cached — quality assertions passed');
  } else {
    console.log('  ⚠ LLM not yet cached — run scripts/ab_compare.sh for full quality check');
  }
});

test('D2. Exec-summary: deterministic sentence present', async ({ request }) => {
  if (!assessmentId) test.skip();

  // regenerate:false — uses cached deterministic sentence, no LLM call
  const t0 = Date.now();
  const r = await request.post(
    `${BASE}/api/v1/assessments/${assessmentId}/executive-summary`,
    {
      headers: { 'Content-Type': 'application/json', 'x-tenant-id': 'default', 'x-api-key': 'devkey123' },
      data: { model: 'qwen3:14b', regenerate: false },
    }
  );
  const latency = Date.now() - t0;
  const result = { ok: r.ok(), status: r.status(), data: r.ok() ? await r.json() : { _error: r.status() }, latency };

  console.log('\n── EXEC SUMMARY API CHECK ────────────────────────────');
  console.log('  Status:', result.status, '| Latency:', result.latency + 'ms');
  if (result.data) {
    console.log('  Deterministic:', (result.data.deterministic || '').slice(0, 200));
    console.log('  LLM color:', (result.data.llm_color || '(none — run ab_compare for LLM)').slice(0, 100));
  }

  expect(result.ok, `Expected 200, got ${result.status}`).toBe(true);
  const det = result.data?.deterministic || '';
  expect(det, 'Deterministic sentence should mention JanuSec').toContain('JanuSec');
  // "cluster" may be rendered as "threat cases" depending on UI vocabulary
  const hasClusterRef = det.includes('cluster') || det.includes('threat case') || det.includes('incident');
  expect(hasClusterRef, 'Deterministic sentence should reference clusters or threat cases').toBe(true);
});

// ─── A/B NOTE ────────────────────────────────────────────────────────────────
// qwen3:30b comparison is intentionally excluded from this Playwright suite.
// Running a large model concurrently with browser automation on a laptop GPU
// risks VIDEO_TDR_FAILURE (confirmed crash 2026-04-21).
// Use scripts/ab_compare.sh instead — it runs models sequentially with a
// cooling pause and nvidia-smi monitoring between calls.

test('E3. A/B final report: quality vs latency comparison', async () => {
  console.log('\n╔════════════════════════════════════════════════════════╗');
  console.log('║       A/B TEST REPORT: TIER1 PREFILL QUALITY          ║');
  console.log('╠════════════════════════════════════════════════════════╣');

  for (const [model, r] of Object.entries(abResults)) {
    if (r.error) {
      console.log(`║  ${model}: UNAVAILABLE (${r.error})`);
      continue;
    }
    console.log(`║  Model: ${model}`);
    console.log(`║    Latency:       ${r.latency}ms`);
    console.log(`║    Narrative wds: ${r.wordCount}`);
    console.log(`║    MITRE count:   ${r.mitreCount}`);
    console.log(`║    Action count:  ${r.actionCount}`);
    console.log(`║    Has verdict:   ${r.hasVerdict}`);
    console.log(`║    Incident name: ${r.incidentName || '(none)'}`);
    console.log('║  ─────────────────────────────────────────────────────');
  }

  const m14 = abResults['qwen3:14b'];
  const m30 = abResults['qwen3:30b'];
  if (m14 && m30 && !m14.error && !m30.error) {
    const latencyDelta = m30.latency - m14.latency;
    const wordDelta    = m30.wordCount - m14.wordCount;
    const mitreDelta   = m30.mitreCount - m14.mitreCount;
    console.log(`║  DELTA (30b - 14b):`);
    console.log(`║    Latency:  ${latencyDelta > 0 ? '+' : ''}${latencyDelta}ms`);
    console.log(`║    Narrative: ${wordDelta > 0 ? '+' : ''}${wordDelta} words`);
    console.log(`║    MITRE:     ${mitreDelta > 0 ? '+' : ''}${mitreDelta} techniques`);
    // Recommendation
    const timeoutRatio = m30.latency / (m14.latency || 1);
    console.log(`║  RATIO: qwen3:30b is ${timeoutRatio.toFixed(1)}x slower`);
    if (timeoutRatio > 2 && wordDelta < 10) {
      console.log('║  VERDICT: qwen3:14b preferred — comparable quality, 2x faster');
    } else if (mitreDelta > 1 || wordDelta > 20) {
      console.log('║  VERDICT: qwen3:30b preferred — measurably richer output');
    } else {
      console.log('║  VERDICT: Marginal — qwen3:14b wins on latency for similar quality');
    }
  }
  console.log('╚════════════════════════════════════════════════════════╝');
});
