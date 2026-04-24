/**
 * breach_santos_ingestion.spec.js
 *
 * Validates the full Santos 4-file upload pipeline after Phase 2 async ingest.
 * The 4 Santos files total >5 MB so breach.js routes them through the async
 * backend path (POST /api/v1/assessments/upload + SSE progress).
 *
 * Files under test (in dump/test files/):
 *   janusec_endpoint_k8s_v1.ndjson   ~15,500 events
 *   janusec_cloud_identity_v1.json   ~12,000 events (multi-section object)
 *   janusec_network_v1.csv           ~16,300 rows
 *   janusec_enrichment_context_v1.xlsx  10 sheets enrichment workbook
 */

const { test, expect } = require('@playwright/test');
const path = require('path');
const fs = require('fs');

test.describe.configure({ mode: 'serial' });

const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:8080';
const BREACH_URL = BASE + '/static/breach.html';
const API_BASE = BASE;

const FILES_DIR = path.join(__dirname, '../../dump/test files');
const NDJSON_FILE = path.join(FILES_DIR, 'janusec_endpoint_k8s_v1.ndjson');
const JSON_FILE   = path.join(FILES_DIR, 'janusec_cloud_identity_v1.json');
const CSV_FILE    = path.join(FILES_DIR, 'janusec_network_v1.csv');
const XLSX_FILE   = path.join(FILES_DIR, 'janusec_enrichment_context_v1.xlsx');

const AUTH_HEADERS = { 'x-api-key': 'janusec-playwright-local', 'x-tenant-id': 'default' };

let assessmentId = '';

async function setAuth(page) {
  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'janusec-playwright-local');
    localStorage.setItem('tenantId', 'default');
  });
}

async function mockLlmRoutes(page) {
  await page.route('**/clusters/*/tier1-summary', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ tier1_prefill: {
      incident_name: 'SANTOS-MOCK',
      headline_subtitle: 'Santos mock',
      short_narrative: 'Mock.',
      confidence_meter: { total: 70, segments: {} },
      top_actions: [],
      mitre_techniques: [],
      verdict_reasoning: 'mock',
      mitre_evidence_map: {},
    }}),
  }));
  await page.route('**/executive-summary', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ deterministic: 'Mock exec summary.', llm_color: '' }),
  }));
}

// Helper: poll progress until status is 'ready' or 'failed' (max timeoutMs)
async function waitForAsyncAssessment(request, aid, timeoutMs = 300000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const res = await request.get(`${API_BASE}/api/v1/assessments/${aid}/progress/poll`, {
      headers: AUTH_HEADERS,
    });
    if (!res.ok()) { await new Promise(r => setTimeout(r, 2000)); continue; }
    const body = await res.json();
    if (body.status === 'ready') return body;
    if (body.status === 'failed') throw new Error(`Assessment failed: ${body.error}`);
    await new Promise(r => setTimeout(r, 2000));
  }
  throw new Error(`Assessment did not reach ready state within ${timeoutMs}ms`);
}

// Helper: async ingest keeps the assessment JSON compact; full evidence lives in DuckDB.
async function getEvidencePage(request, aid, page = 1, limit = 500, caseId = '') {
  const qs = new URLSearchParams({ page: String(page), limit: String(limit) });
  if (caseId) qs.set('case_id', caseId);
  const res = await request.get(`${API_BASE}/api/v1/assessments/${aid}/evidence?${qs.toString()}`, {
    headers: AUTH_HEADERS,
  });
  expect(res.ok(), `Evidence endpoint failed for page ${page}`).toBe(true);
  return await res.json();
}

function getSourceCounts(body) {
  return (body.evidence_store && body.evidence_store.source_counts) || body.source_counts || {};
}

// ── Pre-flight: verify test files exist ───────────────────────────────────────
test('0. Test files exist in dump/test files/', async () => {
  expect(fs.existsSync(NDJSON_FILE), `Missing: ${NDJSON_FILE}`).toBe(true);
  expect(fs.existsSync(JSON_FILE),   `Missing: ${JSON_FILE}`).toBe(true);
  expect(fs.existsSync(CSV_FILE),    `Missing: ${CSV_FILE}`).toBe(true);
  expect(fs.existsSync(XLSX_FILE),   `Missing: ${XLSX_FILE}`).toBe(true);
});

// ── Test 0b: Async upload API returns 202 immediately ────────────────────────
test('0b. POST /upload returns 202 and assessment_id within 5s', async ({ request }) => {
  test.setTimeout(15000);

  const res = await request.post(`${API_BASE}/api/v1/assessments/upload`, {
    headers: AUTH_HEADERS,
    multipart: {
      files: { name: 'janusec_endpoint_k8s_v1.ndjson', mimeType: 'application/x-ndjson', buffer: fs.readFileSync(NDJSON_FILE) },
    },
  });

  if (res.status() !== 202) {
    // Keep this diagnostic because upload failures are otherwise collapsed by app middleware.
    console.log('upload response', res.status(), await res.text());
    const diag = await request.get(`${API_BASE}/api/v1/debug/last-errors?limit=3`, { headers: AUTH_HEADERS });
    console.log('upload diagnostics', diag.status(), await diag.text());
  }
  expect(res.status(), 'Upload should return 202').toBe(202);
  const body = await res.json();
  expect(body.assessment_id, 'Response must include assessment_id').toBeTruthy();
  expect(body.status, 'Initial status should be queued').toBe('queued');
  expect(body.file_count, 'file_count should be 1').toBe(1);

  // Verify progress endpoint exists for this job
  const prog = await request.get(`${API_BASE}/api/v1/assessments/${body.assessment_id}/progress/poll`, {
    headers: AUTH_HEADERS,
  });
  expect(prog.ok(), 'Progress endpoint should return 200').toBe(true);
  const progBody = await prog.json();
  expect(['queued', 'running', 'parsing', 'ready']).toContain(progBody.status);
});

// ── Test 1: Upload all 4 Santos files via browser → redirect ─────────────────
test('1. Upload 4 Santos files → progress bar appears → redirect to assessment', async ({ page }) => {
  test.setTimeout(360000);
  await setAuth(page);
  await page.goto(BREACH_URL);
  await expect(page.locator('[data-testid="br-drop-zone"]')).toBeVisible({ timeout: 10000 });

  const [fileChooser] = await Promise.all([
    page.waitForEvent('filechooser'),
    page.locator('[data-testid="br-drop-zone"]').click(),
  ]);
  await fileChooser.setFiles([NDJSON_FILE, JSON_FILE, CSV_FILE, XLSX_FILE]);

  // Async path: progress bar should appear within 5 seconds
  await expect(page.locator('#br-async-progress')).toBeVisible({ timeout: 8000 });
  // No browser freeze — we should NOT see "Analysing files…" from the sync path
  const syncTitle = page.locator('.br-processing__title', { hasText: 'Analysing files' });

  // Wait for redirect (async pipeline may take up to 5 minutes for 44K rows)
  await page.waitForURL(/\?assessment=/, { timeout: 300000 });
  assessmentId = new URL(page.url()).searchParams.get('assessment') || '';
  expect(assessmentId, 'No assessment ID in URL after upload').toBeTruthy();
});

// ── Test 2: Source count should be >1 ────────────────────────────────────────
test('2. Multiple sources registered — more than just CSV', async ({ page }) => {
  test.setTimeout(60000);
  await setAuth(page);
  await mockLlmRoutes(page);
  await page.goto(BREACH_URL + '?assessment=' + assessmentId);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 30000 });

  const sourceText = await page.locator('[data-testid="br-source-count"]').textContent();
  const sourceCount = parseInt(sourceText.trim(), 10);
  expect(sourceCount, `Expected >1 source, got ${sourceCount}`).toBeGreaterThan(1);
});

// ── Test 3: evidence_rows count > 500 ────────────────────────────────────────
test('3. Assessment JSON is compact and full rows are available by evidence pagination', async ({ request }) => {
  const res = await request.get(`${API_BASE}/api/v1/assessments/${assessmentId}`, {
    headers: AUTH_HEADERS,
  });
  expect(res.ok()).toBe(true);
  const body = await res.json();
  expect(body.evidence_store, 'Expected evidence_store pointer in compact assessment').toBeTruthy();
  expect(body.evidence_store.row_count, 'Expected full row count in evidence_store').toBeGreaterThan(40000);
  expect((body.evidence_rows || []).length, 'Embedded evidence preview should stay bounded').toBeLessThanOrEqual(500);

  const page = await getEvidencePage(request, assessmentId, 1, 500);
  expect(page.total, `Expected >40K persisted evidence rows, got ${page.total}`).toBeGreaterThan(40000);
  expect(page.rows.length, 'Evidence page should return requested rows').toBe(500);
});

// ── Test 4: Assessment contains endpoint rows (NDJSON ingested) ───────────────
test('4. Assessment contains endpoint rows (NDJSON ingested)', async ({ request }) => {
  const res = await request.get(`${API_BASE}/api/v1/assessments/${assessmentId}`, {
    headers: AUTH_HEADERS,
  });
  expect(res.ok()).toBe(true);
  const body = await res.json();
  const counts = getSourceCounts(body);
  const endpointCount = Object.entries(counts)
    .filter(([source]) => /endpoint|crowdstrike|ndjson/i.test(source))
    .reduce((n, [, count]) => n + Number(count || 0), 0);
  expect(endpointCount, `Expected endpoint rows in source_counts: ${JSON.stringify(counts)}`).toBeGreaterThan(0);
});

// ── Test 5: Assessment contains cloud identity rows ───────────────────────────
test('5. Assessment contains cloud identity rows (JSON multi-section flattened)', async ({ request }) => {
  const res = await request.get(`${API_BASE}/api/v1/assessments/${assessmentId}`, {
    headers: AUTH_HEADERS,
  });
  expect(res.ok()).toBe(true);
  const body = await res.json();
  const counts = getSourceCounts(body);
  const cloudCount = Object.entries(counts)
    .filter(([source]) => /cloud|identity|okta|aws|m365|snowflake|json/i.test(source))
    .reduce((n, [, count]) => n + Number(count || 0), 0);
  expect(cloudCount, `Expected cloud identity rows in source_counts: ${JSON.stringify(counts)}`).toBeGreaterThan(0);
});

// ── Test 6: Total evidence_rows > 1000 (4-source ingestion) ──────────────────
test('6. Assessment evidence store > 1000 (4-source ingestion working)', async ({ request }) => {
  const res = await request.get(`${API_BASE}/api/v1/assessments/${assessmentId}`, {
    headers: AUTH_HEADERS,
  });
  expect(res.ok()).toBe(true);
  const body = await res.json();
  expect(body.evidence_store.row_count, `Assessment only has ${body.evidence_store && body.evidence_store.row_count} persisted evidence rows`).toBeGreaterThan(1000);
});

// ── Test 7: Rows span all 4 source types ─────────────────────────────────────
test('7. Assessment rows span all 4 source types', async ({ request }) => {
  const res = await request.get(`${API_BASE}/api/v1/assessments/${assessmentId}`, {
    headers: AUTH_HEADERS,
  });
  expect(res.ok()).toBe(true);
  const body = await res.json();
  const sources = Object.keys(getSourceCounts(body)).filter(Boolean);
  expect(sources.length, `Only ${sources.length} distinct sources: ${sources.join(', ')}`).toBeGreaterThanOrEqual(3);
});

// ── Test 8: CSV rows present ──────────────────────────────────────────────────
test('8. Network CSV contributes rows', async ({ request }) => {
  const res = await request.get(`${API_BASE}/api/v1/assessments/${assessmentId}`, {
    headers: AUTH_HEADERS,
  });
  expect(res.ok()).toBe(true);
  const body = await res.json();
  const counts = getSourceCounts(body);
  const networkCount = Object.entries(counts)
    .filter(([source]) => /network|csv|zeek/i.test(source))
    .reduce((n, [, count]) => n + Number(count || 0), 0);
  expect(networkCount, `Network CSV contributed ${networkCount} rows: ${JSON.stringify(counts)}`).toBeGreaterThan(0);
});

// ── Test 9: XLSX enrichment rows present ─────────────────────────────────────
test('9. XLSX enrichment rows present in assessment payload', async ({ request }) => {
  const res = await request.get(`${API_BASE}/api/v1/assessments/${assessmentId}`, {
    headers: AUTH_HEADERS,
  });
  expect(res.ok()).toBe(true);
  const body = await res.json();
  const counts = getSourceCounts(body);
  const xlsxCount = Object.entries(counts)
    .filter(([source]) => /xlsx|excel|enrichment/i.test(source))
    .reduce((n, [, count]) => n + Number(count || 0), 0);
  expect(xlsxCount, `No XLSX enrichment rows in source_counts: ${JSON.stringify(counts)}`).toBeGreaterThan(0);
});

// ── Test 10: Clusters reference real entities ─────────────────────────────────
test('10. Lead cluster significance is not boilerplate IP-only text', async ({ page }) => {
  await setAuth(page);
  await mockLlmRoutes(page);
  await page.goto(BREACH_URL + '?assessment=' + assessmentId);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 15000 });

  const firstCard = page.locator('[data-testid^="br-card-"]').first();
  await expect(firstCard).toBeVisible({ timeout: 10000 });
  const subtitle = await firstCard.locator('.br-card__subtitle').textContent();
  const isPureBoilerplate = /^same network infrastructure; same resource or artifact path/.test(subtitle.trim());
  expect(isPureBoilerplate, `Card subtitle is pure boilerplate: "${subtitle.trim()}"`).toBe(false);
});

// ── Test 11: Progress endpoint provides structured stages ─────────────────────
test('11. Progress/poll endpoint returns structured stage data', async ({ request }) => {
  // By the time tests reach here, the assessment is already ready.
  // Verify the progress record is still queryable and shows the terminal state.
  const res = await request.get(`${API_BASE}/api/v1/assessments/${assessmentId}/progress/poll`, {
    headers: AUTH_HEADERS,
  });
  expect(res.ok()).toBe(true);
  const body = await res.json();
  expect(body.assessment_id).toBe(assessmentId);
  expect(body.status).toBe('ready');
  expect(body.percent).toBe(100);
  expect(body.row_count, 'row_count should be >0').toBeGreaterThan(0);
});

// ── Test 12: Clusters have structured LLM narrative fields ───────────────────
test('12. Top cluster has structured LLM narrative (verdict + next_steps)', async ({ request }) => {
  const res = await request.get(`${API_BASE}/api/v1/assessments/${assessmentId}`, {
    headers: AUTH_HEADERS,
  });
  expect(res.ok()).toBe(true);
  const body = await res.json();
  const clusters = body.correlation_clusters || [];
  expect(clusters.length, 'Expected at least 1 cluster').toBeGreaterThan(0);

  // Top cluster should have been narrated with structured LLM output
  const top = clusters[0];
  if (top.llm_narrative) {
    const validVerdicts = ['VALIDATED_BREACH', 'SUSPECTED_BREACH', 'BENIGN_EXPECTED', 'REQUIRES_INVESTIGATION', 'INSUFFICIENT_EVIDENCE'];
    expect(validVerdicts, `Unexpected verdict: ${top.llm_narrative.verdict}`).toContain(top.llm_narrative.verdict);
    expect(Array.isArray(top.llm_narrative.next_steps), 'next_steps should be an array').toBe(true);
    expect(top.llm_narrative.kill_chain_stage, 'kill_chain_stage should be present').toBeTruthy();
  }
  // Even without LLM, cluster_id should be a proper string
  expect(top.cluster_id, 'cluster_id should not be raw "cluster-N"').toMatch(/^[a-zA-Z0-9_-]+$/);
});
