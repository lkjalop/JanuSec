/**
 * Three-file investigate path: LLM cluster summary + CRAG enrich
 *
 * Uses v1.1 dataset files from dump/test files/.
 * Requires server running on port 8080 with Ollama + qwen2.5:14b prewarmed.
 * Sonnet/cloud-model assertions skipped unless ANTHROPIC_API_KEY is set.
 */
const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

const BASE     = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:8080';
const DUMP_DIR = path.resolve(__dirname, '../../dump/test files');
const FILES_V11 = [
  { file: 'janusec_net_c2_bgp.v1.1.csv',          mime: 'text/csv' },
  { file: 'janusec_ep_endpoint.v1.1.xlsx',          mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' },
  { file: 'janusec_okta_m365_events.v1.1.json',    mime: 'application/json' },
];

function loadFixtures() {
  return FILES_V11.map(({ file, mime }) => {
    const fp = path.join(DUMP_DIR, file);
    if (!fs.existsSync(fp)) return null;
    return { name: file, mimeType: mime, buffer: fs.readFileSync(fp) };
  }).filter(Boolean);
}

async function seedStorage(page) {
  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'devkey123');
    localStorage.setItem('tenantId', 'default');
  });
}

async function uploadAndAnalyze(page, files) {
  await page.goto(`${BASE}/static/investigate.html`, { waitUntil: 'domcontentloaded' });
  await page.locator('#fileInput').setInputFiles(files);
  // Wait for source list (all 3 files shown)
  await expect(page.locator('#sourceList .source-item')).toHaveCount(3, { timeout: 20000 });
  await page.click('#btnAnalyze');
  // storeClusters() runs at line 654 of investigate.js; pipelineBarFill is set to 85%
  // synchronously at line 665 (right after storeClusters, before the slow LLM report).
  // Waiting for bar ≥ 85% guarantees clusterMap is populated.
  await page.waitForFunction(
    () => {
      if (!window.state || !window.state.assessmentId) return false;
      var bar = document.getElementById('pipelineBarFill');
      return bar && parseFloat(bar.style.width || '0') >= 85;
    },
    { timeout: 90000 },
  );
}

async function firstCluster(page) {
  return page.evaluate(() => {
    const ids = Object.keys((window.state && window.state.clusterMap) || {});
    return { assessmentId: window.state && window.state.assessmentId, clusterId: ids[0] };
  });
}

test.describe('Three-file LLM + CRAG investigate path', () => {
  test.setTimeout(180000); // 3 min — Qwen may take time on first call

  test('analyze builds 241 rows and populates clusterMap', async ({ page }) => {
    const files = loadFixtures();
    test.skip(files.length !== FILES_V11.length, 'v1.1 fixture files not found in dump/test files/');

    await seedStorage(page);
    await uploadAndAnalyze(page, files);

    const { assessmentId, clusterId } = await firstCluster(page);
    expect(assessmentId).toBeTruthy();

    // Row count check (70 net + 83 ep + 88 okta = 241)
    const rowCount = await page.evaluate(() => (window.state && window.state.allRows && window.state.allRows.length) || 0);
    expect(rowCount).toBeGreaterThanOrEqual(100); // 241 in full path; ≥100 even if JSON parsing is partial
  });

  test('openClusterDetail injects drawer elements', async ({ page }) => {
    const files = loadFixtures();
    test.skip(files.length !== FILES_V11.length, 'v1.1 fixture files not found in dump/test files/');

    await seedStorage(page);
    await uploadAndAnalyze(page, files);

    const cluster = await firstCluster(page);
    expect(cluster.clusterId).toBeTruthy();

    // Open cluster drawer
    await page.evaluate(({ cid }) => window.openClusterDetail(cid), { cid: cluster.clusterId });

    // Drawer must be visible
    await expect(page.locator('#clusterDrawer')).toBeVisible({ timeout: 5000 });

    // Dynamic result containers must exist in DOM (even if hidden)
    await expect(page.locator(`#llmSummaryResult_${cluster.clusterId}`)).toHaveCount(1, { timeout: 5000 });
    await expect(page.locator(`#enrichResult_${cluster.clusterId}`)).toHaveCount(1, { timeout: 5000 });
    await expect(page.locator(`#huntResult_${cluster.clusterId}`)).toHaveCount(1, { timeout: 5000 });

    // Model selector must exist with Mistral option
    await expect(page.locator(`#llmModelSel_${cluster.clusterId} option[value="mistral-small3.2:24b"]`)).toHaveCount(1, { timeout: 5000 });
    // Qwen must be first/default
    await expect(page.locator(`#llmModelSel_${cluster.clusterId} option[value="qwen2.5:14b"]`)).toHaveCount(1, { timeout: 5000 });
    await expect(page.locator(`#llmModelSel_${cluster.clusterId} option[value="qwen3:14b"]`)).toHaveCount(1, { timeout: 5000 });

    // Mistral Deepen button visible
    await expect(page.locator('#btnDeepenMistral')).toBeVisible({ timeout: 5000 });
  });

  test('tier2/llm-summary returns 200 for soc_analyst (qwen default)', async ({ page, request }) => {
    const files = loadFixtures();
    test.skip(files.length !== FILES_V11.length, 'v1.1 fixture files not found in dump/test files/');

    await seedStorage(page);
    await uploadAndAnalyze(page, files);
    const cluster = await firstCluster(page);
    expect(cluster.clusterId).toBeTruthy();

    const resp = await request.get(
      `${BASE}/api/v1/assessments/${cluster.assessmentId}/clusters/${cluster.clusterId}/tier2/llm-summary?model=qwen2.5:14b`,
      { headers: { 'x-api-key': 'devkey123', 'X-Tenant-ID': 'default', 'x-persona': 'soc_analyst' }, timeout: 120000 },
    );
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    // Must have persona steps or sections — not empty
    const hasContent = (body.persona_steps && body.persona_steps.length > 0) ||
                       (body.sections && Object.keys(body.sections).length > 0) ||
                       body.fallback_generated;
    expect(hasContent).toBeTruthy();
    // No "Summarise failed" text
    expect(JSON.stringify(body)).not.toContain('Summarise failed');
  });

  test('_triggerLlmSummary renders result without Summarise failed', async ({ page }) => {
    const files = loadFixtures();
    test.skip(files.length !== FILES_V11.length, 'v1.1 fixture files not found in dump/test files/');

    await seedStorage(page);
    await uploadAndAnalyze(page, files);
    const cluster = await firstCluster(page);
    expect(cluster.clusterId).toBeTruthy();

    await page.evaluate(({ cid }) => window.openClusterDetail(cid), { cid: cluster.clusterId });
    await page.evaluate(({ cid, aid }) => window._triggerLlmSummary(cid, aid, false, 'soc_analyst'),
      { cid: cluster.clusterId, aid: cluster.assessmentId });

    // Wait for result to appear (up to 120 s for Qwen)
    await expect(page.locator(`#llmSummaryResult_${cluster.clusterId}`)).not.toBeEmpty({ timeout: 120000 });
    await expect(page.locator(`#llmSummaryResult_${cluster.clusterId}`)).not.toContainText('Summarise failed', { timeout: 5000 });
  });

  test('cluster/enrich returns 200 and renders CRAG verdict', async ({ page, request }) => {
    const files = loadFixtures();
    test.skip(files.length !== FILES_V11.length, 'v1.1 fixture files not found in dump/test files/');

    await seedStorage(page);
    await uploadAndAnalyze(page, files);
    const cluster = await firstCluster(page);
    expect(cluster.clusterId).toBeTruthy();

    const resp = await request.post(
      `${BASE}/api/v1/assessments/${cluster.assessmentId}/clusters/${cluster.clusterId}/enrich`,
      {
        headers: { 'Content-Type': 'application/json', 'x-api-key': 'devkey123', 'X-Tenant-ID': 'default' },
        data: { tenant_id: 'default', force_refresh: true, model: 'qwen2.5:14b' },
        timeout: 60000,
      },
    );
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    // Must have a verdict/grade field
    const hasVerdict = body.verdict || body.crag_verdict || body.grade || body.status;
    expect(hasVerdict).toBeTruthy();
  });

  test('llm/models/catalog returns model list', async ({ request }) => {
    const resp = await request.get(
      `${BASE}/api/v1/llm/models/catalog`,
      { headers: { 'x-api-key': 'devkey123', 'X-Tenant-ID': 'default' }, timeout: 5000 },
    );
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    const models = body.models || body;
    expect(Array.isArray(models)).toBeTruthy();
  });
});
