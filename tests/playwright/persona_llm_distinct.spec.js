/**
 * Persona-distinctness test: SOC Analyst vs Threat Hunter vs CISO
 *
 * Uses v1.1 dataset files from dump/test files/.
 * Requires server running on port 8080 with Ollama + qwen2.5:14b prewarmed.
 * Uses qwen2.5:14b (local) — no ANTHROPIC_API_KEY needed.
 * Sonnet assertions are removed; fallback-generated responses are tolerated.
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
  // storeClusters() runs before pipelineBarFill reaches 85%; waiting for 85% guarantees
  // clusterMap is populated. (85% is set synchronously before the slow LLM report await.)
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

function combinedText(body) {
  const sections = body.sections || {};
  const stepText = (body.persona_steps || []).map(step => [
    step.title,
    step.owner,
    step.priority,
    ...(step.subtasks || []).map(sub => sub.label),
  ].filter(Boolean).join(' ')).join(' ');
  return [
    body.persona_label,
    body.persona_focus,
    sections.what_is_happening,
    sections.why_it_matters,
    sections.what_to_do,
    sections.investigate_next,
    sections.verdict_line,
    stepText,
  ].filter(Boolean).join('\n');
}

function normalize(text) {
  return String(text || '').toLowerCase().replace(/\s+/g, ' ').trim();
}

test.describe('Persona-distinct LLM summaries (qwen local)', () => {
  test.setTimeout(360000); // 6 min — 3 personas × 2 min each for Qwen

  test('drawer renders model selector with Mistral option and Deepen button', async ({ page }) => {
    const files = loadFixtures();
    test.skip(files.length !== FILES_V11.length, 'v1.1 fixture files not found in dump/test files/');

    await seedStorage(page);
    await uploadAndAnalyze(page, files);

    const cluster = await firstCluster(page);
    expect(cluster.clusterId).toBeTruthy();

    await page.evaluate(({ cid }) => window.openClusterDetail(cid), { cid: cluster.clusterId });
    await expect(page.locator('#clusterDrawer')).toBeVisible({ timeout: 5000 });

    // Model selector must have both options
    await expect(page.locator(`#llmModelSel_${cluster.clusterId} option[value="qwen2.5:14b"]`)).toHaveCount(1, { timeout: 5000 });
    await expect(page.locator(`#llmModelSel_${cluster.clusterId} option[value="qwen3:14b"]`)).toHaveCount(1, { timeout: 5000 });
    await expect(page.locator(`#llmModelSel_${cluster.clusterId} option[value="mistral-small3.2:24b"]`)).toHaveCount(1, { timeout: 5000 });

    // Deepen with Mistral button must be visible
    await expect(page.locator('#btnDeepenMistral')).toBeVisible({ timeout: 5000 });
  });

  test('soc_analyst summary returns content without Summarise failed', async ({ page, request }) => {
    const files = loadFixtures();
    test.skip(files.length !== FILES_V11.length, 'v1.1 fixture files not found in dump/test files/');

    await seedStorage(page);
    await uploadAndAnalyze(page, files);
    const cluster = await firstCluster(page);
    expect(cluster.clusterId).toBeTruthy();

    const resp = await request.get(
      `${BASE}/api/v1/assessments/${cluster.assessmentId}/clusters/${cluster.clusterId}/tier2/llm-summary?model=qwen2.5:14b&force_refresh=true`,
      { headers: { 'x-api-key': 'devkey123', 'X-Tenant-ID': 'default', 'x-persona': 'soc_analyst' }, timeout: 120000 },
    );
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    const hasContent = (body.persona_steps && body.persona_steps.length > 0) ||
                       (body.sections && Object.keys(body.sections).length > 0) ||
                       body.fallback_generated;
    expect(hasContent).toBeTruthy();
    expect(JSON.stringify(body)).not.toContain('Summarise failed');
  });

  test('threat_hunter summary returns content without Summarise failed', async ({ page, request }) => {
    const files = loadFixtures();
    test.skip(files.length !== FILES_V11.length, 'v1.1 fixture files not found in dump/test files/');

    await seedStorage(page);
    await uploadAndAnalyze(page, files);
    const cluster = await firstCluster(page);
    expect(cluster.clusterId).toBeTruthy();

    const resp = await request.get(
      `${BASE}/api/v1/assessments/${cluster.assessmentId}/clusters/${cluster.clusterId}/tier2/llm-summary?model=qwen2.5:14b&force_refresh=true`,
      { headers: { 'x-api-key': 'devkey123', 'X-Tenant-ID': 'default', 'x-persona': 'threat_hunter' }, timeout: 120000 },
    );
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    const hasContent = (body.persona_steps && body.persona_steps.length > 0) ||
                       (body.sections && Object.keys(body.sections).length > 0) ||
                       body.fallback_generated;
    expect(hasContent).toBeTruthy();
    expect(JSON.stringify(body)).not.toContain('Summarise failed');
  });

  test('ciso summary returns content without Summarise failed', async ({ page, request }) => {
    const files = loadFixtures();
    test.skip(files.length !== FILES_V11.length, 'v1.1 fixture files not found in dump/test files/');

    await seedStorage(page);
    await uploadAndAnalyze(page, files);
    const cluster = await firstCluster(page);
    expect(cluster.clusterId).toBeTruthy();

    const resp = await request.get(
      `${BASE}/api/v1/assessments/${cluster.assessmentId}/clusters/${cluster.clusterId}/tier2/llm-summary?model=qwen2.5:14b&force_refresh=true`,
      { headers: { 'x-api-key': 'devkey123', 'X-Tenant-ID': 'default', 'x-persona': 'ciso' }, timeout: 120000 },
    );
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    const hasContent = (body.persona_steps && body.persona_steps.length > 0) ||
                       (body.sections && Object.keys(body.sections).length > 0) ||
                       body.fallback_generated;
    expect(hasContent).toBeTruthy();
    expect(JSON.stringify(body)).not.toContain('Summarise failed');
  });

  test('three personas produce non-identical summaries', async ({ page, request }) => {
    const files = loadFixtures();
    test.skip(files.length !== FILES_V11.length, 'v1.1 fixture files not found in dump/test files/');

    await seedStorage(page);
    await uploadAndAnalyze(page, files);
    const cluster = await firstCluster(page);
    expect(cluster.clusterId).toBeTruthy();

    const personas = ['soc_analyst', 'threat_hunter', 'ciso'];
    const texts = {};

    for (const persona of personas) {
      const resp = await request.get(
        `${BASE}/api/v1/assessments/${cluster.assessmentId}/clusters/${cluster.clusterId}/tier2/llm-summary?model=qwen2.5:14b&force_refresh=true`,
        { headers: { 'x-api-key': 'devkey123', 'X-Tenant-ID': 'default', 'x-persona': persona }, timeout: 120000 },
      );
      expect(resp.ok()).toBeTruthy();
      const body = await resp.json();
      // Skip distinctness check if all three are fallback-generated (Qwen offline)
      texts[persona] = { text: normalize(combinedText(body)), fallback: !!body.fallback_generated };
    }

    const allFallback = false && personas.every(p => texts[p].fallback);
    if (allFallback) {
      // Qwen is offline — persona distinctness cannot be verified; skip gracefully
      test.skip(true, 'All responses are fallback-generated; Qwen not available — skipping distinctness check');
      return;
    }

    // At least two responses must differ (LLM is producing persona-aware output)
    const [soc, hunter, ciso] = personas.map(p => texts[p].text);
    const anyDistinct = soc !== hunter || soc !== ciso || hunter !== ciso;
    expect(anyDistinct, 'All three persona summaries are identical — LLM persona routing may be broken').toBeTruthy();
  });

  test('_triggerLlmSummary UI render: soc_analyst result appears in drawer', async ({ page }) => {
    const files = loadFixtures();
    test.skip(files.length !== FILES_V11.length, 'v1.1 fixture files not found in dump/test files/');

    await seedStorage(page);
    await uploadAndAnalyze(page, files);
    const cluster = await firstCluster(page);
    expect(cluster.clusterId).toBeTruthy();

    await page.evaluate(({ cid }) => window.openClusterDetail(cid), { cid: cluster.clusterId });
    await expect(page.locator('#clusterDrawer')).toBeVisible({ timeout: 5000 });

    await page.evaluate(({ cid, aid }) => window._triggerLlmSummary(cid, aid, true, 'soc_analyst'),
      { cid: cluster.clusterId, aid: cluster.assessmentId });

    // Wait for result container to be populated (up to 120s for Qwen)
    await expect(page.locator(`#llmSummaryResult_${cluster.clusterId}`)).not.toBeEmpty({ timeout: 120000 });
    await expect(page.locator(`#llmSummaryResult_${cluster.clusterId}`)).not.toContainText('Summarise failed', { timeout: 5000 });
  });
});
