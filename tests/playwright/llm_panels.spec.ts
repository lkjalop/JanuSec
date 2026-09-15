import { test, expect } from '@playwright/test';

const BASE_URL = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:8080';

// Tier-1 LLM triage via UI panel
test('LLM Summary panel renders and triage runs', async ({ page }) => {
  await page.goto(BASE_URL + '/console');

  // Ensure the panel exists
  const panel = page.locator('#llmSummaryPanel');
  await expect(panel).toBeVisible();

  // Provider chips should render
  await expect(page.locator('#llmProv')).toBeVisible();
  await expect(page.locator('#llmReach')).toBeVisible();

  // Attempt to configure Ollama model in localStorage (best-effort)
  await page.evaluate(() => {
    try {
      localStorage.setItem('llm_settings', JSON.stringify({ ollama_host: 'http://127.0.0.1:11434', ollama_model: 'llama3:8b', ollama_generate_path: '/api/generate' }));
    } catch (_) {}
  });

  // Run triage
  await page.click('#btnRunLlmTriage');
  const body = page.locator('#llmSummaryBody');
  await expect(body).toBeVisible();
  await expect(body).toContainText(/Event triage|conf/i);
});

// Tier-2 LLM explain via direct API
test('LLM Explain endpoint returns structured JSON', async ({ request }) => {
  const payload = {
    row: { id: 'row-1', process: 'injector.exe', domain: 'example.com', sha256: 'deadbeef' },
    mapping_semantics: { user: 'alice', host: 'workstation01', process: 'injector.exe', file_hash: 'deadbeef', domain: 'example.com' },
    domain_diversity: { identity: 1, endpoint: 1, network: 1 },
    hopgraph_context: { chains: [{ src: 'alice', dst: 'example.com', score: 0.42 }] },
    context: { tier: 'tier2' }
  };
  const res = await request.post(BASE_URL + '/api/v1/llm/explain', { data: payload });
  expect(res.ok()).toBeTruthy();
  const j: any = await res.json();
  expect(j).toHaveProperty('explain');
  expect(j).toHaveProperty('path_context');
  expect(j.explain).toHaveProperty('final_score');
});

// Missing logs panel interaction
test('Missing logs panel shows default and click handler', async ({ page }) => {
  await page.goto(BASE_URL + '/console');
  const panel = page.locator('#ransomwareInsightsPanel');
  await expect(panel).toBeVisible();
  const missingList = page.locator('#ransomwareMissingLogs');
  await expect(missingList).toContainText(/No gaps detected/i);
  // Click the button and expect a notification to show
  const btn = page.locator('#btnMissingEvidence');
  await expect(btn).toBeVisible();
  await btn.click();
  const notif = page.locator('.notification').last();
  await expect(notif).toBeVisible();
});
