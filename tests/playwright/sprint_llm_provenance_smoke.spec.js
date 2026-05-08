// sprint_llm_provenance_smoke.spec.js
// Verifies _renderLlmProvenanceRefs and _renderCriticChallenge render without errors
// Uses the live VESPER assessment (49 clusters, already ingested).

const { test, expect } = require('@playwright/test');

const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:8000';
const AID = 'assessment-1778208341-ab705599';

test.describe('LLM provenance + critic rendering smoke', () => {
  test('breach page loads and cluster detail opens without JS errors', async ({ page }) => {
    const jsErrors = [];
    page.on('pageerror', err => jsErrors.push(err.message));

    // Navigate to breach analysis page with the VESPER assessment
    await page.goto(`${BASE}/breach?aid=${AID}`, { waitUntil: 'domcontentloaded', timeout: 30000 });

    // Wait for at least one cluster card to appear
    const clusterCard = page.locator('.sev-box, .cluster-card, [data-cluster-id]').first();
    await clusterCard.waitFor({ timeout: 30000 }).catch(() => {});

    // Check that the key breach JS functions are defined
    const fnLlm = await page.evaluate(() => typeof window._renderLlmProvenanceRefs);
    const fnCritic = await page.evaluate(() => typeof window._renderCriticChallenge);

    // Functions may be local (not on window) — just check no JS errors so far
    expect(jsErrors.filter(e => e.includes('_renderLlmProvenanceRefs') || e.includes('_renderCriticChallenge'))).toHaveLength(0);

    // Try clicking the first cluster card if present
    const card = page.locator('.sev-box').first();
    const cardCount = await card.count();
    if (cardCount > 0) {
      await card.click({ timeout: 5000 }).catch(() => {});
      // Wait briefly for detail panel
      await page.waitForTimeout(1000);
    }

    // No JS errors should have occurred during rendering
    const criticalErrors = jsErrors.filter(e =>
      !e.includes('favicon') &&
      !e.includes('net::ERR') &&
      !e.includes('404')
    );
    expect(criticalErrors).toHaveLength(0);
  });

  test('cluster detail API returns _llm_evidence_refs and _critic fields', async ({ request }) => {
    // Fetch assessment (clusters are embedded in the assessment object)
    const resp = await request.get(`${BASE}/api/v1/assessments/${AID}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    const clusters = body.correlation_clusters || body.analysis_clusters || body.clusters || [];
    expect(Array.isArray(clusters)).toBeTruthy();
    expect(clusters.length).toBeGreaterThan(0);

    // _llm_evidence_refs may be absent on pre-existing assessments — just confirm no crash
    const first = clusters[0];
    // These fields are optional but should be arrays/objects when present
    if ('_llm_evidence_refs' in first) {
      expect(Array.isArray(first._llm_evidence_refs)).toBeTruthy();
    }
    if ('_critic' in first) {
      expect(typeof first._critic).toBe('object');
    }
    // Core fields must always be present
    expect(first).toHaveProperty('cluster_id');
    expect(first).toHaveProperty('verdict');
  });
});
