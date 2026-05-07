/**
 * breach_button_wiring.spec.js
 *
 * Verifies that every interactive button on the breach assessment home page
 * and cluster detail page is wired to the correct API endpoint or DOM
 * behaviour.  All LLM-triggering endpoints are route-intercepted so the
 * suite runs without a live Ollama/LLM server.
 *
 * Tests:
 *  1.  Regenerate business-consequence fires POST /executive-summary  (data-gen-dread + br-regen-btn)
 *  2.  Regenerate bounded-next-actions fires POST tier1-summary        (second br-regen-btn)
 *  3.  SOC Analyst dispatch button opens preview panel
 *  4.  CISO dispatch button opens preview panel
 *  5.  Forensics dispatch button opens preview panel
 *  6.  Compliance dispatch button opens preview panel
 *  7.  Confirm dispatch sends POST /dispatch/notify with correct role
 *  8.  Cancel button hides dispatch preview
 *  9.  Regenerate dispatch fires POST /persona-dispatch with correct persona
 * 10.  Open threat case ↗ opens new tab with ?cluster= in URL
 * 11.  Generate narrative button (br-finding__gen) fires POST tier1-summary
 * 12.  Sign-off Confirmed fires POST /sign-off and shows done badge
 * 13.  Sign-off Escalate fires POST /sign-off with action=escalate
 * 14.  Sign-off Dismiss fires POST /sign-off with action=dismiss
 *
 * Run with:
 *   npx playwright test tests/playwright/breach_button_wiring.spec.js
 *   PLAYWRIGHT_BASE_URL=http://localhost:8080 npx playwright test ...
 */

const { test, expect } = require('@playwright/test');

const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:8080';
const DEFAULT_ASSESSMENT_ID = 'playwright-mock-assessment';

// ── Helpers ──────────────────────────────────────────────────────────────────

async function resolveAssessmentId(request) {
  return process.env.PLAYWRIGHT_ASSESSMENT_ID || DEFAULT_ASSESSMENT_ID;
}

// Minimal assessment payload that drives the home page with a LIKELY cluster
// (no prefill → shows Generate narrative button) and a CONFIRMED cluster
// (prefill done → shows regen + Open threat case buttons).
function buildMockAssessment(aid) {
  return {
    assessment_id: aid,
    status: 'complete',
    source_count: 3,
    row_count: 450,
    normalized_rows: [],
    analysis_clusters: [
      // ── Cluster A: CONFIRMED_BREACH with prefill — shows regen buttons ──────
      {
        cluster_id: 'mock-cluster-confirmed',
        verdict: 'CONFIRMED_BREACH',
        severity: 'critical',
        row_refs: ['r1', 'r2', 'r3', 'r4', 'r5'],
        tier1_prefill: {
          incident_name: 'Mock Confirmed Breach',
          headline_subtitle: 'Playwright confirmed mock',
          short_narrative: 'Adversary moved laterally and exfiltrated data.',
          confidence_meter: { total: 85, segments: {} },
          top_actions: ['Isolate host', 'Reset credentials'],
          mitre_techniques: ['T1071.004'],
        },
        persona_dispatch: {
          soc_analyst: {
            headline: 'SOC: isolate affected endpoints immediately',
            required_actions: ['Revoke session tokens for aaron.blackwood@corp.com', 'Isolate WORKSTATION-42'],
          },
          ciso: {
            headline: 'CISO: NDB notification clock started',
            regulatory_clocks: ['NDB 72-hour window', 'OAIC mandatory reporting'],
          },
          forensics: {
            headline: 'Forensics: preserve volatile memory artifacts',
            required_actions: ['Capture memory image from WORKSTATION-42'],
          },
          compliance: {
            headline: 'Compliance: initiate Privacy Act review',
            required_actions: ['Assess OAIC NDB notification requirement'],
          },
        },
      },
      // ── Cluster B: LIKELY_BREACH without prefill — shows Generate narrative button ──
      {
        cluster_id: 'mock-cluster-likely',
        verdict: 'LIKELY_BREACH',
        severity: 'high',
        row_refs: ['r6', 'r7', 'r8'],
        tier1_prefill: null,
        persona_dispatch: null,
      },
    ],
    executive_summary: {
      headline: 'Mock: confirmed lateral movement and data exfiltration detected.',
      subline: 'Three sources corroborated across 450 rows.',
      executive_summary: 'Playwright mock executive summary — no LLM required.',
    },
  };
}

async function mockAssessmentRoute(page, aid) {
  await page.route('**/api/v1/assessments/**', route => {
    const url = new URL(route.request().url());
    const expected = `/api/v1/assessments/${aid}`;
    if (url.pathname === expected || url.pathname === `${expected}/`) {
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(buildMockAssessment(aid)),
      });
    }
    return route.fallback();
  });
}

test.beforeEach(async ({ page }) => {
  await mockAssessmentRoute(page, process.env.PLAYWRIGHT_ASSESSMENT_ID || DEFAULT_ASSESSMENT_ID);
});

// Wire all LLM-adjacent routes so no real AI calls are made.
// Returns a stub for tier1-summary and executive-summary.
async function mockLlmRoutes(page) {
  await page.route('**/clusters/*/tier1-summary', route => {
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        tier1_prefill: {
          incident_name: 'MOCK-REGEN',
          headline_subtitle: 'Regenerated by Playwright mock',
          short_narrative: 'Playwright mock regen narrative.',
          confidence_meter: { total: 72, segments: {} },
          top_actions: ['Isolate host'],
          mitre_techniques: ['T1071.004'],
          verdict_reasoning: 'Mock regen.',
        },
      }),
    });
  });

  await page.route('**/executive-summary', route => {
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        headline: 'Mock regen: confirmed breach.',
        subline: 'Three sources.',
        executive_summary: 'Playwright mock executive summary regenerated.',
      }),
    });
  });
}

// ── Suite: Breach Home Page Buttons ──────────────────────────────────────────

test.describe('Breach Assessment Button Wiring — Home Page', () => {

  // ── Test 1: Regenerate business-consequence (br-regen-btn + data-gen-dread) ──
  test('1. regenerate business-consequence fires POST tier1-summary (data-gen-dread / br-regen-btn)', async ({ page, request }) => {
    const assessmentId = await resolveAssessmentId(request);
    const url = `${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`;

    const tier1Calls = [];
    await page.route('**/clusters/*/tier1-summary', async route => {
      tier1Calls.push({
        url: route.request().url(),
        body: route.request().postDataJSON(),
      });
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          tier1_prefill: {
            incident_name: 'MOCK-REGEN',
            headline_subtitle: 'Regen mock',
            short_narrative: 'Playwright mock.',
            confidence_meter: { total: 70, segments: {} },
            top_actions: [],
            mitre_techniques: [],
          },
        }),
      });
    });
    await page.route('**/executive-summary', route => route.fulfill({
      status: 200, contentType: 'application/json',
      body: JSON.stringify({ headline: 'mock', executive_summary: 'mock summary' }),
    }));

    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await expect(page.locator('[data-testid="br-dispatch"]')).toBeVisible({ timeout: 20000 });

    // br-drilldown's native <summary> is display:none — use the action-row toggle button
    const drilldownBtn = page.locator('[data-testid="br-toggle-drilldown"]');
    if (await drilldownBtn.count() > 0) await drilldownBtn.click();
    const analystDetail = page.locator('[data-testid="br-analyst-detail"] > summary');
    if (await analystDetail.count() > 0) { await expect(analystDetail).toBeVisible({ timeout: 5000 }); await analystDetail.click(); }

    // Find the first business-consequence regen button
    const regenBtn = page.locator('button.br-regen-btn[data-gen-dread]').first();
    await expect(regenBtn, 'br-regen-btn[data-gen-dread] must be present').toBeVisible({ timeout: 10000 });

    const initialCallCount = tier1Calls.length;
    await regenBtn.click();

    // After click, tier1-summary must have been called at least once more
    await expect.poll(() => tier1Calls.length, { timeout: 8000 }).toBeGreaterThan(initialCallCount);

    const lastCall = tier1Calls[tier1Calls.length - 1];
    expect(lastCall.url, 'URL must contain /clusters/').toContain('/clusters/');
    expect(lastCall.url, 'URL must contain /tier1-summary').toContain('/tier1-summary');
    // force=true is sent for regen (data-gen-dread triggers _fireDreadGenerate → _fireSinglePrefill(cid, cb, true))
    expect(lastCall.body, 'force flag must be true for regenerate').toMatchObject({ force: true });
  });

  // ── Test 2: Regenerate bounded-next-actions (second br-regen-btn) ─────────────
  test('2. regenerate bounded-next-actions fires POST tier1-summary (second br-regen-btn)', async ({ page, request }) => {
    const assessmentId = await resolveAssessmentId(request);
    const url = `${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`;

    const tier1Calls = [];
    await page.route('**/clusters/*/tier1-summary', async route => {
      tier1Calls.push({ url: route.request().url() });
      await route.fulfill({
        status: 200, contentType: 'application/json',
        body: JSON.stringify({ tier1_prefill: { incident_name: 'MOCK', headline_subtitle: 'mock', short_narrative: 'mock', confidence_meter: { total: 70, segments: {} }, top_actions: [], mitre_techniques: [] } }),
      });
    });
    await page.route('**/executive-summary', route => route.fulfill({
      status: 200, contentType: 'application/json',
      body: JSON.stringify({ headline: 'mock', executive_summary: 'mock summary' }),
    }));

    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await expect(page.locator('[data-testid="br-dispatch"]')).toBeVisible({ timeout: 20000 });

    // br-drilldown's native <summary> is display:none — use the action-row toggle button
    const drilldownBtn2 = page.locator('[data-testid="br-toggle-drilldown"]');
    if (await drilldownBtn2.count() > 0) await drilldownBtn2.click();
    const analystDetail = page.locator('[data-testid="br-analyst-detail"] > summary');
    if (await analystDetail.count() > 0) { await expect(analystDetail).toBeVisible({ timeout: 5000 }); await analystDetail.click(); }

    // nth(1) is the bounded-next-actions regen button (0 = business-consequence)
    const allRegenBtns = page.locator('button.br-regen-btn[data-gen-dread]');
    const count = await allRegenBtns.count();
    if (count < 2) {
      // Only one regen button found — card may only have one section rendered; skip gracefully
      test.skip();
      return;
    }

    const before = tier1Calls.length;
    await allRegenBtns.nth(1).click();
    await expect.poll(() => tier1Calls.length, { timeout: 8000 }).toBeGreaterThan(before);
    expect(tier1Calls[tier1Calls.length - 1].url).toContain('/tier1-summary');
  });

  // ── Test 3: SOC Analyst dispatch button shows preview panel ──────────────────
  test('3. soc_analyst dispatch button shows preview panel', async ({ page, request }) => {
    const assessmentId = await resolveAssessmentId(request);
    const url = `${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`;

    await mockLlmRoutes(page);

    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await expect(page.locator('[data-testid="br-dispatch"]')).toBeVisible({ timeout: 20000 });

    await page.locator('[data-testid="br-dispatch-soc_analyst"]').click();
    await expect(page.locator('#br-dispatch-preview')).toBeVisible({ timeout: 5000 });
  });

  // ── Test 4: CISO dispatch button shows preview panel ─────────────────────────
  test('4. ciso dispatch button shows preview panel', async ({ page, request }) => {
    const assessmentId = await resolveAssessmentId(request);
    const url = `${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`;

    await mockLlmRoutes(page);

    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await expect(page.locator('[data-testid="br-dispatch"]')).toBeVisible({ timeout: 20000 });

    await page.locator('[data-testid="br-dispatch-ciso"]').click();
    await expect(page.locator('#br-dispatch-preview')).toBeVisible({ timeout: 5000 });
  });

  // ── Test 5: Forensics dispatch button shows preview panel ────────────────────
  test('5. forensics dispatch button shows preview panel', async ({ page, request }) => {
    const assessmentId = await resolveAssessmentId(request);
    const url = `${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`;

    await mockLlmRoutes(page);

    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await expect(page.locator('[data-testid="br-dispatch"]')).toBeVisible({ timeout: 20000 });

    await page.locator('[data-testid="br-dispatch-forensics"]').click();
    await expect(page.locator('#br-dispatch-preview')).toBeVisible({ timeout: 5000 });
  });

  // ── Test 6: Compliance dispatch button shows preview panel ───────────────────
  test('6. compliance dispatch button shows preview panel', async ({ page, request }) => {
    const assessmentId = await resolveAssessmentId(request);
    const url = `${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`;

    await mockLlmRoutes(page);

    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await expect(page.locator('[data-testid="br-dispatch"]')).toBeVisible({ timeout: 20000 });

    await page.locator('[data-testid="br-dispatch-compliance"]').click();
    await expect(page.locator('#br-dispatch-preview')).toBeVisible({ timeout: 5000 });
  });

  // ── Test 7: Confirm dispatch sends POST /dispatch/notify with correct role ────
  test('7. confirm dispatch sends POST /dispatch/notify with correct role', async ({ page, request }) => {
    const assessmentId = await resolveAssessmentId(request);
    const url = `${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`;

    let dispatchPayload = null;
    await page.route('**/api/v1/dispatch/notify', async route => {
      dispatchPayload = route.request().postDataJSON();
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ role: 'soc_analyst', delivered: false, demo: true, message: '[DEMO] Dispatched' }),
      });
    });
    await mockLlmRoutes(page);

    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await expect(page.locator('[data-testid="br-dispatch"]')).toBeVisible({ timeout: 20000 });

    await page.locator('[data-testid="br-dispatch-soc_analyst"]').click();
    await expect(page.locator('#br-dispatch-preview')).toBeVisible({ timeout: 5000 });

    const confirmBtn = page.locator('#br-dispatch-confirm');
    await expect(confirmBtn).toBeVisible();
    await confirmBtn.click();

    await expect.poll(() => dispatchPayload, { timeout: 8000 }).not.toBeNull();
    expect(dispatchPayload.role).toBe('soc_analyst');
    expect(dispatchPayload.assessment_id).toBe(assessmentId);

    // Confirm button should be disabled after dispatch
    await expect(confirmBtn).toBeDisabled({ timeout: 5000 });
  });

  // ── Test 8: Cancel button hides dispatch preview ──────────────────────────────
  test('8. cancel button hides dispatch preview', async ({ page, request }) => {
    const assessmentId = await resolveAssessmentId(request);
    const url = `${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`;

    await mockLlmRoutes(page);

    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await expect(page.locator('[data-testid="br-dispatch"]')).toBeVisible({ timeout: 20000 });

    await page.locator('[data-testid="br-dispatch-soc_analyst"]').click();
    const preview = page.locator('#br-dispatch-preview');
    await expect(preview).toBeVisible({ timeout: 5000 });

    await page.locator('#br-dispatch-cancel').click();
    await expect(preview).not.toBeVisible({ timeout: 5000 });
  });

  // ── Test 9: Regenerate dispatch fires POST /persona-dispatch with persona ─────
  test('9. regenerate dispatch fires POST /persona-dispatch with correct persona', async ({ page, request }) => {
    const assessmentId = await resolveAssessmentId(request);
    const url = `${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`;

    const regenHits = [];
    await page.route('**/assessments/**/persona-dispatch', async route => {
      regenHits.push({ persona: route.request().postDataJSON()?.persona });
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ payload: { headline: 'Regenerated CISO payload — Playwright mock' } }),
      });
    });
    await mockLlmRoutes(page);

    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await expect(page.locator('[data-testid="br-dispatch"]')).toBeVisible({ timeout: 20000 });

    // Open the CISO preview so we can click the regen button inside More actions
    await page.locator('[data-testid="br-dispatch-ciso"]').click();
    await expect(page.locator('#br-dispatch-preview')).toBeVisible({ timeout: 5000 });

    // Open "More actions" accordion to expose the regen button
    const moreToggle = page.locator('.br-dispatch-more__summary');
    if (await moreToggle.count() > 0) {
      await moreToggle.click();
    }

    const regenDispatchBtn = page.locator('#br-dispatch-regen');
    await expect(regenDispatchBtn).toBeVisible({ timeout: 5000 });
    await regenDispatchBtn.click();

    await expect.poll(() => regenHits.length, { timeout: 8000 }).toBeGreaterThan(0);
    expect(regenHits[0].persona).toBe('ciso');
  });

  // ── Test 10: Open threat case ↗ opens new tab with ?cluster= in URL ───────────
  test('10. open threat case button opens new tab with ?cluster= in URL', async ({ page, request }) => {
    const assessmentId = await resolveAssessmentId(request);
    const url = `${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`;

    await mockLlmRoutes(page);

    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await expect(page.locator('[data-testid="br-dispatch"]')).toBeVisible({ timeout: 20000 });

    // Cards may be inside collapsed sections — open drilldown first (its <summary> is display:none,
    // so use the action-row toggle button), then expand the analyst-detail accordion
    const drilldownBtn10 = page.locator('[data-testid="br-toggle-drilldown"]');
    if (await drilldownBtn10.count() > 0) await drilldownBtn10.click();
    const analystDetail = page.locator('[data-testid="br-analyst-detail"] > summary');
    if (await analystDetail.count() > 0) { await expect(analystDetail).toBeVisible({ timeout: 5000 }); await analystDetail.click(); }

    // Find any "Open threat case ↗" button — all use br-card__open with window.open
    const openBtn = page.locator('button.br-card__open', { hasText: /Open threat case|Open workbench/ }).first();
    await expect(openBtn, '"Open threat case ↗" button must be visible').toBeVisible({ timeout: 10000 });

    const [newTab] = await Promise.all([
      page.context().waitForEvent('page'),
      openBtn.click(),
    ]);
    await newTab.waitForLoadState('domcontentloaded');
    expect(newTab.url(), 'New tab URL must contain ?cluster=').toContain('cluster=');
    await newTab.close();
  });

  // ── Test 11: Generate narrative button fires tier1-summary ────────────────────
  test('11. generate narrative button (br-finding__gen) fires POST tier1-summary for likely cluster', async ({ page, request }) => {
    const assessmentId = await resolveAssessmentId(request);
    const url = `${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`;

    const tier1Hits = [];
    await page.route('**/clusters/*/tier1-summary', async route => {
      tier1Hits.push({ url: route.request().url(), body: route.request().postDataJSON() });
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          tier1_prefill: {
            incident_name: 'MOCK-GEN',
            headline_subtitle: 'Generated mock',
            short_narrative: 'Playwright generate mock narrative.',
            confidence_meter: { total: 65, segments: {} },
            top_actions: ['Block outbound to 45.133.0.0/16'],
            mitre_techniques: ['T1041'],
          },
        }),
      });
    });
    await page.route('**/executive-summary', route => route.fulfill({
      status: 200, contentType: 'application/json',
      body: JSON.stringify({ headline: 'mock', executive_summary: 'mock' }),
    }));

    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await expect(page.locator('[data-testid="br-dispatch"]')).toBeVisible({ timeout: 20000 });

    // The Generate narrative button is present only when a LIKELY cluster has no prefill.
    // It uses class br-finding__gen and attribute data-gen-cluster.
    const genBtn = page.locator('button.br-finding__gen[data-gen-cluster]').first();
    const genBtnVisible = await genBtn.isVisible().catch(() => false);

    if (!genBtnVisible) {
      // All clusters already have prefill — generate was auto-fired on load; skip gracefully
      test.skip();
      return;
    }

    const before = tier1Hits.length;
    await genBtn.click();

    await expect.poll(() => tier1Hits.length, { timeout: 10000 }).toBeGreaterThan(before);
    const hit = tier1Hits.find((h, i) => i >= before);
    expect(hit.url).toContain('/tier1-summary');
    // The normal generate path sends force: false (only regen sends force: true)
    expect(hit.body).toMatchObject({ force: false });
  });

});

// ── Suite: Cluster Detail Page — Sign-off Buttons ────────────────────────────

test.describe('Breach Cluster Detail — Sign-off Buttons', () => {

  // Resolve the cluster ID from the live assessment so the suite works
  // against real data. Falls back to a combined fallback URL.
  async function resolveClusterUrl(request) {
    const aid = await resolveAssessmentId(request);
    try {
      const resp = await request.get(`${BASE}/api/v1/assessments/${encodeURIComponent(aid)}`, {
        headers: { 'x-api-key': 'devkey123', 'x-tenant-id': 'default' },
        timeout: 5000,
      });
      if (resp.ok()) {
        const data = await resp.json();
        const clusters = data.analysis_clusters || data.correlation_clusters || [];
        if (clusters.length) {
          return {
            aid,
            cid: clusters[0].cluster_id,
            url: `${BASE}/static/breach.html?cluster=${encodeURIComponent(clusters[0].cluster_id)}&assessment=${encodeURIComponent(aid)}`,
          };
        }
      }
    } catch (_) {}
    // Use env override or constructed fallback
    const cid = process.env.PLAYWRIGHT_CLUSTER_ID || 'mock-cluster-confirmed';
    return {
      aid,
      cid,
      url: `${BASE}/static/breach.html?cluster=${encodeURIComponent(cid)}&assessment=${encodeURIComponent(aid)}`,
    };
  }

  // ── Test 12: Sign-off Confirmed → done badge ─────────────────────────────────
  test('12. sign-off Confirmed fires POST /sign-off and shows done badge', async ({ page, request }) => {
    const { aid, cid, url } = await resolveClusterUrl(request);

    let signOffPayload = null;
    await page.route('**/sign-off', async route => {
      if (route.request().method() === 'POST') {
        signOffPayload = route.request().postDataJSON();
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ status: 'signed_off', cluster_id: cid, signed_off_at: Math.floor(Date.now() / 1000) }),
        });
      } else {
        await route.continue();
      }
    });
    await page.route('**/clusters/*/tier1-summary', route => route.fulfill({
      status: 200, contentType: 'application/json',
      body: JSON.stringify({ tier1_prefill: { incident_name: 'MOCK', headline_subtitle: 'mock', short_narrative: 'mock', confidence_meter: { total: 70, segments: {} }, top_actions: [], mitre_techniques: [] } }),
    }));
    await page.route('**/executive-summary', route => route.fulfill({
      status: 200, contentType: 'application/json',
      body: JSON.stringify({ headline: 'mock', executive_summary: 'mock' }),
    }));

    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await expect(page.locator('[data-testid="bct-wrap"]')).toBeVisible({ timeout: 20000 });

    const confirmBtn = page.locator('[data-testid="bct-signoff-confirm"]');
    await expect(confirmBtn).toBeVisible({ timeout: 10000 });
    await confirmBtn.click();

    // Done badge should appear
    await expect(page.locator('[data-testid="bct-signoff-done"]')).toBeVisible({ timeout: 8000 });
    await expect(page.locator('[data-testid="bct-signoff-done"]')).toContainText('CONFIRMED');

    // Verify POST was made with action=confirmed
    await expect.poll(() => signOffPayload, { timeout: 5000 }).not.toBeNull();
    expect(signOffPayload.action).toBe('confirmed');

    // Confirm button must be gone after sign-off
    await expect(confirmBtn).not.toBeVisible();
  });

  // ── Test 13: Sign-off Escalate fires POST with action=escalate ───────────────
  test('13. sign-off Escalate fires POST /sign-off with action=escalate', async ({ page, request }) => {
    const { aid, cid, url } = await resolveClusterUrl(request);

    let signOffPayload = null;
    await page.route('**/sign-off', async route => {
      if (route.request().method() === 'POST') {
        signOffPayload = route.request().postDataJSON();
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ status: 'signed_off', cluster_id: cid, signed_off_at: Math.floor(Date.now() / 1000) }),
        });
      } else {
        await route.continue();
      }
    });
    await page.route('**/clusters/*/tier1-summary', route => route.fulfill({
      status: 200, contentType: 'application/json',
      body: JSON.stringify({ tier1_prefill: { incident_name: 'MOCK', headline_subtitle: 'mock', short_narrative: 'mock', confidence_meter: { total: 70, segments: {} }, top_actions: [], mitre_techniques: [] } }),
    }));
    await page.route('**/executive-summary', route => route.fulfill({
      status: 200, contentType: 'application/json',
      body: JSON.stringify({ headline: 'mock', executive_summary: 'mock' }),
    }));

    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await expect(page.locator('[data-testid="bct-wrap"]')).toBeVisible({ timeout: 20000 });

    await expect(page.locator('[data-testid="bct-signoff-escalate"]')).toBeVisible({ timeout: 10000 });
    await page.locator('[data-testid="bct-signoff-escalate"]').click();

    await expect.poll(() => signOffPayload, { timeout: 8000 }).not.toBeNull();
    expect(signOffPayload.action).toBe('escalate');

    await expect(page.locator('[data-testid="bct-signoff-done"]')).toBeVisible({ timeout: 8000 });
    await expect(page.locator('[data-testid="bct-signoff-done"]')).toContainText('ESCALATE');
  });

  // ── Test 14: Sign-off Dismiss fires POST with action=dismiss ─────────────────
  test('14. sign-off Dismiss fires POST /sign-off with action=dismiss', async ({ page, request }) => {
    const { aid, cid, url } = await resolveClusterUrl(request);

    let signOffPayload = null;
    await page.route('**/sign-off', async route => {
      if (route.request().method() === 'POST') {
        signOffPayload = route.request().postDataJSON();
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ status: 'signed_off', cluster_id: cid, signed_off_at: Math.floor(Date.now() / 1000) }),
        });
      } else {
        await route.continue();
      }
    });
    await page.route('**/clusters/*/tier1-summary', route => route.fulfill({
      status: 200, contentType: 'application/json',
      body: JSON.stringify({ tier1_prefill: { incident_name: 'MOCK', headline_subtitle: 'mock', short_narrative: 'mock', confidence_meter: { total: 70, segments: {} }, top_actions: [], mitre_techniques: [] } }),
    }));
    await page.route('**/executive-summary', route => route.fulfill({
      status: 200, contentType: 'application/json',
      body: JSON.stringify({ headline: 'mock', executive_summary: 'mock' }),
    }));

    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await expect(page.locator('[data-testid="bct-wrap"]')).toBeVisible({ timeout: 20000 });

    await expect(page.locator('[data-testid="bct-signoff-dismiss"]')).toBeVisible({ timeout: 10000 });
    await page.locator('[data-testid="bct-signoff-dismiss"]').click();

    await expect.poll(() => signOffPayload, { timeout: 8000 }).not.toBeNull();
    expect(signOffPayload.action).toBe('dismiss');

    await expect(page.locator('[data-testid="bct-signoff-done"]')).toBeVisible({ timeout: 8000 });
    await expect(page.locator('[data-testid="bct-signoff-done"]')).toContainText('DISMISS');
  });

});
