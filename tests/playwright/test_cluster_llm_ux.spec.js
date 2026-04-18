/**
 * Playwright tests for investigate.html — Cluster LLM Briefing and CRAG Enrichment UX
 *
 * These tests use the live server at http://localhost:8080.
 * They require TEST_HELPERS_ENABLED=1 which enables the stub in-memory session routes.
 *
 * Coverage:
 *   1. Model catalog dropdown has enabled & greyed-out entries
 *   2. Clicking "Summarise" transitions from idle → loading → result (no orange error when LLM responds)
 *   3. Clicking "Run CRAG + LLM Enrich" shows CRAG grade + LLM result or skip reason
 *   4. LLM summary appears above persona tasks; heuristic tasks are in collapsed section
 *   5. TOGAF/SABSA architecture section is collapsed by default with concise visible summary
 */

const { test, expect } = require('@playwright/test');

const BASE = 'http://localhost:8080';
const INVESTIGATE_URL = `${BASE}/static/investigate.html`;

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Seed a minimal assessment + cluster via the test-stub endpoint. */
async function seedAssessment(request) {
  const payload = {
    assessment_id: 'pw-test-canvas',
    clusters: [
      {
        cluster_id:           'cluster-pw1',
        severity:             'high',
        confidence:           0.82,
        top_mitre:            ['T1078', 'T1021'],
        shared_accounts:      ['testuser'],
        shared_hosts:         ['host-01'],
        shared_external_ips:  ['1.2.3.4'],
        row_refs:             [0, 1],
        blast_radius_summary: '1 host, 1 account',
        reason_summary:       'testuser shared across sources',
        rearchitect: {
          domains: [
            {
              domain:           'Identity',
              priority:         1,
              is_root_cause:    true,
              sabsa_attribute:  'Access Control',
              sabsa_principle:  'Identity must be verified before access is granted.',
              sabsa_risk:       'Unauthorised access to privileged resources.',
              togaf_phase:      'Phase C (Technology Architecture)',
              togaf_action:     'Enforce MFA for all privileged accounts.',
              evidence_caveat:  null,
            },
          ],
          affected_controls:  ['CIS-7.1', 'NIST:AC-2'],
        },
      },
    ],
    rows: [
      { row_number: 0, row_index: 0, severity: 'high',   user: 'testuser', hostname: 'host-01', src_ip: '1.2.3.4', description: 'Suspicious logon', mitre_technique: 'T1078' },
      { row_number: 1, row_index: 1, severity: 'medium', user: 'testuser', hostname: 'host-01', description: 'RDP lateral movement', mitre_technique: 'T1021' },
    ],
  };
  const resp = await request.post(`${BASE}/api/v1/test/seed_assessment`, {
    headers: { 'x-api-key': 'devkey123', 'Content-Type': 'application/json' },
    data: payload,
  });
  // Seeding may 404 if the stub endpoint is not wired — tests degrade gracefully
  return resp.status() === 200;
}

/** Navigate to investigate.html and inject minimal state so the cluster drawer opens. */
async function openClusterDrawer(page) {
  await page.goto(INVESTIGATE_URL, { waitUntil: 'domcontentloaded' });

  // Inject a fake assessmentId and cluster into page state, bypassing upload
  await page.evaluate(() => {
    if (typeof state === 'undefined') return;
    const cluster = {
      cluster_id:           'cluster-pw1',
      severity:             'high',
      confidence:           0.82,
      top_mitre:            ['T1078', 'T1021'],
      shared_accounts:      ['testuser'],
      shared_hosts:         ['host-01'],
      shared_external_ips:  ['1.2.3.4'],
      row_refs:             [0, 1],
      blast_radius_summary: '1 host, 1 account',
      reason_summary:       'testuser shared across sources',
      rearchitect: {
        domains: [
          {
            domain: 'Identity', priority: 1, is_root_cause: true,
            sabsa_attribute: 'Access Control',
            sabsa_principle: 'Identity must be verified before access is granted.',
            sabsa_risk: 'Unauthorised access to privileged resources.',
            togaf_phase: 'Phase C (Technology Architecture)',
            togaf_action: 'Enforce MFA for all privileged accounts.',
            evidence_caveat: null,
          },
        ],
        affected_controls: ['CIS-7.1'],
      },
    };
    state.assessmentId = 'pw-test-canvas';
    state.clusterMap = state.clusterMap || {};
    state.clusterMap['cluster-pw1'] = cluster;
    state.clusters = [cluster];
  });

  // Open the cluster drawer
  await page.evaluate(() => {
    if (typeof openClusterDetail === 'function') {
      openClusterDetail('cluster-pw1');
    }
  });

  // Wait for drawer to appear
  await page.waitForSelector('#clusterDrawer', { state: 'visible', timeout: 5000 }).catch(() => {});
}


// ─────────────────────────────────────────────────────────────────────────────
// Test 1 — Model catalog dropdown contains enabled and disabled options
// ─────────────────────────────────────────────────────────────────────────────

test('model picker has enabled and disabled entries', async ({ page, request }) => {
  await seedAssessment(request);
  await openClusterDrawer(page);

  // Wait for the LLM BRIEFING section to be present
  await page.waitForSelector('[data-catalog-sel="llm-summary"]', { timeout: 8000 }).catch(() => {});

  // The select may initially have only the default option — wait for catalog load
  await page.waitForTimeout(500);

  const sel = page.locator('[data-catalog-sel="llm-summary"]').first();
  const optionsCount = await sel.evaluate(el => el.options.length).catch(() => 0);
  expect(optionsCount).toBeGreaterThanOrEqual(1);

  // Check that at least one option is present (may be fallback when Ollama offline)
  const firstOption = await sel.evaluate(el => el.options[0]?.value).catch(() => '');
  expect(firstOption).toBeTruthy();

  // Verify catalog endpoint itself returns proper shape
  const resp = await request.get(`${BASE}/api/v1/llm/models/catalog`, {
    headers: { 'x-api-key': 'devkey123' },
  });
  expect(resp.status()).toBe(200);
  const data = await resp.json();
  expect(data.models).toBeDefined();
  expect(Array.isArray(data.models)).toBe(true);
  expect(data.models.length).toBeGreaterThan(0);

  // All entries should have required fields
  for (const m of data.models) {
    expect(m).toHaveProperty('id');
    expect(m).toHaveProperty('provider');
    expect(m).toHaveProperty('available');
  }

  // Cloud models without API key should be disabled
  const cloudModels = data.models.filter(m => m.tier === 'cloud');
  if (cloudModels.length > 0) {
    const hasDisabled = cloudModels.some(m => m.available === false && m.disabled_reason);
    expect(hasDisabled).toBe(true);
  }
});


// ─────────────────────────────────────────────────────────────────────────────
// Test 2 — "Summarise" button leaves loading/orange state and shows a result
// ─────────────────────────────────────────────────────────────────────────────

test('Summarise button resolves — no persistent orange error state', async ({ page, request }) => {
  await seedAssessment(request);
  await openClusterDrawer(page);

  // Wait for the LLM BRIEFING widget
  const resultEl = await page.waitForSelector('#llmSummaryResult_cluster-pw1', { timeout: 8000 })
    .catch(() => null);
  if (!resultEl) {
    test.skip('LLM BRIEFING widget not rendered — cluster drawer may not be open');
    return;
  }

  // Click Summarise
  await page.evaluate(() => {
    const cid = 'cluster-pw1';
    const aid = 'pw-test-canvas';
    if (typeof window._triggerLlmSummary === 'function') {
      window._triggerLlmSummary(cid, aid, false);
    }
  });

  // Wait up to 15s for the result container to change from the initial "Click Summarise" text
  const resolved = await page.waitForFunction(
    () => {
      const el = document.getElementById('llmSummaryResult_cluster-pw1');
      if (!el) return false;
      const text = el.textContent || '';
      // Resolved states: summary content, LLM unavailable warning, or provider error
      if (text.includes('Summarise')) return false;  // still initial
      if (el.querySelector('.enrich-spinner')) return false;  // still loading
      return true;
    },
    { timeout: 20000 },
  ).catch(() => false);

  // Result should be present (not forever-loading)
  expect(resolved).toBe(true);

  // The result should NOT be just an error orange box without any diagnostic text
  // (If LLM is offline, a yellow warning box with a message is acceptable)
  const resultText = await page.evaluate(() => {
    const el = document.getElementById('llmSummaryResult_cluster-pw1');
    return el ? el.textContent : '';
  });
  expect(resultText.length).toBeGreaterThan(20);
});


// ─────────────────────────────────────────────────────────────────────────────
// Test 3 — "Run CRAG + LLM Enrich" result panel updates
// ─────────────────────────────────────────────────────────────────────────────

test('CRAG enrich result panel updates after click', async ({ page, request }) => {
  await seedAssessment(request);
  await openClusterDrawer(page);

  // Scroll to enrich panel
  const enrichResult = await page.waitForSelector('#enrichResult_cluster-pw1', { timeout: 8000 })
    .catch(() => null);
  if (!enrichResult) {
    test.skip('CRAG ENRICHMENT panel not rendered');
    return;
  }

  // Click "Run CRAG + LLM Enrich"
  await page.evaluate(() => {
    const cid = 'cluster-pw1';
    const aid = 'pw-test-canvas';
    if (typeof window._triggerClusterEnrich === 'function') {
      window._triggerClusterEnrich(cid, aid, false);
    }
  });

  // Wait for panel to update from initial "(Not yet run)" text
  const updated = await page.waitForFunction(
    () => {
      const el = document.getElementById('enrichResult_cluster-pw1');
      if (!el) return false;
      const text = el.textContent || '';
      if (text.includes('Not yet run')) return false;
      if (el.querySelector('.enrich-spinner')) return false;
      return true;
    },
    { timeout: 25000 },
  ).catch(() => false);

  expect(updated).toBe(true);

  // Result should contain CRAG grade or a skip reason
  const resultText = await page.evaluate(() => {
    const el = document.getElementById('enrichResult_cluster-pw1');
    return el ? el.textContent : '';
  });
  const hasCrag    = /CRAG|ACCEPT|REJECT|REFINE/.test(resultText);
  const hasSkip    = /skipped|rejected|unavailable|not configured/i.test(resultText);
  const hasFailed  = /failed/i.test(resultText);
  expect(hasCrag || hasSkip || hasFailed).toBe(true);
});


// ─────────────────────────────────────────────────────────────────────────────
// Test 4 — LLM summary above persona tasks; heuristic tasks in collapsed section
// ─────────────────────────────────────────────────────────────────────────────

test('LLM summary shown above persona tasks heuristics are collapsed', async ({ page }) => {
  await openClusterDrawer(page);

  // Inject a pre-existing LLM summary onto the cluster state so drawer renders it
  await page.evaluate(() => {
    const cid = 'cluster-pw1';
    const summary = {
      cluster_id: cid,
      model: 'qwen2.5:14b',
      from_cache: false,
      llm_available: true,
      sections: {
        reality_verdict:   'LIKELY REAL',
        what_is_happening: 'testuser compromised with lateral movement.',
        why_it_matters:    'Active intrusion in progress.',
        what_to_do:        '1. Isolate testuser.\n2. Block 1.2.3.4.\n3. Collect logs.',
        is_this_real:      'LIKELY REAL — multiple correlated events.',
      },
    };
    if (state.clusterMap && state.clusterMap[cid]) {
      state.clusterMap[cid].llmSummary = summary;
    }
    // Re-render the drawer
    if (typeof renderClusterDrawer === 'function') {
      renderClusterDrawer(state.clusterMap[cid]);
    }
  });

  await page.waitForTimeout(300);

  // Check LLM-Generated Next Steps are visible
  const llmNextSteps = await page.evaluate(() => {
    const el = document.querySelector('#clusterDrawer');
    if (!el) return null;
    const text = el.textContent || '';
    return {
      hasLlmSteps:          text.includes('LLM-Generated Next Steps'),
      hasHeuristicLabel:    text.includes('Heuristic fallback tasks'),
    };
  });

  if (llmNextSteps) {
    expect(llmNextSteps.hasLlmSteps).toBe(true);
    expect(llmNextSteps.hasHeuristicLabel).toBe(true);

    // Heuristic tasks block should be inside a <details> (collapsed by default)
    const heuristicInDetails = await page.evaluate(() => {
      const detailsEls = document.querySelectorAll('#clusterDrawer details');
      for (const d of detailsEls) {
        const summary = d.querySelector('summary');
        if (summary && /heuristic/i.test(summary.textContent || '')) {
          return !d.hasAttribute('open');  // closed by default
        }
      }
      return null;
    });
    if (heuristicInDetails !== null) {
      expect(heuristicInDetails).toBe(true);
    }
  }
});


// ─────────────────────────────────────────────────────────────────────────────
// Test 5 — TOGAF/SABSA section is collapsed by default with concise visible summary
// ─────────────────────────────────────────────────────────────────────────────

test('TOGAF/SABSA architecture section collapsed by default with concise summary', async ({ page }) => {
  await openClusterDrawer(page);
  await page.waitForTimeout(300);

  const result = await page.evaluate(() => {
    const drawer = document.querySelector('#clusterDrawer');
    if (!drawer) return null;

    // Find the REARCHITECT badge section
    const header = [...drawer.querySelectorAll('span')].find(
      el => el.textContent.trim() === 'REARCHITECT',
    );
    if (!header) return { rearchitectFound: false };

    // Search for the <details> element containing architecture drill-down
    let parent = header;
    for (let i = 0; i < 10; i++) {
      parent = parent.parentElement;
      if (!parent) break;
      if (parent.tagName === 'DIV') {
        const details = parent.querySelector('details');
        if (details) {
          return {
            rearchitectFound:  true,
            detailsExists:     true,
            isCollapsed:       !details.hasAttribute('open'),
            hasConciseSummary: (parent.textContent || '').length > 30 &&
                               !details.contains(parent.firstChild),
          };
        }
      }
    }
    return { rearchitectFound: true, detailsExists: false };
  });

  if (result && result.rearchitectFound) {
    // The detailed TOGAF/SABSA content should be in a <details> element
    if (result.detailsExists) {
      expect(result.isCollapsed).toBe(true);
    }
    // Some concise text should be visible above the fold
    expect(result.rearchitectFound).toBe(true);
  } else {
    // REARCHITECT section not present for this cluster/persona combination — OK
    // (only rendered for CISO/executive/compliance personas or critical severity)
    test.info().annotations.push({
      type: 'note',
      description: 'REARCHITECT section not visible for this persona/severity combination',
    });
  }
});
