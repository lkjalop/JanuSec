/**
 * breach_exec_summary_quality.spec.js
 *
 * Diagnostic tests that prove the executive summary and dispatch preview
 * panels are (a) populated with assessment-specific evidence, not generic
 * template strings, and (b) the dispatch preview shows per-persona
 * evidence-backed content, not static role descriptions.
 *
 * Run against a live server with a Santos assessment already loaded:
 *   npx playwright test tests/playwright/breach_exec_summary_quality.spec.js
 */
const { test, expect } = require('@playwright/test');

const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:8080';
const HEADERS = { 'x-api-key': 'devkey123', 'x-tenant-id': 'default' };

// ── Helpers ─────────────────────────────────────────────────────────────────

async function getLatestAssessment(request) {
  const resp = await request.get(`${BASE}/api/v1/assessments`, { headers: HEADERS });
  if (!resp.ok()) return null;
  const body = await resp.json();
  const jobs = (body.jobs || []).sort((a, b) =>
    (b.created_at || 0) - (a.created_at || 0)
  );
  return jobs.length ? jobs[0].assessment_id : null;
}

async function getBreachAssessment(request, aid) {
  const resp = await request.get(`${BASE}/api/v1/assessments/${encodeURIComponent(aid)}`, {
    headers: HEADERS,
  });
  if (!resp.ok()) return null;
  return resp.json();
}

// ── Probes ───────────────────────────────────────────────────────────────────

// Strings that should NEVER appear in a good exec summary for a breach
const GENERIC_EXEC_PATTERNS = [
  /JanuSec found observed attacker action against a protected business process/i,
  /^No confirmed breach found/i,
  /Executive summary unavailable/i,
];

// Strings that prove the exec summary is evidence-specific (Santos case)
const SPECIFIC_EXEC_SIGNALS = [
  // Identities
  /aaron\.blackwood|rachel\.nakamura/i,
  // Techniques
  /lsass|mfa.*(push|fatigue)|credential dump/i,
  // Exfil signals
  /mega\.nz|rclone|snowflake|s3:\/\/|exfil/i,
  // Time window
  /202[56]-0[12]/,
  // IPs (attacker infrastructure, not RFC1918)
  /45\.133|91\.240|31\.216/,
];

// Dispatch preview static strings that should NOT appear after fixes
const DISPATCH_STATIC_DESC = [
  'Triage focus, containment options, IOCs, decision tree, priority',
  'Assess NDB notification requirement.',
  'Approve containment spend.',
  'Collect volatile artifacts (memory → disk → network).',
];

// Dispatch preview should contain evidence-specific content instead
const DISPATCH_SPECIFIC_SIGNALS_SOC = [
  // Should name the affected account
  /aaron\.blackwood|rachel\.nakamura|svc_sfl_analytics/i,
  // Should include a concrete tool command or action
  /okta|aws.*iam|crowdstrike|schtasks|rtr|revoke.*key|expire.*session|isolate/i,
];

const DISPATCH_SPECIFIC_SIGNALS_CISO = [
  // Should reference regulatory frameworks
  /NDB|OAIC|Privacy Act|SOCI|notification.*clock|GDPR/i,
  // Should mention breach specifics
  /snowflake|manifest|crown.jewel|port.scheduling/i,
];

// ── Tests ────────────────────────────────────────────────────────────────────

test.describe('Executive Summary Quality', () => {
  let assessmentId = null;
  let assessmentData = null;

  test.beforeAll(async ({ request }) => {
    assessmentId = await getLatestAssessment(request);
    if (!assessmentId) test.skip();
    assessmentData = await getBreachAssessment(request, assessmentId);
  });

  test('assessment has a confirmed breach verdict', () => {
    if (!assessmentData) test.skip();
    const clusters = assessmentData.analysis_clusters || assessmentData.correlation_clusters || [];
    const leadCluster = clusters[0];
    const verdict = (leadCluster?.verdict || leadCluster?.final_verdict || '').toUpperCase();
    expect(['VALIDATED_BREACH', 'CONFIRMED_BREACH', 'CONFIRMED_INTRUSION']).toContain(verdict);
  });

  test('exec-summary API returns non-generic text on regenerate', async ({ request }) => {
    if (!assessmentId) test.skip();

    const resp = await request.post(
      `${BASE}/api/v1/assessments/${encodeURIComponent(assessmentId)}/executive-summary`,
      {
        headers: { ...HEADERS, 'Content-Type': 'application/json' },
        data: { regenerate: true, model: 'qwen3.6:27b' },
      }
    );
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();

    const summaryText = [
      body.headline || '',
      body.subline || '',
      body.executive_summary || '',
    ].join(' ');

    // Must NOT be generic fallback
    for (const pattern of GENERIC_EXEC_PATTERNS) {
      expect(summaryText, `FAIL: exec summary is still generic (matched ${pattern})`).not.toMatch(pattern);
    }

    // Must contain at least 2 specific evidence signals
    const signalsFound = SPECIFIC_EXEC_SIGNALS.filter(p => p.test(summaryText));
    expect(signalsFound.length, `FAIL: exec summary lacks specific evidence. Found: "${summaryText.slice(0, 300)}"`).toBeGreaterThanOrEqual(2);
  });

  test('persona_dispatch present in cluster data', async ({ request }) => {
    if (!assessmentData) test.skip();
    const clusters = assessmentData.analysis_clusters || assessmentData.correlation_clusters || [];
    const leadCluster = clusters.find(c => {
      const v = (c.verdict || c.final_verdict || '').toUpperCase();
      return ['VALIDATED_BREACH', 'CONFIRMED_BREACH'].includes(v);
    });
    if (!leadCluster) test.skip();

    expect(leadCluster, 'FAIL: persona_dispatch not serialized into cluster API response')
      .toHaveProperty('persona_dispatch');

    const pd = leadCluster.persona_dispatch;
    expect(pd, 'FAIL: soc_analyst dispatch missing').toHaveProperty('soc_analyst');
    expect(pd, 'FAIL: ciso dispatch missing').toHaveProperty('ciso');
    expect(pd, 'FAIL: executive dispatch missing').toHaveProperty('executive');
  });

  test('soc_analyst persona_dispatch has evidence-specific required_actions', async ({ request }) => {
    if (!assessmentData) test.skip();
    const clusters = assessmentData.analysis_clusters || assessmentData.correlation_clusters || [];
    const leadCluster = clusters.find(c => c.persona_dispatch?.soc_analyst);
    if (!leadCluster) test.skip();

    const socDispatch = leadCluster.persona_dispatch.soc_analyst;
    const actionsText = JSON.stringify(socDispatch.required_actions || []);

    // Must reference specific accounts, keys, or tools — not generic placeholders
    const hasSpecific = DISPATCH_SPECIFIC_SIGNALS_SOC.some(p => p.test(actionsText));
    expect(hasSpecific, `FAIL: SOC actions are generic: ${actionsText.slice(0, 400)}`).toBe(true);
  });

  test('ciso persona_dispatch has regulatory clocks', async ({ request }) => {
    if (!assessmentData) test.skip();
    const clusters = assessmentData.analysis_clusters || assessmentData.correlation_clusters || [];
    const leadCluster = clusters.find(c => c.persona_dispatch?.ciso);
    if (!leadCluster) test.skip();

    const cisoDispatch = leadCluster.persona_dispatch.ciso;
    const regulatoryText = JSON.stringify(cisoDispatch.regulatory_clocks || []);

    const hasSpecific = DISPATCH_SPECIFIC_SIGNALS_CISO.some(p =>
      p.test(regulatoryText) || p.test(cisoDispatch.headline || '')
    );
    expect(hasSpecific, `FAIL: CISO dispatch lacks regulatory specificity: ${regulatoryText.slice(0, 400)}`).toBe(true);
  });
});

test.describe('Dispatch Preview Panel — Evidence-Specific', () => {
  let assessmentId = null;

  test.beforeAll(async ({ request }) => {
    assessmentId = await getLatestAssessment(request);
  });

  test('SOC Analyst preview shows evidence-backed content, not static role description', async ({ page, request }) => {
    if (!assessmentId) test.skip();
    const url = `${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`;
    await page.goto(url);

    await expect(page.locator('[data-testid="br-dispatch"]')).toBeVisible({ timeout: 25000 });
    await page.locator('[data-testid="br-dispatch-soc_analyst"]').click();

    const preview = page.locator('#br-dispatch-preview');
    await expect(preview).toBeVisible({ timeout: 5000 });

    const previewText = await preview.innerText();

    // Fail if we see the hardcoded role description
    for (const staticStr of DISPATCH_STATIC_DESC) {
      expect(previewText, `FAIL: dispatch preview shows static role desc: "${staticStr}"`).not.toContain(staticStr);
    }

    // Pass if we see any evidence-specific signal
    const hasEvidence = DISPATCH_SPECIFIC_SIGNALS_SOC.some(p => p.test(previewText));
    expect(hasEvidence, `FAIL: SOC dispatch preview lacks specific evidence. Content: "${previewText.slice(0, 600)}"`).toBe(true);
  });

  test('CISO preview shows regulatory clock content', async ({ page, request }) => {
    if (!assessmentId) test.skip();
    const url = `${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`;
    await page.goto(url);

    await expect(page.locator('[data-testid="br-dispatch"]')).toBeVisible({ timeout: 25000 });
    await page.locator('[data-testid="br-dispatch-ciso"]').click();

    const preview = page.locator('#br-dispatch-preview');
    await expect(preview).toBeVisible({ timeout: 5000 });
    const previewText = await preview.innerText();

    const hasRegulatory = DISPATCH_SPECIFIC_SIGNALS_CISO.some(p => p.test(previewText));
    expect(hasRegulatory, `FAIL: CISO preview lacks regulatory content. Content: "${previewText.slice(0, 600)}"`).toBe(true);
  });

  test('Executive preview shows plain-English breach summary, not template text', async ({ page, request }) => {
    if (!assessmentId) test.skip();
    const url = `${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`;
    await page.goto(url);

    await expect(page.locator('[data-testid="br-dispatch"]')).toBeVisible({ timeout: 25000 });
    await page.locator('[data-testid="br-dispatch-executive"]').click();

    const preview = page.locator('#br-dispatch-preview');
    await expect(preview).toBeVisible({ timeout: 5000 });
    const previewText = await preview.innerText();

    // Generic template text must not appear
    expect(previewText).not.toContain('Business impact, plain-English narrative, operational next steps');

    // Must mention what was stolen or the specific breach type
    const hasBreachSpecific = [
      /manifest|shipping|snowflake|exfil|mega\.nz/i,
      /aaron\.blackwood|rachel\.nakamura/i,
      /crown.jewel|port.scheduling/i,
    ].some(p => p.test(previewText));
    expect(hasBreachSpecific, `FAIL: executive preview lacks breach specifics. Content: "${previewText.slice(0, 600)}"`).toBe(true);
  });
});

test.describe('Model Selection', () => {
  test('exec-summary endpoint respects qwen3.6:27b model param', async ({ request }) => {
    const assessmentId = await getLatestAssessment(request);
    if (!assessmentId) test.skip();

    const resp = await request.post(
      `${BASE}/api/v1/assessments/${encodeURIComponent(assessmentId)}/executive-summary`,
      {
        headers: { ...HEADERS, 'Content-Type': 'application/json' },
        data: { regenerate: true, model: 'qwen3.6:27b' },
      }
    );
    const body = await resp.json();
    // Either model_used matches, or the response has a non-generic executive_summary
    const modelOk = (body.model_used || '').includes('qwen3');
    expect(modelOk, `FAIL: model not used or not reported. model_used=${body.model_used}`).toBe(true);
  });
});
