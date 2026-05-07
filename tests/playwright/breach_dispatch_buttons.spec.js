/**
 * breach_dispatch_buttons.spec.js
 *
 * Full-button audit: verifies that ALL dispatch persona previews work end-to-end,
 * including: SOC Analyst, CISO/Legal, Executive, Threat Hunter, Forensics, Compliance.
 * Also tests: "Preview Full Report" link, "Generate Deep Report", "Confirm & Send",
 * "Regenerate", postmortem viewer Control Failures page, and SABSA Architecture page.
 *
 * Requires:
 *  - Server running at http://localhost:8080 with PLATFORM_LITE_INIT=1
 *  - At least one assessment in ready state
 *
 * Run:
 *   npx playwright test tests/playwright/breach_dispatch_buttons.spec.js --workers=1
 */
const { test, expect } = require('@playwright/test');

const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:8080';
const HEADERS = { 'x-api-key': 'devkey123', 'x-tenant-id': 'default' };

async function getLatestAssessment(request) {
  const resp = await request.get(`${BASE}/api/v1/assessments`, { headers: HEADERS });
  if (!resp.ok()) return null;
  const body = await resp.json();
  const jobs = (body.jobs || []).sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
  return jobs.length ? jobs[0].assessment_id : null;
}

/** Helper: open breach page, click persona dispatch button, return preview text */
async function openDispatchPreview(page, assessmentId, personaLabel) {
  await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`);
  await page.waitForSelector(`button:has-text("${personaLabel}")`, { timeout: 25000 });
  await page.locator(`button:has-text("${personaLabel}")`).first().click();
  const preview = page.locator('#br-dispatch-preview');
  await expect(preview).toBeVisible({ timeout: 15000 });
  await page.waitForTimeout(2000); // allow async enrichment
  return await preview.innerText();
}

// ─── Page Load & Exec Summary ──────────────────────────────────────────────

test.describe('Dispatch Preview — Full Button Audit', () => {
  let assessmentId;

  test.beforeAll(async ({ request }) => {
    assessmentId = await getLatestAssessment(request);
    if (!assessmentId) test.skip();
  });

  test('page loads with assessment data and verdict banner', async ({ page }) => {
    await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`);
    const verdict = page.locator('[class*="verdict"]').first();
    await expect(verdict).toBeVisible({ timeout: 20000 });
    const pageText = await page.locator('#br-content').innerText();
    expect(pageText).toContain('BREACH ASSESSMENT VERDICT');
    expect(pageText).toContain('EXECUTIVE SUMMARY');
  });

  test('exec summary regenerate button triggers LLM call', async ({ page }) => {
    await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`);
    await page.waitForSelector('#br-exec-regen', { timeout: 20000 });
    const regenBtn = page.locator('#br-exec-regen');
    await regenBtn.click();
    await expect(regenBtn).toContainText('regenerating', { timeout: 5000 });
  });

  // ─── SOC Analyst ───────────────────────────────────────────────────────────

  test('SOC Analyst dispatch preview opens with triage content', async ({ page }) => {
    const text = await openDispatchPreview(page, assessmentId, 'SOC Analyst');
    expect(text.toUpperCase()).toContain('DISPATCH PREVIEW');
    expect(text.toUpperCase()).toContain('SOC');
    expect(text.toUpperCase()).toContain('WHAT THEY RECEIVE');
    // SOC should show containment/triage/IOC language
    expect(text).toMatch(/confidence|containment|triage|isolat|IOC|evidence/i);
  });

  test('SOC Analyst dispatch has "Confirm & Send" and delivery channel', async ({ page }) => {
    const text = await openDispatchPreview(page, assessmentId, 'SOC Analyst');
    expect(text.toUpperCase()).toContain('DELIVERY CHANNEL');
    expect(text).toMatch(/Confirm & Send/i);
  });

  test('SOC Analyst "Generate Deep Report" navigates to postmortem', async ({ page }) => {
    await openDispatchPreview(page, assessmentId, 'SOC Analyst');
    const preview = page.locator('#br-dispatch-preview');
    const moreActions = preview.locator('summary:has-text("More actions")');
    await moreActions.click();
    const deepBtn = preview.locator('button:has-text("Generate Deep Report")');
    await expect(deepBtn).toBeVisible({ timeout: 3000 });
    await deepBtn.click();
    await page.waitForURL(/tab=postmortem/, { timeout: 10000 });
    await page.waitForSelector('.br-postmortem, [class*="postmortem"], #br-content:has-text("Postmortem")', { timeout: 20000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).toMatch(/Postmortem|postmortem|ISO 27035|Corrective/i);
  });

  // ─── CISO / Legal ──────────────────────────────────────────────────────────

  test('CISO / Legal dispatch preview opens with regulatory content', async ({ page }) => {
    const text = await openDispatchPreview(page, assessmentId, 'CISO / Legal');
    expect(text.toUpperCase()).toContain('DISPATCH PREVIEW');
    expect(text.toUpperCase()).toContain('CISO');
    expect(text.toUpperCase()).toContain('WHAT THEY RECEIVE');
    // CISO should show regulatory/compliance/notification language
    expect(text).toMatch(/regulatory|compliance|notification|NDB|GDPR|breach|confidence|control/i);
  });

  test('CISO / Legal dispatch has delivery channel and confirm button', async ({ page }) => {
    const text = await openDispatchPreview(page, assessmentId, 'CISO / Legal');
    expect(text.toUpperCase()).toContain('DELIVERY CHANNEL');
    expect(text).toMatch(/Confirm & Send/i);
  });

  test('CISO / Legal "Generate Deep Report" navigates to postmortem', async ({ page }) => {
    await openDispatchPreview(page, assessmentId, 'CISO / Legal');
    const preview = page.locator('#br-dispatch-preview');
    const moreActions = preview.locator('summary:has-text("More actions")');
    await moreActions.click();
    const deepBtn = preview.locator('button:has-text("Generate Deep Report")');
    await expect(deepBtn).toBeVisible({ timeout: 3000 });
    await deepBtn.click();
    await page.waitForURL(/tab=postmortem/, { timeout: 10000 });
    await page.waitForSelector('.br-postmortem, [class*="postmortem"], #br-content:has-text("Postmortem")', { timeout: 20000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).toMatch(/Postmortem|postmortem|ISO 27035|Corrective/i);
  });

  // ─── Executive ─────────────────────────────────────────────────────────────

  test('Executive dispatch preview opens with business content', async ({ page }) => {
    const text = await openDispatchPreview(page, assessmentId, 'Executive');
    expect(text.toUpperCase()).toContain('DISPATCH PREVIEW');
    expect(text.toUpperCase()).toContain('EXECUTIVE');
    expect(text.toUpperCase()).toContain('WHAT THEY RECEIVE');
    // Executive should show business/impact language
    expect(text).toMatch(/confidence|impact|breach|business|material|risk|action/i);
  });

  test('Executive dispatch has delivery channel and confirm button', async ({ page }) => {
    const text = await openDispatchPreview(page, assessmentId, 'Executive');
    expect(text.toUpperCase()).toContain('DELIVERY CHANNEL');
    expect(text).toMatch(/Confirm & Send/i);
  });

  test('Executive "Generate Deep Report" navigates to postmortem', async ({ page }) => {
    await openDispatchPreview(page, assessmentId, 'Executive');
    const preview = page.locator('#br-dispatch-preview');
    const moreActions = preview.locator('summary:has-text("More actions")');
    await moreActions.click();
    const deepBtn = preview.locator('button:has-text("Generate Deep Report")');
    await expect(deepBtn).toBeVisible({ timeout: 3000 });
    await deepBtn.click();
    await page.waitForURL(/tab=postmortem/, { timeout: 10000 });
    await page.waitForSelector('.br-postmortem, [class*="postmortem"], #br-content:has-text("Postmortem")', { timeout: 20000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).toMatch(/Postmortem|postmortem|ISO 27035|Corrective/i);
  });

  // ─── Threat Hunter ─────────────────────────────────────────────────────────

  test('Threat Hunter dispatch preview opens with hunt content', async ({ page }) => {
    const text = await openDispatchPreview(page, assessmentId, 'Threat Hunter');
    expect(text.toUpperCase()).toContain('DISPATCH PREVIEW');
    expect(text.toUpperCase()).toContain('THREAT HUNTER');
    expect(text.toUpperCase()).toContain('WHAT THEY RECEIVE');
    // Threat hunter should show kill chain/sigma/hunt language
    expect(text).toMatch(/kill chain|sigma|hunt|pivot|hypothesis|IOC|confidence|evidence|phase/i);
  });

  test('Threat Hunter dispatch has delivery channel and confirm button', async ({ page }) => {
    const text = await openDispatchPreview(page, assessmentId, 'Threat Hunter');
    expect(text.toUpperCase()).toContain('DELIVERY CHANNEL');
    expect(text).toMatch(/Confirm & Send/i);
  });

  test('Threat Hunter "Generate Deep Report" navigates to postmortem', async ({ page }) => {
    await openDispatchPreview(page, assessmentId, 'Threat Hunter');
    const preview = page.locator('#br-dispatch-preview');
    const moreActions = preview.locator('summary:has-text("More actions")');
    await moreActions.click();
    const deepBtn = preview.locator('button:has-text("Generate Deep Report")');
    await expect(deepBtn).toBeVisible({ timeout: 3000 });
    await deepBtn.click();
    await page.waitForURL(/tab=postmortem/, { timeout: 10000 });
    await page.waitForSelector('.br-postmortem, [class*="postmortem"], #br-content:has-text("Postmortem")', { timeout: 20000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).toMatch(/Postmortem|postmortem|ISO 27035|Corrective/i);
  });

  // ─── Forensics ─────────────────────────────────────────────────────────────

  test('Forensics dispatch preview opens with artifact content', async ({ page }) => {
    const text = await openDispatchPreview(page, assessmentId, 'Forensics');
    expect(text.toUpperCase()).toContain('DISPATCH PREVIEW');
    expect(text.toUpperCase()).toContain('FORENSIC');
    expect(text.toUpperCase()).toContain('WHAT THEY RECEIVE');
    // Forensics should show artifact/evidence/chain-of-custody language
    expect(text).toMatch(/artifact|evidence|custody|memory|disk|proof|confidence|preserve/i);
  });

  test('Forensics dispatch has delivery channel and confirm button', async ({ page }) => {
    const text = await openDispatchPreview(page, assessmentId, 'Forensics');
    expect(text.toUpperCase()).toContain('DELIVERY CHANNEL');
    expect(text).toMatch(/Confirm & Send/i);
  });

  test('Forensics "Generate Deep Report" navigates to postmortem', async ({ page }) => {
    await openDispatchPreview(page, assessmentId, 'Forensics');
    const preview = page.locator('#br-dispatch-preview');
    const moreActions = preview.locator('summary:has-text("More actions")');
    await moreActions.click();
    const deepBtn = preview.locator('button:has-text("Generate Deep Report")');
    await expect(deepBtn).toBeVisible({ timeout: 3000 });
    await deepBtn.click();
    await page.waitForURL(/tab=postmortem/, { timeout: 10000 });
    await page.waitForSelector('.br-postmortem, [class*="postmortem"], #br-content:has-text("Postmortem")', { timeout: 20000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).toMatch(/Postmortem|postmortem|ISO 27035|Corrective/i);
  });

  // ─── Compliance (existing, consolidated) ───────────────────────────────────

  test('Compliance dispatch preview opens with control/framework content', async ({ page }) => {
    const text = await openDispatchPreview(page, assessmentId, 'Compliance');
    expect(text.toUpperCase()).toContain('DISPATCH PREVIEW');
    expect(text.toUpperCase()).toContain('COMPLIANCE');
    expect(text.toUpperCase()).toContain('WHAT THEY RECEIVE');
    expect(text.toUpperCase()).toContain('DELIVERY CHANNEL');
    expect(text).toContain('Preview Full Compliance Report');
    expect(text).toMatch(/Confirm & Send/i);
    // Compliance enrichment content
    expect(text).toMatch(/DETECT|ISO 27035|Corrective Actions|P1|LIFECYCLE/i);
  });

  test('Compliance "Preview Full Report" link opens postmortem viewer', async ({ page }) => {
    await openDispatchPreview(page, assessmentId, 'Compliance');
    const preview = page.locator('#br-dispatch-preview');
    const link = preview.locator('a:has-text("Preview Full Compliance Report")');
    await expect(link).toBeVisible();
    const href = await link.getAttribute('href');
    expect(href).toContain('/static/postmortem_viewer.html');
    expect(href).toContain('assessment=');
    expect(href).toContain('cluster=');
  });

  test('Compliance "Generate Deep Report" navigates to postmortem', async ({ page }) => {
    await openDispatchPreview(page, assessmentId, 'Compliance');
    const preview = page.locator('#br-dispatch-preview');
    const moreActions = preview.locator('summary:has-text("More actions")');
    await moreActions.click();
    const deepBtn = preview.locator('button:has-text("Generate Deep Report")');
    await expect(deepBtn).toBeVisible({ timeout: 3000 });
    await deepBtn.click();
    await page.waitForURL(/tab=postmortem/, { timeout: 10000 });
    await page.waitForSelector('.br-postmortem, [class*="postmortem"], #br-content:has-text("Postmortem")', { timeout: 20000 });
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).toMatch(/Postmortem|postmortem|ISO 27035|Corrective/i);
  });

  // ─── Dispatch API (all personas) ──────────────────────────────────────────

  const DISPATCH_ROLES = ['soc_analyst', 'ciso', 'executive', 'threat_hunter', 'forensics', 'compliance'];

  for (const role of DISPATCH_ROLES) {
    test(`dispatch/notify API returns 200 for role=${role}`, async ({ request }) => {
      const resp = await request.post(`${BASE}/api/v1/dispatch/notify`, {
        headers: { ...HEADERS, 'Content-Type': 'application/json' },
        data: {
          assessment_id: assessmentId,
          role: role,
          channel: 'email',
          requires_change_management: false,
        },
      });
      expect(resp.status(), `dispatch/notify returned ${resp.status()} for ${role}`).toBe(200);
      const body = await resp.json();
      expect(body).toHaveProperty('message');
    });
  }

  // ─── Regenerate Button ─────────────────────────────────────────────────────

  test('"Regenerate" in More actions re-renders dispatch preview', async ({ page }) => {
    await openDispatchPreview(page, assessmentId, 'Compliance');
    const preview = page.locator('#br-dispatch-preview');
    const moreActions = preview.locator('summary:has-text("More actions")');
    await moreActions.click();
    const regenBtn = preview.locator('button:has-text("Regenerate")');
    await expect(regenBtn).toBeVisible({ timeout: 3000 });
    await regenBtn.click();
    await page.waitForTimeout(2000);
    const newPreview = page.locator('#br-dispatch-preview');
    await expect(newPreview).toBeVisible();
    const previewText = await newPreview.innerText();
    expect(previewText).toContain('DISPATCH PREVIEW');
  });

  // ─── Postmortem Viewer — Control Failures Page ─────────────────────────────

  test('postmortem viewer loads Control Failures section', async ({ page }) => {
    await openDispatchPreview(page, assessmentId, 'Compliance');
    const preview = page.locator('#br-dispatch-preview');
    const link = preview.locator('a:has-text("Preview Full Compliance Report")');
    const href = await link.getAttribute('href');
    await page.goto(`${BASE}${href}`);
    await page.waitForTimeout(3000);
    // Click "Control Failures" nav item
    await page.click('[data-sec="controls"]');
    await page.waitForTimeout(1000);
    const section = page.locator('#sec-controls');
    await expect(section).toBeVisible();
    const controlsText = await section.innerText();
    // Should show control failures section title or placeholder
    expect(controlsText).toMatch(/Control Failure|control|No control failures|0 control/i);
  });

  // ─── Postmortem Viewer — SABSA Architecture Page ───────────────────────────

  test('postmortem viewer loads SABSA Architecture section', async ({ page }) => {
    await openDispatchPreview(page, assessmentId, 'Compliance');
    const preview = page.locator('#br-dispatch-preview');
    const link = preview.locator('a:has-text("Preview Full Compliance Report")');
    const href = await link.getAttribute('href');
    await page.goto(`${BASE}${href}`);
    await page.waitForTimeout(3000);
    // Click "SABSA Architecture" nav item
    await page.click('[data-sec="sabsa"]');
    await page.waitForTimeout(1000);
    const section = page.locator('#sec-sabsa');
    await expect(section).toBeVisible();
    const sabsaText = await section.innerText();
    // Should show SABSA layers or at least section structure
    expect(sabsaText).toMatch(/SABSA|Architecture|layer|business|logical|physical|component/i);
  });

  // ─── Postmortem Viewer — All Sections Reachable ────────────────────────────

  test('postmortem viewer all nav sections are accessible', async ({ page }) => {
    await openDispatchPreview(page, assessmentId, 'Compliance');
    const preview = page.locator('#br-dispatch-preview');
    const link = preview.locator('a:has-text("Preview Full Compliance Report")');
    const href = await link.getAttribute('href');
    await page.goto(`${BASE}${href}`);
    await page.waitForTimeout(3000);

    const sections = ['verdict', 'lifecycle', 'threat', 'controls', 'sabsa', 'risk', 'regs', 'actions'];
    for (const sec of sections) {
      await page.click(`[data-sec="${sec}"]`);
      await page.waitForTimeout(500);
      const el = page.locator(`#sec-${sec}`);
      const isVisible = await el.isVisible();
      expect(isVisible, `Section #sec-${sec} should be visible after clicking nav`).toBe(true);
    }
  });

  // ─── No Console Errors ─────────────────────────────────────────────────────

  test('no console errors on dispatch preview interactions', async ({ page }) => {
    const errors = [];
    page.on('console', msg => {
      if (msg.type() === 'error' && !msg.text().includes('net::ERR_')) {
        errors.push(msg.text());
      }
    });
    await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`);
    await page.waitForSelector('button:has-text("Compliance")', { timeout: 20000 });
    await page.locator('button:has-text("Compliance")').first().click();
    await page.waitForTimeout(2000);
    const realErrors = errors.filter(e => !e.includes('Failed to load resource') && !e.includes('tier1-summary'));
    expect(realErrors, `Unexpected console errors: ${realErrors.join('; ')}`).toHaveLength(0);
  });
});
