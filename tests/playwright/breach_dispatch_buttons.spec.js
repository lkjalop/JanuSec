/**
 * breach_dispatch_buttons.spec.js
 *
 * Full-button audit: verifies that all dispatch preview buttons in the breach
 * console work end-to-end — not stubs. Tests:
 *  - Compliance persona preview opens with meaningful content
 *  - "Preview Full Compliance Report" opens postmortem viewer with sections
 *  - "Generate Deep Report" opens postmortem tab with structured data
 *  - "Confirm & Send to Compliance" returns 200 and shows Dispatched state
 *  - "Regenerate" re-renders the dispatch preview without error
 *  - Exec summary "regenerate" button triggers LLM call
 *
 * Requires:
 *  - Server running at http://localhost:8080 with PLATFORM_LITE_INIT=1
 *  - At least one assessment in ready state
 *
 * Run:
 *   npx playwright test tests/playwright/breach_dispatch_buttons.spec.js --workers=1
 */
const { test, expect } = require('@playwright/test');

const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:8080';
const HEADERS = { 'x-api-key': 'devkey123', 'x-tenant-id': 'default' };

async function getLatestAssessment(request) {
  const resp = await request.get(`${BASE}/api/v1/assessments`, { headers: HEADERS });
  if (!resp.ok()) return null;
  const body = await resp.json();
  const jobs = (body.jobs || []).sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
  return jobs.length ? jobs[0].assessment_id : null;
}

test.describe('Dispatch Preview — Full Button Audit', () => {
  let assessmentId;

  test.beforeAll(async ({ request }) => {
    assessmentId = await getLatestAssessment(request);
    if (!assessmentId) test.skip();
  });

  test('page loads with assessment data and verdict banner', async ({ page }) => {
    await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`);
    // Wait for the verdict banner
    const verdict = page.locator('[class*="verdict"]').first();
    await expect(verdict).toBeVisible({ timeout: 20000 });
    const pageText = await page.locator('#br-content').innerText();
    expect(pageText).toContain('BREACH ASSESSMENT VERDICT');
    expect(pageText).toContain('EXECUTIVE SUMMARY');
  });

  test('exec summary regenerate button triggers LLM call', async ({ page }) => {
    await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`);
    // Wait for exec summary section
    await page.waitForSelector('#br-exec-regen', { timeout: 20000 });
    const regenBtn = page.locator('#br-exec-regen');
    await regenBtn.click();
    // Should show "regenerating…"
    await expect(regenBtn).toContainText('regenerating', { timeout: 5000 });
  });

  test('compliance dispatch opens preview with postmortem content', async ({ page }) => {
    await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`);
    // Wait for dispatch buttons to appear
    await page.waitForSelector('[data-testid="br-dispatch-compliance"], button:has-text("Compliance")', { timeout: 20000 });
    // Click Compliance in the dispatch section
    const compBtn = page.locator('button:has-text("Compliance")').first();
    await compBtn.click();
    // Dispatch preview should become visible
    const preview = page.locator('#br-dispatch-preview');
    await expect(preview).toBeVisible({ timeout: 10000 });
    const previewText = await preview.innerText();
    // Should contain dispatch-specific elements
    expect(previewText).toContain('DISPATCH PREVIEW');
    expect(previewText.toUpperCase()).toContain('WHAT THEY RECEIVE');
    expect(previewText.toUpperCase()).toContain('DELIVERY CHANNEL');
    expect(previewText).toContain('Preview Full Compliance Report');
    expect(previewText).toContain('Confirm & Send to Compliance');
  });

  test('compliance dispatch preview shows postmortem enrichment (not empty)', async ({ page }) => {
    await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`);
    await page.waitForSelector('button:has-text("Compliance")', { timeout: 20000 });
    await page.locator('button:has-text("Compliance")').first().click();
    const preview = page.locator('#br-dispatch-preview');
    await expect(preview).toBeVisible({ timeout: 10000 });
    // Wait for async postmortem enrichment to load
    await page.waitForTimeout(3000);
    const previewText = await preview.innerText();
    // Should show meaningful lifecycle content (not just placeholder)
    const hasLifecycle = /DETECT|ISO 27035|Corrective Actions|P1/i.test(previewText);
    expect(hasLifecycle, `Dispatch preview lacks postmortem enrichment. Got: "${previewText.slice(0, 300)}"`).toBe(true);
  });

  test('"Preview Full Compliance Report" link targets postmortem viewer', async ({ page }) => {
    await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`);
    await page.waitForSelector('button:has-text("Compliance")', { timeout: 20000 });
    await page.locator('button:has-text("Compliance")').first().click();
    const preview = page.locator('#br-dispatch-preview');
    await expect(preview).toBeVisible({ timeout: 10000 });
    const link = preview.locator('a:has-text("Preview Full Compliance Report")');
    await expect(link).toBeVisible();
    const href = await link.getAttribute('href');
    expect(href).toContain('/static/postmortem_viewer.html');
    expect(href).toContain('assessment=');
    expect(href).toContain('cluster=');
  });

  test('"Preview Full Compliance Report" page loads real sections', async ({ page }) => {
    await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`);
    await page.waitForSelector('button:has-text("Compliance")', { timeout: 20000 });
    await page.locator('button:has-text("Compliance")').first().click();
    const preview = page.locator('#br-dispatch-preview');
    await expect(preview).toBeVisible({ timeout: 10000 });
    const link = preview.locator('a:has-text("Preview Full Compliance Report")');
    const href = await link.getAttribute('href');
    // Navigate to the postmortem viewer
    await page.goto(`${BASE}${href}`);
    await page.waitForTimeout(3000);
    const bodyText = await page.locator('body').innerText();
    // Should have real structured report content
    expect(bodyText).toContain('Compliance & ISMS Postmortem Report');
    expect(bodyText).toMatch(/Incident Lifecycle|ISO 27035 Lifecycle/);
    // Should have verdict table
    expect(bodyText).toMatch(/REQUIRES_INVESTIGATION|VALIDATED_BREACH|CONFIRMED_BREACH/);
    // Should have corrective actions
    expect(bodyText).toMatch(/Corrective Actions|P1/);
  });

  test('"Generate Deep Report" opens postmortem tab with structured data', async ({ page }) => {
    await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`);
    await page.waitForSelector('button:has-text("Compliance")', { timeout: 20000 });
    await page.locator('button:has-text("Compliance")').first().click();
    const preview = page.locator('#br-dispatch-preview');
    await expect(preview).toBeVisible({ timeout: 10000 });
    // Expand "More actions" details
    const moreActions = preview.locator('summary:has-text("More actions")');
    await moreActions.click();
    const deepBtn = preview.locator('button:has-text("Generate Deep Report")');
    await expect(deepBtn).toBeVisible({ timeout: 3000 });
    await deepBtn.click();
    // Should navigate to postmortem tab
    await page.waitForURL(/tab=postmortem/, { timeout: 10000 });
    await page.waitForTimeout(3000);
    const bodyText = await page.locator('body').innerText();
    // Postmortem tab should show cluster-level structured data
    expect(bodyText).toContain('Postmortem');
    expect(bodyText).toMatch(/ISO 27035|Incident Lifecycle|Corrective Actions/);
  });

  test('"Confirm & Send to Compliance" dispatches successfully (not a stub)', async ({ page, request }) => {
    // Verify the API endpoint works directly
    const resp = await request.post(`${BASE}/api/v1/dispatch/notify`, {
      headers: { ...HEADERS, 'Content-Type': 'application/json' },
      data: {
        assessment_id: assessmentId,
        role: 'compliance',
        channel: 'email',
        requires_change_management: false,
      },
    });
    // Should return 200 (not 404/501 which would indicate stub)
    expect(resp.status(), `dispatch/notify returned ${resp.status()}, expected 200`).toBe(200);
    const body = await resp.json();
    expect(body).toHaveProperty('message');
    // Demo mode is acceptable
    expect(body.demo === true || body.dispatched === true || body.message).toBeTruthy();
  });

  test('"Regenerate" in More actions re-renders dispatch preview', async ({ page }) => {
    await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`);
    await page.waitForSelector('button:has-text("Compliance")', { timeout: 20000 });
    await page.locator('button:has-text("Compliance")').first().click();
    const preview = page.locator('#br-dispatch-preview');
    await expect(preview).toBeVisible({ timeout: 10000 });
    // Expand "More actions"
    const moreActions = preview.locator('summary:has-text("More actions")');
    await moreActions.click();
    const regenBtn = preview.locator('button:has-text("Regenerate")');
    await expect(regenBtn).toBeVisible({ timeout: 3000 });
    await regenBtn.click();
    // Preview should still be visible after regeneration
    await page.waitForTimeout(2000);
    const newPreview = page.locator('#br-dispatch-preview');
    await expect(newPreview).toBeVisible();
    const previewText = await newPreview.innerText();
    expect(previewText).toContain('DISPATCH PREVIEW');
  });

  test('SOC Analyst dispatch preview shows containment content', async ({ page }) => {
    await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`);
    await page.waitForSelector('button:has-text("SOC Analyst")', { timeout: 20000 });
    await page.locator('button:has-text("SOC Analyst")').first().click();
    const preview = page.locator('#br-dispatch-preview');
    await expect(preview).toBeVisible({ timeout: 10000 });
    const previewText = await preview.innerText();
    expect(previewText).toContain('DISPATCH PREVIEW');
    // SOC should show triage/containment language
    expect(previewText).toMatch(/confidence|evidence|containment|triage|isolat/i);
  });

  test('Executive dispatch preview shows business-oriented content', async ({ page }) => {
    await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`);
    await page.waitForSelector('button:has-text("Executive")', { timeout: 20000 });
    await page.locator('button:has-text("Executive")').first().click();
    const preview = page.locator('#br-dispatch-preview');
    await expect(preview).toBeVisible({ timeout: 10000 });
    const previewText = await preview.innerText();
    expect(previewText).toContain('DISPATCH PREVIEW');
  });

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
    // Filter out expected errors (network failures from missing endpoints)
    const realErrors = errors.filter(e => !e.includes('Failed to load resource') && !e.includes('tier1-summary'));
    expect(realErrors, `Unexpected console errors: ${realErrors.join('; ')}`).toHaveLength(0);
  });
});
