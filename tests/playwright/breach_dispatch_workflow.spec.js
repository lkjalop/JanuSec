const { test, expect } = require('@playwright/test');

const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:8080';

async function resolveAssessmentId(request) {
  const fallback = process.env.PLAYWRIGHT_ASSESSMENT_ID || 'assessment-1777494094-eb6931fb';
  try {
    const resp = await request.get(`${BASE}/api/v1/assessments`, {
      headers: { 'x-api-key': 'devkey123', 'x-tenant-id': 'default' },
      timeout: 5000,
    });
    if (resp.ok()) {
      const body = await resp.json();
      const jobs = body.jobs || [];
      if (jobs.length && jobs[0].assessment_id) return jobs[0].assessment_id;
    }
  } catch (_) {}
  return fallback;
}

test('dispatch workflow: preview, CAB toggle payload, confirm disables', async ({ page, request }) => {
  const assessmentId = await resolveAssessmentId(request);
  const url = `${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`;

  let dispatchPayload = null;
  await page.route('**/api/v1/dispatch/notify', async route => {
    dispatchPayload = route.request().postDataJSON();
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        role: 'soc_analyst',
        delivered: false,
        demo: true,
        message: '[DEMO] Persona report ready for SOC_ANALYST',
      }),
    });
  });

  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await expect(page.locator('[data-testid="br-dispatch"]')).toBeVisible({ timeout: 20000 });

  await page.locator('[data-testid="br-dispatch-soc_analyst"]').click();
  await expect(page.locator('#br-dispatch-preview')).toBeVisible();

  const cabCheckbox = page.locator('#br-dispatch-change-mgmt');
  await expect(cabCheckbox).toBeVisible();
  await expect(cabCheckbox).not.toBeChecked();
  await cabCheckbox.check();
  await expect(cabCheckbox).toBeChecked();

  const confirmBtn = page.locator('#br-dispatch-confirm');
  await confirmBtn.click();

  await expect.poll(() => dispatchPayload).not.toBeNull();
  expect(dispatchPayload.role).toBe('soc_analyst');
  expect(dispatchPayload.assessment_id).toBe(assessmentId);
  expect(dispatchPayload.requires_change_management).toBe(true);

  await expect(confirmBtn).toBeDisabled();
  await expect(confirmBtn).toContainText('Dispatched');
});

test('compliance dispatch footer and more-actions buttons are wired', async ({ page, request }) => {
  const assessmentId = await resolveAssessmentId(request);
  const url = `${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`;
  const hits = [];

  await page.route('**/api/v1/report/ingestion**', async route => {
    const u = new URL(route.request().url());
    hits.push({ type: 'report', apiKey: u.searchParams.get('api_key'), persona: u.searchParams.get('persona') });
    await route.fulfill({ status: 200, contentType: 'text/html', body: '<!doctype html><title>report</title><body>report ok</body>' });
  });
  await page.route('**/api/v1/postmortem/**/assemble', async route => {
    hits.push({ type: 'assemble' });
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ postmortem: { sections: [] } }) });
  });
  await page.route('**/api/v1/postmortem/**/push-itsm', async route => {
    hits.push({ type: 'push', target: route.request().postDataJSON().target });
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, ticket_url: 'demo://ticket' }) });
  });
  await page.route('**/api/v1/assessments/**/persona-dispatch', async route => {
    hits.push({ type: 'regen', persona: route.request().postDataJSON().persona });
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ payload: { headline: 'regenerated compliance payload' } }) });
  });
  await page.route('**/api/v1/dispatch/notify', async route => {
    hits.push({ type: 'confirm', role: route.request().postDataJSON().role });
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ demo: true, message: 'sent' }) });
  });

  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await expect(page.locator('[data-testid="br-dispatch"]')).toBeVisible({ timeout: 20000 });

  await page.locator('[data-testid="br-dispatch-soc_analyst"]').click();
  await expect(page.locator('#br-dispatch-preview-link')).toHaveAttribute('href', /api_key=devkey123/);

  await page.locator('[data-testid="br-dispatch-compliance"]').click();
  await expect(page.locator('#br-dispatch-preview')).toBeVisible();

  await expect(page.locator('#br-dispatch-preview-link')).toContainText('Preview Full Compliance Report');
  await expect(page.locator('#br-dispatch-confirm')).toContainText('Confirm');
  await expect(page.locator('.br-dispatch-more__summary')).toContainText('More actions');
  await expect(page.locator('#br-dispatch-cancel')).toContainText('Cancel');

  const [viewer] = await Promise.all([
    page.waitForEvent('popup'),
    page.locator('#br-dispatch-preview-link').click(),
  ]);
  await expect.poll(() => viewer.url()).toContain('/static/postmortem_viewer.html');
  await viewer.close();

  await page.locator('.br-dispatch-more__summary').click();
  await expect(page.locator('#br-dispatch-deep')).toBeVisible();
  await expect(page.locator('#br-dispatch-rebuild-pm')).toBeVisible();
  await expect(page.locator('[data-push-target="jira"]')).toBeVisible();
  await expect(page.locator('[data-push-target="confluence"]')).toBeVisible();
  await expect(page.locator('[data-push-target="servicenow"]')).toBeVisible();
  await expect(page.locator('#br-dispatch-regen')).toBeVisible();

  await page.evaluate(() => {
    window.__pmOpenArgs = null;
    window.JanusecPostmortem = { openTab: (aid, cid) => { window.__pmOpenArgs = [aid, cid]; } };
  });
  await page.locator('#br-dispatch-deep').click();
  await expect.poll(() => page.evaluate(() => window.__pmOpenArgs)).not.toBeNull();

  await page.locator('#br-dispatch-rebuild-pm').click();
  await expect.poll(() => hits.some(h => h.type === 'assemble')).toBeTruthy();

  if (!(await page.locator('[data-push-target="jira"]').isVisible())) {
    await page.locator('.br-dispatch-more__summary').click();
  }
  await page.locator('[data-push-target="jira"]').click();
  await expect.poll(() => hits.some(h => h.type === 'push' && h.target === 'jira')).toBeTruthy();

  if (!(await page.locator('#br-dispatch-regen').isVisible())) {
    await page.locator('.br-dispatch-more__summary').click();
  }
  await page.locator('#br-dispatch-regen').click();
  await expect.poll(() => hits.some(h => h.type === 'regen' && h.persona === 'compliance')).toBeTruthy();

  await page.locator('#br-dispatch-confirm').click();
  await expect.poll(() => hits.some(h => h.type === 'confirm' && h.role === 'compliance')).toBeTruthy();

  expect(hits.some(h => h.type === 'confirm' && h.role === 'compliance')).toBeTruthy();
});
