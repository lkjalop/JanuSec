const { test, expect } = require('@playwright/test');

const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:8080';

async function resolveAssessmentId(request) {
  const resp = await request.get(`${BASE}/api/v1/assessments`, {
    headers: { 'x-api-key': 'devkey123', 'x-tenant-id': 'default' },
  });
  expect(resp.ok()).toBeTruthy();
  const body = await resp.json();
  const jobs = body.jobs || [];
  expect(jobs.length).toBeGreaterThan(0);
  return jobs[0].assessment_id;
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

  await page.goto(url);
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
