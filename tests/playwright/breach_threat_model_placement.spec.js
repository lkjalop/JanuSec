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

test('threat modeling lives in threat case workbench, not Home', async ({ page, request }) => {
  const assessmentId = await resolveAssessmentId(request);
  await page.goto(`${BASE}/static/breach.html?assessment=${encodeURIComponent(assessmentId)}`, {
    waitUntil: 'domcontentloaded',
    timeout: 30000,
  });

  await expect(page.locator('[data-testid="br-home-threat-cases"]')).toBeVisible({ timeout: 20000 });
  await expect(page.locator('[data-testid="br-home-evidence-views"]')).toBeVisible();
  await expect(page.locator('.br-threat-model:visible')).toHaveCount(0);

  const firstOpen = page.locator('[data-testid="br-home-threat-cases"] button.br-card__open').first();
  const onclick = await firstOpen.getAttribute('onclick');
  const match = onclick && onclick.match(/window\.open\('([^']+)'/);
  expect(match && match[1]).toBeTruthy();

  await page.goto(`${BASE}${match[1]}`, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await expect(page.locator('[data-testid="bct-threat-model-workbench"]')).toBeVisible({ timeout: 20000 });
  await expect(page.locator('[data-model-section="dread"]')).toBeVisible();
  await expect(page.locator('[data-model-section="pasta"]')).toBeVisible();
  await expect(page.locator('[data-model-section="diamond"]')).toBeVisible();
  await expect(page.locator('[data-testid="bct-threat-model-refresh"]')).toBeVisible();
});
