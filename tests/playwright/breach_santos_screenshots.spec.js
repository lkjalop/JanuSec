const { test, expect } = require('@playwright/test');
const path = require('path');

const AID = process.env.SANTOS_ASSESSMENT_ID || 'assessment-1777008559-81de74d8';
const OUT = path.join('test-results', 'breach-santos-dread');

test('capture Santos breach DREAD pages', async ({ page }) => {
  test.setTimeout(90000);
  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'janusec-playwright-local');
    localStorage.setItem('tenantId', 'default');
    localStorage.setItem('selectedModel', 'qwen3:14b');
  });

  await page.goto(`/static/breach.html?assessment=${AID}`, { waitUntil: 'domcontentloaded' });
  // Exec block is inside the drill-down — open it first
  const toggleBtn = page.locator('[data-testid="br-toggle-drilldown"]');
  if (await toggleBtn.count() > 0) await toggleBtn.click();
  await expect(page.locator('[data-testid="br-exec-block"]')).toBeVisible({ timeout: 30000 });
  await expect(page.locator('body')).toContainText(/DREAD|SABSA|SFL_DATA|FINANCE_WH/i, { timeout: 30000 });
  await page.screenshot({ path: path.join(OUT, '01-home-dread-summary.png'), fullPage: true });

  const clusterId = await page.evaluate(() => {
    const card = document.querySelector('[data-testid^="br-card-"]');
    if (!card) return '';
    return card.getAttribute('data-testid').replace(/^br-card-/, '');
  });
  expect(clusterId).toBeTruthy();

  await page.goto(`/static/breach.html?assessment=${AID}&cluster=${encodeURIComponent(clusterId)}`, { waitUntil: 'domcontentloaded' });
  await expect(page.locator('[data-testid="bct-evidence-narrative"]')).toBeVisible({ timeout: 30000 });
  await page.screenshot({ path: path.join(OUT, '02-cluster-evidence-narrative.png'), fullPage: true });

  await page.goto(`/static/breach.html?assessment=${AID}&tab=evidence`, { waitUntil: 'domcontentloaded' });
  await page.screenshot({ path: path.join(OUT, '03-evidence-tab.png'), fullPage: true });
});
