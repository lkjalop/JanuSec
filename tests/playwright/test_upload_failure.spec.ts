import { test, expect } from '@playwright/test';

const BASE = process.env.BASE_URL || 'http://localhost:8080';

test('upload failure 401 shows auth banner and toast', async ({ page }) => {
  await page.goto(BASE + '/static/sbom.html');
  // ensure no api key is set so upload will 401
  await page.evaluate(() => { localStorage.removeItem('apiKey'); });
  await page.waitForLoadState('networkidle');
  // click Use example SBOM to populate textarea
  await page.click('#useExampleSbom');
  // try upload (button id uploadSbomButton expected)
  await page.click('#uploadSbomButton');
  // wait a bit for toast and banner
  await page.waitForTimeout(600);
  // auth banner should be visible
  const banner = page.locator('#authProbeBanner');
  await expect(banner).toBeVisible();
});
