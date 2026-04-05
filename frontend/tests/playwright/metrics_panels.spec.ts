import { test, expect } from '@playwright/test';

test('Metrics page shows new panels', async ({ page }) => {
  await page.goto('/static/metrics.html');
  await expect(page.locator('#beforeAfterPanel')).toBeVisible();
  await expect(page.locator('#baTenantSelect')).toBeVisible();
  await expect(page.locator('#btnComputeBA')).toBeVisible();

  await expect(page.locator('#abPanel')).toBeVisible();
  await expect(page.locator('#abTenantSelect')).toBeVisible();
  await expect(page.locator('#abTestId')).toBeVisible();
  await expect(page.locator('#btnRunAB')).toBeVisible();
});
