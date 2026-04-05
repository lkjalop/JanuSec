const { test, expect } = require('@playwright/test');

test.describe('LLM Controls Smoke', () => {
  test('estimate and generate buttons work', async ({ page }) => {
    // Use the local dev server root
    await page.goto('http://localhost:8080/static/csv_analyzer.html');
    await page.waitForSelector('#llmLimit');
    const est = page.locator('#llmCostEstimate');
    const gen = page.locator('#btnGenerateMore');
    // Wait for initial estimate to populate (may be n/a in CI)
    await expect(est).toBeVisible();
    // Click generate and assert queuing state then restored
    await gen.click();
    await expect(gen).toHaveText(/Generate More|Queuing.../);
    // Allow short time for backend enqueue to respond
    await page.waitForTimeout(800);
    await expect(gen).toHaveText('Generate More');
  });
});
