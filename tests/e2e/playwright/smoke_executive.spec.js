const { test, expect } = require('@playwright/test');

test('executive page loads and shows drivers', async ({ page }) => {
  await page.goto('http://127.0.0.1:8080/static/executive.html');
  await page.waitForSelector('#k_active');
  const active = await page.$('#k_active');
  expect(active).toBeTruthy();
  // wait for drivers or error message
  await page.waitForSelector('#drivers', { timeout: 10000 });
  const drivers = await page.$('#drivers');
  expect(drivers).toBeTruthy();
});
