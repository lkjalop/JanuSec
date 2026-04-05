const { test, expect } = require('@playwright/test');

test('graph page renders svg and export controls', async ({ page }) => {
  await page.goto('http://127.0.0.1:8080/static/graph_explain_v2.html');
  // Wait for svg to appear
  await page.waitForSelector('#graph svg', { timeout: 10000 });
  const svg = await page.$('#graph svg');
  expect(svg).toBeTruthy();
  // Export buttons should exist
  const png = await page.$('#exportPNG');
  const json = await page.$('#exportJSON');
  expect(png).toBeTruthy();
  expect(json).toBeTruthy();
});
