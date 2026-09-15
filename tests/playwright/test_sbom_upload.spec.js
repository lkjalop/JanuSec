const { test, expect } = require('@playwright/test');

test('SBOM upload happy path', async ({ page }) => {
  // Ensure API key set so uploads do not 401 and test hooks are active
  await page.addInitScript(() => { try{ localStorage.setItem('apiKey','devkey123'); localStorage.setItem('showDev','1'); }catch(e){} });
  await page.goto('/static/sbom.html');
  // Wait for deterministic test-ready indicator to be present
  // test_ready is injected hidden; wait for it to be attached to DOM
  await page.waitForSelector('#test_ready', { state: 'attached', timeout: 3000 });
  // Textarea should be prefilled with example in dev mode
  const ta = await page.locator('#sbom');
  await expect(ta).toHaveValue(/"components"/);

  // Intercept network for sbom upload
  const [req] = await Promise.all([
    page.waitForRequest(r => r.url().endsWith('/api/v1/sbom/upload') && r.method() === 'POST'),
    page.click('#btnUpload')
  ]);
  const postBody = JSON.parse(await req.postData());
  expect(postBody).toHaveProperty('components');

  // Wait for vulnerabilities table to render (either No vulnerabilities or rows)
  await page.waitForSelector('#tbl tbody');
  const rows = await page.locator('#tbl tbody tr').count();
  expect(rows).toBeGreaterThanOrEqual(1);
});
