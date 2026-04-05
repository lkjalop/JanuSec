const { test, expect } = require('@playwright/test');

test('CSPM SG drift renders and Tighten posts dispatch', async ({ page, request }) => {
  // Seed SG drift with an open-to-world rule
  const payload = {
    tenant_id: 't1',
    events: [ { sg_id: 'sg-test-123', change: 'added', cidr: '0.0.0.0/0', port: 22, proto: 'tcp', reason: 'test' } ]
  };
  await request.post('/api/v1/compliance/net/sg/audit', { headers: { 'x-api-key': 'devkey123' }, data: payload });

  await page.addInitScript(() => { try{ localStorage.setItem('apiKey','devkey123'); localStorage.setItem('tenantId','t1'); }catch(e){} });
  await page.goto('/static/cspm.html');
  await page.waitForSelector('#drift', { timeout: 5000 });
  // Wait for SG row to appear
  await page.waitForSelector('table >> text=sg-test-123', { timeout: 5000 });

  // Intercept Tighten remediation
  const [req] = await Promise.all([
    page.waitForRequest(r => r.url().endsWith('/api/v1/soar/remediate/net/sg-tighten') && r.method() === 'POST'),
    page.locator('#drift button:has-text("Tighten")').first().click()
  ]);
  const body = JSON.parse(await req.postData());
  expect(body).toHaveProperty('sg_id');
});

