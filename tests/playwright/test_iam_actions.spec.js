const { test, expect } = require('@playwright/test');

test('IAM violators render and remediation posts dispatch', async ({ page, request }) => {
  // Seed IAM audit with violators
  const payload = {
    tenant_id: 't1',
    users: [ { name: 'alice', is_admin: true, mfa_enabled: false }, { name: 'bob', is_admin: false, mfa_enabled: true } ],
    keys: [ { id: 'AKIA_TEST1', user: 'alice', last_used_days: 120, mfa_enabled: false } ],
    policies: [ { name: 'AdminStar', wildcard: true, attached_to: 'alice' } ]
  };
  await request.post('/api/v1/compliance/iam/audit', { headers: { 'x-api-key': 'devkey123' }, data: payload });

  await page.addInitScript(() => { try{ localStorage.setItem('apiKey','devkey123'); localStorage.setItem('tenantId','t1'); }catch(e){} });
  await page.goto('/static/iam.html');
  // Wait for violations block to render
  await page.waitForSelector('#violations', { timeout: 5000 });
  const bodyText = await page.$eval('#violations', el => el.innerText.toLowerCase());
  expect(bodyText).toContain('keys without mfa');
  expect(bodyText).toContain('unused keys');

  // Intercept disable-key remediation post
  const [req1] = await Promise.all([
    page.waitForRequest(r => r.url().endsWith('/api/v1/soar/remediate/iam/disable-key') && r.method() === 'POST'),
    page.locator('#violations button:has-text("Disable Key")').first().click()
  ]);
  const body1 = JSON.parse(await req1.postData());
  expect(body1).toHaveProperty('key_id');

  // Intercept enforce-mfa remediation post
  const [req2] = await Promise.all([
    page.waitForRequest(r => r.url().endsWith('/api/v1/soar/remediate/iam/enforce-mfa') && r.method() === 'POST'),
    page.locator('#violations button:has-text("Enforce MFA")').first().click()
  ]);
  const body2 = JSON.parse(await req2.postData());
  expect(body2).toHaveProperty('user');
});

