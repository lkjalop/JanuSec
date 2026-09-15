import { test, expect } from '@playwright/test';

// This test requires the demo server to be running locally on :8080 and uses demo api key
// It performs a minimal sanity run: open investigate page, attempt to build with a test assessment id

test('investigate page basic build and verify', async ({ page }) => {
  // Create a minimal assessment via API to drive the investigate UI
  const apiRoot = 'http://localhost:8080/api/v1/assessments';
  const demoKey = 'devkey123';
  const payload = {
    rows: [
      { process: 'powershell.exe', user: 'alice', host: 'host1', verdict: 'suspicious', factors: ['no_network_logs','script_execution'] },
      { process: 'cmd.exe', user: 'bob', host: 'host2', verdict: 'high', factors: ['threat_intel_hit'] }
    ],
    options: { auto_llm: false }
  };
  const resp = await page.request.post(apiRoot + '/deep_analyze', { data: payload, headers: { 'x-api-key': demoKey } });
  if (resp.status() !== 200) {
    test.skip();
    return;
  }
  const body = await resp.json();
  const assessmentId = body.assessment_id || body.report_id || '';
  if (!assessmentId) {
    test.skip();
    return;
  }
  // seed localStorage and open UI
  await page.goto('http://localhost:8080/static/investigate.html');
  await page.evaluate((aid) => { localStorage.setItem('apiKey','devkey123'); localStorage.setItem('last_investigation_assessment', aid); }, assessmentId);
  await page.fill('#assessmentInput', assessmentId);
  await page.click('#btnBuild');
  // wait up to 10s for status to become ready
  await page.waitForFunction(() => document.querySelector('#buildStatus').textContent.toLowerCase().indexOf('ready')!==-1, { timeout: 10000 });
  // verify narrative present
  const narrative = await page.textContent('#narrativeBlock');
  expect(narrative).toBeTruthy();
  // request verification
  await page.click('#btnVerify');
  await page.waitForSelector('#verificationSection', { timeout: 5000 });
  const md = await page.textContent('#verificationMarkdown');
  expect(md).toContain('LLM Verification Report');
});
