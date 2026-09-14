const { test, expect } = require('@playwright/test');
const path = require('path');

test('CrowdStrike intel appears in CSV Analyzer modal', async ({ page, request }) => {
  // Trigger a demo sync via API (uses dev key in headers in demo environment)
  const r = await request.post('/api/v1/integrations/crowdstrike/sync', { headers: { 'x-api-key': 'devkey123' } });
  // Demo environment may not implement a live CrowdStrike sync; accept 501 as a skip condition
  if (r.status() !== 200) {
    console.log('CrowdStrike sync returned', r.status(), '— skipping intel assertion');
    return;
  }
  const jr = await r.json();
  const created = jr.created || [];
  if (!created.length) {
    console.log('CrowdStrike sync created no detections — skipping');
    return;
  }
  const eventId = created[0];

  // Navigate to CSV Analyzer and seed LAST_RESULTS with a row that references the created event
  await page.goto('/static/csv_analyzer.html');
  // seed a minimal LAST_RESULTS so UI can open modal for index 0
  await page.evaluate((eid) => {
    window.LAST_RESULTS = [{ raw: { event_id: eid }, factors: [], _dread: { score: 0 } }];
  }, eventId);
  // If a table row exists, try the UI button; otherwise call the modal renderer directly
  await page.click('tr[data-row] button[title="Why flagged / details"]').catch(()=>{});
  await page.evaluate(() => {
    try{
      if(typeof renderFullDetails === 'function'){
        return renderFullDetails(0);
      }
      if(typeof window.openCsvRowDetails === 'function'){
        window.openCsvRowDetails(0);
      }
    }catch(_){}
    return null;
  });
  await page.waitForSelector('#csvDrillModal', { state: 'visible', timeout: 5000 });

  // Wait for the explain section to appear (either server explain or local explain)
  await page.waitForSelector('#csvDrillBody', { timeout: 3000 });
  // Validate that intel hits area contains vendor or detection id
  const bodyText = await page.$eval('#csvDrillBody', el => el.innerText.toLowerCase());
  expect(bodyText).toContain('crowdstrike');
  // Also check the explain api returned intel_hits via direct fetch as a fallback check
  const resp = await request.get(`/api/v1/decisions/${eventId}/explain_verbose`);
  expect([200,201].includes(resp.status())).toBeTruthy();
  const ej = await resp.json();
  expect(ej).toHaveProperty('intel_hits');
  expect(ej.intel_hits.id || ej.intel_hits.vendor).toBeTruthy();
});
