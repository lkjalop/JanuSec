const { test, expect } = require('@playwright/test');

test('telemetry enqueues and collector receives payload', async ({ page, request }) => {
  await page.goto('http://localhost:8080/');
  await page.waitForLoadState('networkidle');

  // ensure telemetry helper loaded; inject if missing
  const needInject = await page.evaluate(() => !window.__janusec_telemetry);
  if(needInject){
    await page.addScriptTag({ path: 'frontend/static/js/telemetry.js' });
    // allow telemetry.js to initialize
    await page.waitForFunction(() => !!(window.__janusec_telemetry && window.__janusec_telemetry.enqueue), { timeout: 2000 });
  }

  // enqueue events in the page
  await page.evaluate(() => {
    window.__janusec_telemetry.enqueue({type:'e2e_test', message:'hello_playwright'});
  });

  // try to flush immediately
  await page.evaluate(() => window.__janusec_telemetry.flushNow && window.__janusec_telemetry.flushNow());

  // Poll collector GET endpoint for the latest payload using browser fetch (CORS enabled on collector)
  const url = 'http://127.0.0.1:5001/telemetry/latest';
  let ok = false;
  for(let i=0;i<15;i++){
    const body = await page.evaluate(async (u) => {
      try{
        const r = await fetch(u, { method: 'GET', credentials: 'omit' });
        if(!r.ok) return null;
        return await r.text();
      }catch(e){ return null; }
    }, url);
    if(body && body.includes('hello_playwright')){ ok = true; break; }
    await new Promise(r=>setTimeout(r,300));
  }
  expect(ok).toBe(true);
});
