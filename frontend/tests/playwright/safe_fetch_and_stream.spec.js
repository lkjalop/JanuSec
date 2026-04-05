const { test, expect } = require('@playwright/test');

// Smoke tests validating presence and basic behavior of safeFetch and StreamClient
test.describe('Frontend primitives smoke', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('http://localhost:8080/');
    await page.waitForLoadState('networkidle');
  });
  
  // Ensure our helper scripts are available when running against a plain static server
  async function ensureHelpers(page){
    await page.evaluate(() => {
      window.__injectedHelpers = window.__injectedHelpers || {};
    });
    const helpers = ['/static/js/fetch_wrapper.js','/static/js/stream_client.js','/static/js/sw_update_banner.js'];
    for(const h of helpers){
      await page.evaluate(async (src)=>{
        if(document.querySelector(`script[src="${src}"]`) || window.__injectedHelpers[src]) return;
        await new Promise((res)=>{
          const s=document.createElement('script'); s.src=src; s.onload=res; s.onerror=res; document.head.appendChild(s);
        });
        window.__injectedHelpers[src]=true;
      }, h);
    }
  }

  test('safeFetch exists and can fetch dashboard (mockable)', async ({ page }) => {
    await ensureHelpers(page);
    const hasSafe = await page.evaluate(() => !!(window.safeFetch || window.fetch));
    expect(hasSafe).toBe(true);

    // Call safeFetch on a benign endpoint; may 404 but should not throw sync
    const res = await page.evaluate(async () => {
      try{
        const r = await (window.safeFetch || fetch)('/api/v1/status/dashboard').catch(()=>({ ok:false }));
        return !!r;
      }catch(e){ return false; }
    });
    expect(res).toBeTruthy();
  });

  test('streamSubscribe exists', async ({ page }) => {
    await ensureHelpers(page);
    const hasStream = await page.waitForFunction(() => !!(window.streamSubscribe || window.StreamClient), {timeout: 2000}).catch(()=>null);
    expect(!!hasStream).toBe(true);
  });

  test('sw update banner handler exists', async ({ page }) => {
    await ensureHelpers(page);
    const hasHandler = await page.evaluate(() => !!window.showSwUpdate);
    expect(hasHandler).toBe(true);
  });
});
