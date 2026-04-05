const { chromium } = require('playwright');
const fs = require('fs');
const { initScript } = require('./playwright_setup');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ recordVideo: { dir: 'test-results/videos', size: { width: 1280, height: 720 } } });
  const page = await context.newPage();
  page.on('console', msg => {
    try { console.log('[PAGE]', msg.type(), msg.text()); } catch(e) {}
  });
  page.on('response', resp => {
    try { console.log('[RESP]', resp.status(), resp.url()); } catch(e) {}
  });
  try {
    await page.addInitScript(initScript);
    await page.goto('http://localhost:8080/static/csv_multi_analyzer.html', { waitUntil: 'load', timeout: 30000 });
    // dump HTML for inspection
    const html = await page.content();
    require('fs').writeFileSync('test-results/html_dump.csv_multi_analyzer.html', html);
    console.log('Wrote test-results/html_dump.csv_multi_analyzer.html');
    // Trigger page-level test init if present and give shims time
    try{ await page.evaluate(() => { if(window.__csvMultiTestInit) try{ window.__csvMultiTestInit(); }catch(_){ } }); }catch(_){ }
    await page.waitForTimeout(400);

    // Start tracing early to capture the modal open flow
    await page.context().tracing.start({ screenshots: true, snapshots: true });

    // Try multiple strategies to open the mapping modal deterministically
    let opened = false;
    try{
      // 1) call offerMappingModalOnUploadConfirm if available
      const offerResult = await page.evaluate(() => {
        try{
          if(typeof window.offerMappingModalOnUploadConfirm === 'function'){
            window.offerMappingModalOnUploadConfirm([], null);
            return 'offered';
          }
        }catch(_){ }
        return null;
      });
      if(offerResult === 'offered') opened = true;
    }catch(_){ }

    // 2) attempt to click legacy or modern button if present
    try{
      const btn = await page.$('#btnSavePreset');
      if(btn){ await page.$eval('#btnSavePreset', el => { try{ el.click(); }catch(e){} }); opened = true; }
    }catch(_){ }
    try{
      if(!opened){ const f = await page.$('#btnFinalizeMapping'); if(f){ await page.$eval('#btnFinalizeMapping', el=>{ try{ el.click(); }catch(_){ } }); opened = true; } }
    }catch(_){ }

    // 3) direct DOM fallback: show modern modal and trigger preview button
    try{
      if(!opened){
        await page.evaluate(() => {
          try{
            const modern = document.getElementById('mappingSaveModal');
            const backdrop = document.getElementById('modalBackdrop');
            if(modern){ modern.style.display = 'block'; if(backdrop) backdrop.style.display='block'; const prev = modern.querySelector('#modalPreview'); if(prev) try{ prev.click(); }catch(_){ } }
            return true;
          }catch(_){ return false; }
        });
        opened = true;
      }
    }catch(_){ }

    // Wait for mapping modal to be visible
    try{
      await page.waitForSelector('#mappingSaveModal', { state: 'visible', timeout: 20000 });
      console.log('Mapping modal visible');
    }catch(err){ console.warn('Mapping modal did not become visible:', err && err.message); }

    // Give UI a moment then stop trace
    await page.waitForTimeout(1200);
    await page.context().tracing.stop({ path: 'test-results/traces/mapping_modal_trace.zip' }).catch(()=>{});
    console.log('Trace saved to test-results/traces/mapping_modal_trace.zip');
  } catch (e) {
    console.error('Error during debug run:', e);
    try { await page.screenshot({ path: 'test-results/screenshots/mapping_modal_error.png', fullPage: true }); console.log('Saved screenshot'); } catch(err){}
  } finally {
    await context.close();
    await browser.close();
  }
})();
