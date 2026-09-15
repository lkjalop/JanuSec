const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  try {
    await page.goto('http://localhost:8080/static/csv_analyzer.html', { timeout: 10000 });
    // seed LAST_RESULTS
    const rows = [{ process_name: 'rundll32', file_path: '/windows/system32/rundll32.exe', sha256: 'deadbeef', host: 'host1', verdict: 'SUSPICIOUS', factors: ['lolbin'], raw: { event_id: 'evt-1' } }];
    await page.evaluate((r) => { localStorage.setItem('csv_last_results', JSON.stringify(r)); localStorage.setItem('csv_last_results_ts', String(Date.now()/1000)); }, rows);
    await page.reload();
    await page.waitForTimeout(500);
    const hasInitiate = await page.evaluate(() => typeof window.initiateDeepAnalyze === 'function');
    console.log('hasInitiate:', hasInitiate);
    if(hasInitiate){
      await page.evaluate(() => { try{ window.initiateDeepAnalyze({ auto_llm: true, max_rows: 10 }); }catch(e){ console.error('initErr', e && e.message); } });
      await page.waitForTimeout(1000);
      const state = await page.evaluate(() => ({ currentAssessmentId: window.currentAssessmentId||null, LAST_DEEP_ANALYZE: window.LAST_DEEP_ANALYZE||null, LAST_CORR_SUMMARY: window.LAST_CORR_SUMMARY||null }));
      console.log('state:', state);
    }
  }catch(e){ console.error('script error', e && e.message); }
  await browser.close();
})();
