const { chromium } = require('playwright');
(async()=>{
  const browser = await chromium.launch();
  const page = await browser.newPage();
  page.on('console', msg => console.log('PAGE LOG:', msg.type(), msg.text()));
  page.on('pageerror', err => console.log('PAGE ERROR:', err));
  page.on('requestfailed', r=> console.log('REQ FAIL:', r.url(), r.failure && r.failure.errorText));
  page.on('request', r=> console.log('REQ:', r.method(), r.url()));
  page.on('response', async r=>{ try{ if(/api\//.test(r.url())){ console.log('RESP', r.status(), r.url()); const t = await r.text(); console.log('RESP BODY (truncated):', t.slice(0,600)); } }catch(e){} });

  await page.goto('http://localhost:8080/static/csv_analyzer.html', { waitUntil: 'domcontentloaded' });
  // clear persisted results to force load
  await page.evaluate(()=>{ try{ localStorage.removeItem('csv_last_results'); localStorage.removeItem('csv_last_results_ts'); }catch(_){ } });
  // set file input directly
  const filePath = 'dump/Cyberstash_csv2.xlsx';
  try{
    await page.setInputFiles('#fileInput', filePath);
  }catch(e){ console.log('SET FILE ERROR', e.message); }
  // click load button
  await page.click('#btnLoad');
  // wait for results ready
  await page.waitForSelector('#csv_results_ready[data-ready="1"]', { timeout: 15000 });
  console.log('RESULTS READY VISIBLE');

  // Test filter buttons
  const btns = ['#btnFilterAll','#btnFilterSuspicious','#btnFilterPassed'];
  for(const id of btns){
    await page.click(id);
    // small delay
    await page.waitForTimeout(400);
    const active = await page.$eval(id, el => el.classList.contains('btn-primary'));
    console.log('BUTTON', id, 'active?', active);
  }

  // Open details for first visible row
  await page.click('#tbody tr[data-row] button[title="Why flagged / details"]');
  await page.waitForSelector('tr.csv-inline-details', { timeout: 5000 });
  console.log('INLINE DETAILS INSERTED');

  // Click LLM T1 inside inline details
  // find the button by text inside inline details
  const t1 = await page.$('tr.csv-inline-details button:has-text("LLM T1")');
  if(t1){
    await t1.click();
    console.log('Clicked LLM T1');
    // wait a short while for network
    await page.waitForTimeout(3000);
  } else {
    console.log('LLM T1 button not found');
  }

  // check that an insights/generate request was made (inspect recent responses logged above)
  console.log('Finished interactions');
  await browser.close();
})();