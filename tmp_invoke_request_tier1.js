const { chromium } = require('playwright');
(async()=>{
  const browser = await chromium.launch();
  const page = await browser.newPage();
  page.on('console', msg => console.log('PAGE LOG:', msg.type(), msg.text()));
  page.on('pageerror', err => console.log('PAGE ERROR:', err));
  page.on('request', r=> console.log('REQ:', r.method(), r.url()));
  page.on('response', async r=>{ try{ if(/insights\/generate/.test(r.url())){ console.log('RESP', r.status(), r.url()); const t = await r.text(); console.log('RESP BODY:', t.slice(0,1000)); } }catch(e){} });

  await page.goto('http://localhost:8080/static/csv_analyzer.html', { waitUntil: 'domcontentloaded' });
  await page.evaluate(()=>{ try{ localStorage.removeItem('csv_last_results'); localStorage.removeItem('csv_last_results_ts'); }catch(_){ } });
  // set file so rows exist
  await page.setInputFiles('#fileInput', 'dump/Cyberstash_csv2.xlsx');
  await page.click('#btnLoad');
  await page.waitForSelector('#csv_results_ready[data-ready="1"]', { timeout: 15000 });
  console.log('rows ready');
  // call requestTier1Summary for first row
  await page.evaluate(()=>{ try{ if(typeof requestTier1Summary==='function'){ requestTier1Summary(0); } else { console.log('requestTier1Summary not found'); } }catch(e){ console.log('invoke error', e); } });
  // wait for network
  await page.waitForTimeout(3000);
  await browser.close();
})();