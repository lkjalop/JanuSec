const { chromium } = require('playwright');
(async()=>{
  const browser = await chromium.launch();
  const page = await browser.newPage();
  page.on('console', msg => console.log('PAGE LOG:', msg.type(), msg.text()));
  page.on('pageerror', err => console.log('PAGE ERROR:', err));
  page.on('requestfailed', r=> console.log('REQ FAIL:', r.url(), r.failure && r.failure.errorText));
  page.on('request', r=> console.log('REQ:', r.method(), r.url()));
  page.on('response', async r=>{ try{ if(r.request().resourceType()==='xhr' || /api\//.test(r.url())){ console.log('RESP', r.status(), r.url()); const t = await r.text(); console.log('RESP BODY SNIPPET:', t.slice(0,400)); } }catch(e){} });
  await page.goto('http://localhost:8080/static/csv_analyzer.html', { waitUntil: 'domcontentloaded' });
  await page.evaluate(()=>{ try{ localStorage.removeItem('csv_last_results'); localStorage.removeItem('csv_last_results_ts'); }catch(_){ } });
  // set file input
  const filePath = 'dump/Cyberstash_csv2.xlsx';
  const [fileChooser] = await Promise.all([
    page.waitForEvent('filechooser'),
    page.click('#btnLoad')
  ]);
  await fileChooser.setFiles(filePath);
  // wait for results
  await page.waitForSelector('#csv_results_ready[data-ready="1"]', { timeout: 10000 });
  console.log('results ready');
  // click details on first row
  await page.click('#tbody tr[data-row] button[title="Why flagged / details"]');
  await page.waitForSelector('tr.csv-inline-details', { timeout: 5000 });
  console.log('inline details inserted');
  // click LLM T1 button inside inline details
  await page.click('tr.csv-inline-details button:has-text("LLM T1")');
  // wait a bit to capture network
  await page.waitForTimeout(3000);
  await browser.close();
})();