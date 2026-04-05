const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

(async ()=>{
  const base = process.env.BASE_URL || 'http://localhost:8080';
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();
  const errors = [];
  const badResponses = [];
  page.on('console', msg => { if(msg.type() === 'error') { console.error('PAGE_CONSOLE_ERROR:', msg.text()); errors.push(msg.text()); } });
  page.on('pageerror', err => { console.error('PAGE_ERROR:', err.stack||err); errors.push(String(err)); });
  page.on('requestfailed', req => { console.error('REQUEST_FAILED:', req.url(), req.failure && req.failure().errorText); badResponses.push({ url: req.url(), failure: req.failure() }); });
  page.on('response', async resp => { try{ if(!resp.ok()){ const url = resp.url(); const status = resp.status(); const text = await resp.text().catch(()=>'<no body>'); console.warn('RESPONSE_NOT_OK', status, url, text.slice(0,300)); badResponses.push({ url, status, text: text.slice(0,1000) }); } }catch(_){ } });

  try{
    console.log('goto', base + '/static/csv_analyzer.html');
    await page.goto(base + '/static/csv_analyzer.html', { waitUntil: 'load', timeout: 30000 });

    // create tmp csv
    const tmpFile = path.join(process.cwd(), 'tmp_playwright_upload.csv');
    const csv = 'process_name,file_path,sha256,host,verdict\npowershell,C:\\\\Windows\\\\System32\\\\cmd.exe,deadbeef,host1,SUSPICIOUS\nnotepad,C:\\\\Temp\\\\bad.exe,cafebabecafe,host2,BENIGN\n';
    fs.writeFileSync(tmpFile, csv, 'utf8');

    const input = await page.$('input#fileInput');
    if(!input){ console.error('File input not found'); process.exit(1); }
    await input.setInputFiles(tmpFile);
    console.log('file set');

    // click load
    const loadBtn = await page.$('#btnLoad');
    if(!loadBtn){ console.error('Load button not found'); }
    else{ await loadBtn.click(); console.log('clicked load'); }

    // wait for rows
    await page.waitForSelector('#tbody tr[data-row]', { timeout: 15000 });
    console.log('rows present');

    // click first row
    const firstRow = await page.$('#tbody tr[data-row]');
    const rowHtmlBefore = await firstRow.evaluate(el=>el.outerHTML).catch(()=>'<no row html>');
    console.log('row HTML before click:', rowHtmlBefore);
    await firstRow.click();
    console.log('clicked row');

    // wait longer and capture DOM around the row
    try{
      await page.waitForSelector('tr.csv-inline-details', { timeout: 15000 });
      console.log('inline details shown');
    }catch(_){
      console.warn('inline details not found under expected selector');
    }

    // Capture DOM fragment after click to inspect structure
    const tbodyHtml = await page.$eval('#tbody', el=>el.innerHTML).catch(()=>'<no tbody html>');
    console.log('TBODY fragment (first 1200 chars):', String(tbodyHtml).slice(0,1200));

    // Also check for common alternative classes/structures
    const altSelectors = [
      'tr.inline-details',
      'tr.details-row',
      'tr[data-inline-details]',
      'div.csv-inline-details',
      'div.inline-details',
      '#inline-details',
    ];
    for(const sel of altSelectors){
      const exists = await page.$(sel);
      console.log('selector check', sel, !!exists);
    }

    // click inline buttons if present
    const btnSelectors = ['button:has-text("LLM T1")', 'button:has-text("Per-row Deep Explain")', 'button:has-text("View Attack Path")', 'button:has-text("Fetch Explain")'];
    for(const sel of btnSelectors){
      // try primary location
      let btn = await page.$('tr.csv-inline-details ' + sel).catch(()=>null);
      if(!btn){
        // try alternatives near the clicked row
        btn = await firstRow.$(':scope + tr ' + sel).catch(()=>null) || await firstRow.$(':scope ~ tr ' + sel).catch(()=>null);
      }
      if(btn){
        console.log('clicking', sel);
        await btn.click().catch(e=>console.warn('click failed', e));
        await page.waitForTimeout(400);
      } else { console.log('button not found:', sel); }
    }

    console.log('done interactions');

  }catch(err){ console.error('script error', err.stack||err); }
  finally{
    console.log('errors captured:', errors.length);
    errors.forEach((e,i)=> console.log('ERR['+i+']', e));
    console.log('badResponses:', badResponses.length);
    badResponses.forEach((r,i)=> console.log('BAD['+i+']', r.url, r.status||'', r.failure? r.failure.errorText : ''));
    await browser.close();
    process.exit(0);
  }
})();
