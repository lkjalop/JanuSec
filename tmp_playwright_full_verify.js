const { chromium } = require('playwright');
const fs = require('fs');

(async ()=>{
  const base = process.env.BASE_URL || 'http://localhost:8080';
  const assessmentId = process.env.ASSESSMENT_ID;
  const apiKey = process.env.API_KEY || 'devkey123';
  if(!assessmentId){ console.error('Missing ASSESSMENT_ID env var'); process.exit(2); }

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  const capturedPosts = [];
  page.on('request', req => {
    try{
      if(req.method().toUpperCase()==='POST' && (req.url().includes('/api/v1/incidents') || req.url().includes('/api/v1/sbom/upload'))){
        capturedPosts.push({ url: req.url(), method: req.method(), postData: req.postData() });
      }
    }catch(_){ }
  });
  page.on('console', msg => { if(msg.type()==='error') console.error('PAGE_CONSOLE_ERROR:', msg.text()); });
  page.on('pageerror', err => { console.error('PAGE_ERROR:', err && err.stack || err); });

  try{
    console.log('Opening CSV analyzer UI...');
    await page.goto(base + '/static/csv_analyzer.html', { waitUntil: 'load', timeout: 30000 });

    // Create tmp csv and upload to populate the table first
    const tmpFile = 'tmp_playwright_upload.csv';
    const csv = 'process_name,file_path,sha256,host,verdict\npowershell,C:\\Windows\\System32\\cmd.exe,deadbeef,host1,SUSPICIOUS\nnotepad,C:\\Temp\\bad.exe,cafebabecafe,host2,BENIGN\n';
    require('fs').writeFileSync(tmpFile, csv, 'utf8');
    const input = await page.$('input#fileInput');
    if(!input){ console.error('File input not found'); await browser.close(); process.exit(2); }
    await input.setInputFiles(tmpFile);
    console.log('Uploaded CSV to page, waiting for rows...');
    await page.waitForSelector('#tbody tr[data-row]', { timeout: 20000 });
    console.log('Data rows present, now fetching assessment rows and injecting into page render...');

    // Inject assessment rows from backend into page and render
    await page.evaluate(async (params) => {
      try{
        const r = await fetch('/api/v1/assessments/'+encodeURIComponent(params.id)+'/rows', { headers: { 'x-api-key': params.key } });
        const j = await r.json();
        // try a few hooks the page exposes
        if(typeof window.renderLLMRowCards === 'function'){
          window.renderLLMRowCards(j.llm_rows || j.rows || []);
        }
        try{ if(typeof window.mergeAssessmentRowsIntoResults === 'function') window.mergeAssessmentRowsIntoResults(j); }catch(_){ }
        try{ if(typeof window.renderTableFromResults === 'function') window.renderTableFromResults(); }catch(_){ }
        return true;
      }catch(e){ console.error('inject error', e); return false; }
    }, { id: assessmentId, key: apiKey });

    // Use page.evaluate to call the global helper to open details reliably
    await page.evaluate(() => { try{ if(typeof window.openCsvRowDetails === 'function') window.openCsvRowDetails(0); }catch(_){ } });

    await page.waitForSelector('tr.csv-inline-details, tr.inline-details, div.csv-inline-details', { timeout: 15000 });
    console.log('Inline details visible');

    // Attempt clicks on known loop-closure button labels with retry
    const buttonLabels = ['Push Incident','Publish SBOM','Push SBOM','SBOM Delta','Create Incident','Push Incident to SIEM','Export SBOM'];
    for(const label of buttonLabels){
      try{
        // try to find a button inside the inline details
        const btn = await page.locator(`tr.csv-inline-details button:has-text("${label}")`).first();
        if(await btn.count() > 0){
          try{
            await btn.waitFor({ state: 'visible', timeout: 3000 });
            await btn.click({ timeout: 5000 });
            console.log('Clicked button:', label);
            await page.waitForTimeout(1200);
            continue;
          }catch(clickErr){
            console.warn('Click failed for', label, clickErr.message||clickErr);
          }
        }
        // fallback: try broader scope
        const btn2 = await page.locator(`button:has-text("${label}")`).first();
        if(await btn2.count() > 0){
          try{ await btn2.waitFor({ state: 'visible', timeout: 3000 }); await btn2.click({ timeout: 5000 }); console.log('Clicked fallback button:', label); await page.waitForTimeout(1200); }
          catch(e){ console.warn('Fallback click failed for', label); }
        }
      }catch(_){ }
    }

    // Wait briefly for outgoing POSTs to be captured
    await page.waitForTimeout(1200);

    console.log('Captured POSTs count:', capturedPosts.length);
    capturedPosts.forEach((p,i)=>{
      console.log('POST['+i+']', p.url);
      try{ console.log('Payload:', p.postData ? p.postData.substring(0,2000) : '<none>'); }catch(_){ }
    });

    // If none captured, try clicking any generic loop-closure buttons inside inline area
    if(capturedPosts.length===0){
      const genericBtns = await page.locator('tr.csv-inline-details button, tr.inline-details button, div.csv-inline-details button').all();
      for(const btnHandle of genericBtns){
        try{
          const txt = (await btnHandle.innerText()).trim().slice(0,64);
          if(/incident|sbom|sbom|push|publish/i.test(txt)){
            try{ await btnHandle.click(); console.log('Clicked generic inline button:', txt); await page.waitForTimeout(800); }catch(_){ }
          }
        }catch(_){ }
      }
      await page.waitForTimeout(1000);
    }

    console.log('Done; closing browser');
    await browser.close();
    process.exit(0);

  }catch(err){ console.error('Script error', err && err.stack || err); await browser.close(); process.exit(1); }
})();
