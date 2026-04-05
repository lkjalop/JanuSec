const { chromium } = require('playwright');
const path = require('path');
(async ()=>{
  const browser = await chromium.launch();
  const page = await browser.newPage();
  page.on('console', msg => {
    try{ console.log('PAGE LOG:', msg.type(), msg.text(), msg.location()); }catch(_){ console.log('PAGE LOG', msg.type(), msg.text()); }
  });
  page.on('pageerror', err => { try{ console.log('PAGE ERROR stack:', err.stack || String(err)); }catch(_){ console.log('PAGE ERROR:', String(err)); } });
  page.on('requestfailed', req => { try{ console.log('REQUEST FAILED', req.url(), req.failure() && req.failure().errorText); }catch(_){ } });
  try{
    const filePath = path.resolve(__dirname, 'dump', 'Cyberstash_csv2.xlsx');
    console.log('Using file:', filePath);
    // Clear localStorage to avoid JSON.parse errors from stale/corrupt data
    // Install early error hooks before any script runs
    await page.addInitScript(() => {
      try{
        window.__early_errors = window.__early_errors || [];
        window.addEventListener('error', function(e){ try{ window.__early_errors.push({ type: 'error', message: e && e.message, filename: e && e.filename, lineno: e && e.lineno, colno: e && e.colno, error: (e && e.error && e.error.stack) || null }); }catch(_){ } });
        window.addEventListener('unhandledrejection', function(ev){ try{ window.__early_errors.push({ type: 'unhandledrejection', reason: (ev && ev.reason && (ev.reason.stack||ev.reason.message)) || String(ev && ev.reason) }); }catch(_){ } });
      }catch(_){ }
    });
    await page.goto('about:blank');
    await page.evaluate(()=>{ try{ localStorage.clear(); sessionStorage.clear(); }catch(_){} });
    await page.goto('http://localhost:8080/static/csv_analyzer.html', { waitUntil: 'domcontentloaded', timeout: 10000 });
    // list scripts on the page
    const scripts = await page.evaluate(()=> Array.from(document.scripts).map(s=>({ src: s.src||null, inlineLen: s.src? null : (s.textContent||'').length })));
    console.log('PAGE SCRIPTS:', scripts);
    // Attempt to fetch and parse each external script in browser context to locate syntax errors
    try{
      const results = await page.evaluate(async ()=>{
        const out = [];
        for(const s of Array.from(document.scripts)){
          if(!s.src){ out.push({ src: null, inline: true }); continue; }
          try{
            const resp = await fetch(s.src);
            const txt = await resp.text();
            try{ new Function(txt); out.push({ src: s.src, ok: true }); }catch(e){ out.push({ src: s.src, ok: false, msg: e && e.message, tail: txt.slice(-300) }); }
          }catch(fe){ out.push({ src: s.src, ok: false, msg: 'fetch_failed', detail: (fe && fe.message) }); }
        }
        return out;
      });
      console.log('external script parse results:', results);
    }catch(e){ console.log('external script parse check failed', e && e.stack); }
    // Print any early errors captured before or during load
    try{
      const early = await page.evaluate(()=> window.__early_errors || []);
      console.log('EARLY ERRORS:', JSON.stringify(early, null, 2));
    }catch(e){ console.log('failed to read early errors', e && e.stack); }
    // inject clientSideAggregate shim
    await page.evaluate(()=>{
      try{
        window.parseTabular = window.parseTabular || {};
        window.parseTabular.clientSideAggregate = window.parseTabular.clientSideAggregate || (async function(files){
          const f = files[0]; const text = await f.text(); const lines = text.split(/\r?\n/).filter(Boolean); const headers = (lines[0]||'').split(/[,;\t]/).map(h=>h.trim()); const rows = []; for(let i=1;i<lines.length;i++){ const cols = lines[i].split(','); const obj={}; headers.forEach((h,idx)=> obj[h]= (cols[idx]||'').replace(/^\"|\"$/g,'')); rows.push(obj);} return { rows };
        });
      }catch(e){ console.log('shim error', e); }
    });
    const fileInput = await page.$('input[type=file]#fileInput');
    if(!fileInput){ console.log('file input not found'); await browser.close(); return; }
    await fileInput.setInputFiles(filePath);
    console.log('file set');
    await page.click('#btnLoad');
    console.log('clicked load');
    // wait for csv_results_ready
    try{
      await page.waitForSelector('#csv_results_ready', { state: 'visible', timeout: 20000 });
      console.log('csv_results_ready visible');
    }catch(e){ console.log('csv_results_ready not visible after wait:', e.message); }
    const inner = await page.$eval('#csv_results_ready', el=>el.outerHTML);
    console.log('csv_results_ready outerHTML:', inner);
    const tbodyHtml = await page.$eval('#tbody', el=>el.innerHTML);
    console.log('tbody innerHTML length', tbodyHtml.length);
    console.log('tbody innerHTML excerpt:\n', tbodyHtml.slice(0,1000));
  }catch(e){ console.log('Script error', e); }
  await browser.close();
})();