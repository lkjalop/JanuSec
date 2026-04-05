const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
(async ()=>{
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  page.on('console', msg => console.log('PAGE LOG:', msg.type(), msg.text()));
  page.on('pageerror', err => { console.log('PAGE ERROR:', err.message); try{ if(err.stack) console.log('PAGE ERROR STACK:', err.stack); }catch(_){ } });
  const base = 'http://127.0.0.1:8080';
  const url = base + '/static/csv_analyzer.html';
  console.log('Opening', url);
  // Install an in-page global error collector before navigation completes
  await page.addInitScript(()=>{
    window._capturedErrors = window._capturedErrors || [];
    window.addEventListener('error', (ev)=>{
      try{ window._capturedErrors.push({ message: ev.message, filename: ev.filename, lineno: ev.lineno, colno: ev.colno, error: ev.error && (ev.error.stack||ev.error.message) }); }catch(_){ }
    });
    window.addEventListener('unhandledrejection', (ev)=>{ try{ window._capturedErrors.push({ type:'unhandledrejection', reason: String(ev.reason) }); }catch(_){ } });
  });
  await page.goto(url, { waitUntil: 'load' });
  const fixture = path.resolve(__dirname, '..', 'tests', 'playwright', 'fixtures', 'test_row.csv');
  const txt = fs.readFileSync(fixture, 'utf8');
  // Ensure parseCsv is available
  const exists = await page.evaluate(() => typeof window.parseCsv === 'function');
  console.log('parseCsv defined on page:', exists);
  if(!exists){ console.log('Waiting 500ms for scripts to load...'); await page.waitForTimeout(500); }

  // Inspect loaded scripts and run a syntax check (new Function) on each script's text
  const scripts = await page.evaluate(async ()=>{
    const out = [];
    for(const s of Array.from(document.scripts)){
      try{
        const src = s.src||'(inline)';
        let text = '';
        if(s.src){
          try{ const r = await fetch(s.src); if(r && r.ok) text = await r.text(); else text = '[fetch_failed]'; }
          catch(_){ text = '[fetch_failed]'; }
        } else {
          text = s.textContent || '';
        }
        // Attempt to detect syntax errors by using the Function constructor
        let syntaxError = null;
        try{ new Function(text); }catch(e){ syntaxError = String(e.message||e); }
        out.push({ src, len: text.length, head: text.slice(0,200).replace(/\n/g,'\\n'), syntaxError });
      }catch(e){ out.push({ src: s.src||'(inline)', error: String(e) }); }
    }
    return out;
  });
  console.log('Loaded scripts (syntax check):');
  scripts.forEach(s=> console.log('- ', s.src, 'len=', s.len || '?', 'syntaxError=', s.syntaxError || '(ok)', 'head=', s.head ? s.head.slice(0,200) : s.error));

  const captured = await page.evaluate(()=> window._capturedErrors || []);
  console.log('Captured in-page errors:', JSON.stringify(captured, null, 2));

  const rows = await page.evaluate((t)=>{
    try{ return (window.parseCsv ? window.parseCsv(t) : null); }catch(e){ return { error: String(e) }; }
  }, txt);
  console.log('parseCsv result:', JSON.stringify(rows, null, 2));
  await browser.close();
})();
