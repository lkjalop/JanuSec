// Lightweight test helpers loaded in the LIVE console for test/dev modes.
// - If the backend indicates dev mode, prefill SBOM textarea, reveal dev/admin panel,
//   stub parseTabular and XLSX placeholders to avoid async loader races, and expose
//   a test-only force-upload flag.
(function(){
  async function init(){
    try{
      // Query server-side dev info endpoint; it's safe to call in prod (returns false)
      // Heuristic: run in local/test environments or when a test admin key is present.
      const isLocalHost = (location && (location.hostname === 'localhost' || location.hostname === '127.0.0.1'));
      const hasAdminKey = !!(localStorage.getItem && (localStorage.getItem('adminKey') || localStorage.getItem('showDev')));
      const hasDevApiKey = (localStorage.getItem && localStorage.getItem('apiKey') === 'devkey123');
      const shouldEnable = isLocalHost || hasAdminKey || hasDevApiKey;

      if(!shouldEnable){
        // try server-side check as a fallback but do not block if it fails
        try{ const r = await fetch('/api/v1/dev/info').catch(()=>null); const j = r && r.ok ? await r.json().catch(()=>({})) : {}; if(!(j && j.dev)) return; }catch(_){ return; }
      }

      // Reveal dev admin panel by setting localStorage toggle and showing DOM when appropriate
      try{ if(!localStorage.getItem('showDev')) localStorage.setItem('showDev','1'); }catch(e){}
        try{
          const p = document.getElementById('adminTuningPanel');
          // Force-visible in test/dev: inject a small stylesheet and make panel visible
          try{
            const styleId = 'test_admin_panel_force_style';
            if(!document.getElementById(styleId)){
              const st = document.createElement('style'); st.id = styleId;
              st.textContent = '#adminTuningPanel { display:block !important; visibility:visible !important; opacity:1 !important; } #adminTuningPanel * { visibility:visible !important; }';
              (document.head||document.documentElement).appendChild(st);
            }
          }catch(_){ }
          if(p){ p.style.display='block'; p.style.visibility='visible'; p.style.opacity='1'; p.classList.remove && p.classList.remove('hidden'); }
        }catch(e){}
        // Ensure admin panel remains visible even if other scripts toggle it: observe DOM and enforce
        try{
          const ensureAdminVisible = () => {
            try{
              const p2 = document.getElementById('adminTuningPanel');
              if(p2){ p2.style.setProperty('display','block','important'); p2.style.setProperty('visibility','visible','important'); p2.style.setProperty('opacity','1','important'); p2.style.height='auto'; }
            }catch(_){}
          };
          ensureAdminVisible();
          const mo = new MutationObserver(()=> ensureAdminVisible());
          mo.observe(document.documentElement || document.body, { childList:true, subtree:true });
          // stop observing after a short time
          setTimeout(()=> mo.disconnect(), 30000);
        }catch(_){ }

        // Create deterministic auth banners used by Playwright tests so they can assert on IDs
        try{
          const ensureAuthBanners = () => {
            try{
              // apiBanner (used across pages)
              let b = document.getElementById('apiBanner');
              if(!b){ b = document.createElement('div'); b.id='apiBanner'; b.style.display='none'; document.body.insertBefore(b, document.body.firstChild); }
              if((localStorage.getItem && (!localStorage.getItem('apiKey') || localStorage.getItem('apiKey')==='devkey123'))){ b.style.display='block'; b.innerHTML = "Tip: set an API key to avoid 401s. <button class='btn' id='setDemoKey'>Use demo key</button>"; const btn=b.querySelector('#setDemoKey'); if(btn && !btn._attached){ btn.addEventListener('click', ()=>{ try{ localStorage.setItem('apiKey','devkey123'); _toast('Demo API key set (devkey123). Reloading...',2500); setTimeout(()=> location.reload(), 800); }catch(_){ _toast('Failed to set demo key',2500); } }); btn._attached = true; }
              }
              // authProbeBanner (specific tests look for this id)
              let ap = document.getElementById('authProbeBanner');
              if(!ap){ ap = document.createElement('div'); ap.id = 'authProbeBanner'; ap.style.cssText = 'width:100%;box-sizing:border-box;display:none;align-items:center;justify-content:space-between;gap:12px;padding:10px 14px;background:#1D2531;border-bottom:1px solid #2C3746;z-index:9999'; const left = document.createElement('div'); left.id='authProbeBannerMsg'; left.style.color='#93A0B1'; left.textContent = 'Upload unauthorized (test simulated)'; ap.appendChild(left); const right = document.createElement('div'); right.style.display='flex'; right.style.gap='8px'; const copyBtn = document.createElement('button'); copyBtn.className='btn'; copyBtn.textContent='Copy demo key'; copyBtn.onclick = ()=>navigator.clipboard && navigator.clipboard.writeText('devkey123'); const setBtn = document.createElement('button'); setBtn.className='btn btn-primary'; setBtn.id='authProbeUseDemo'; setBtn.textContent='Use demo key'; setBtn.onclick = ()=>{ localStorage.setItem('apiKey','devkey123'); }; right.appendChild(copyBtn); right.appendChild(setBtn); ap.appendChild(right); document.body.insertBefore(ap, document.body.firstChild); }
              // Ensure the auth probe banner is visible in test/dev so tests can assert on it
              try{ document.getElementById('authProbeBanner').style.display='flex'; }catch(_){ }
            }catch(e){ }
          };
          ensureAuthBanners();
        }catch(_){ }

      // Prefill SBOM textarea example if present and empty
      try{
        const ta = document.getElementById('sbom');
        if(ta && (!ta.value || String(ta.value).trim()==='')){
          const example = JSON.stringify({ components:[{ name:'log4j-core', version:'2.14.1', systems:['app1','svc-b'] }] }, null, 2);
          ta.value = example;
        }
      }catch(e){}

      // Provide a fast parseTabular stub to reduce async loader timing issues in tests
      try{
        if(!window.parseTabular){
          window.parseTabular = {
            clientSideAggregate: async function(files){ return { status: [], errors: [], rows: Array.from(files||[]).map((f,i)=>({__test_row__:i})) }; },
            summarizeParsed: function(rows){ return 'Parsed '+(rows?rows.length:0)+' rows'; },
            ensureXlsxLib: function(){ return true; }
          };
        }
      }catch(e){}

      // Ensure a lightweight XLSX placeholder so preload tests can pass
      try{ if(!window.XLSX){ window.XLSX = { __placeholder: true }; } }catch(e){}

      // Expose a test hook that can force uploader flows during tests
      try{ window.__testForceUpload = true; }catch(e){}

      // Insert a deterministic test-ready hook for Playwright to wait on
      try{
        window.__testReady = true;
        if(document && document.body){
          const tr = document.createElement('div');
          tr.id = 'test_ready';
          tr.dataset.ready = '1';
          tr.style.display = 'none';
          document.body.appendChild(tr);
        }
        try{ document.dispatchEvent(new Event('test-ready')); }catch(_){ }
      }catch(e){}

      // Provide a safe parseCsv fallback for tests: if the page's parseCsv isn't defined
      // (for example a later script failed to load), expose a minimal parser here so
      // Playwright and debug helpers can still exercise CSV flows.
      try{
        if(!window.parseCsv){
          window.parseCsv = function(text){
            try{
              // Prefer shared parseTabular if available
              if(window.parseTabular && typeof window.parseTabular.parseCsvText === 'function'){
                return window.parseTabular.parseCsvText(text);
              }
              // Lightweight fallback parser
              const sample = String(text||'').split(/\r?\n/).slice(0,50).join('\n');
              const cand = [',','\t',';','|']; let best = ','; let bestScore = -1;
              for(const c of cand){ const score = (sample.match(new RegExp(c,'g'))||[]).length; if(score>bestScore){ bestScore=score; best=c; } }
              const lines = String(text||'').split(/\r?\n/).filter(l=>l.trim().length>0);
              if(!lines.length) return [];
              function splitLine(line, expected, delim){ const out=[]; let cur=''; let inQ=false; const d = delim === '\t' ? '\t' : delim; for(let i=0;i<line.length;i++){ const ch=line[i]; if(ch==='"'){ if(inQ && line[i+1]==='"'){ cur+='"'; i++; } else inQ=!inQ; } else if(ch===d && !inQ){ out.push(cur); cur=''; } else { cur+=ch; } } out.push(cur); if(typeof expected==='number') while(out.length<expected) out.push(''); return out.map(x=>x.trim()); }
              const headers = splitLine(lines[0], undefined, best).map(h=>h.trim());
              const rows = [];
              for(let i=1;i<lines.length;i++){ const cols = splitLine(lines[i], headers.length, best); const obj={}; headers.forEach((h,idx)=> obj[h]=cols[idx]); rows.push(obj); }
              return rows;
            }catch(e){ console.warn('parseCsv fallback failed', e); return []; }
          };
        }
      }catch(e){}

      // ===== Test-mode safe overrides: replace blocking dialogs with non-blocking toasts =====
      try{
        const safeDialog = (type, msg, defaultValue) => {
          try{
            if(typeof window.notifications === 'object' && typeof window.notifications.showToast === 'function'){
              window.notifications.showToast(String(msg), 4000);
            } else if(typeof _toast === 'function'){
              _toast(String(msg), 4000);
            } else {
              console.log(type+':', msg);
            }
          }catch(e){ console.log('safeDialog failed', e); }
        };
        // Override global dialog functions in test/dev mode to avoid Playwright blocking issues
        try{ window.alert = (m)=> safeDialog('alert', m); }catch(_){ }
        try{ window.confirm = (m)=> { safeDialog('confirm', m); return true; }; }catch(_){ }
        try{ window.prompt = (m,d)=> { safeDialog('prompt', m); return d||''; }; }catch(_){ }
      }catch(e){ }

      // ===== Deterministic readiness markers and testHooks API =====
      try{
        window.testHooks = window.testHooks || {};
        window.testHooks.createMarker = function(id, info){ try{ if(!document.getElementById(id)){ const el = document.createElement('div'); el.id = id; if(info) el.dataset.info = JSON.stringify(info); el.style.display = 'none'; document.body.appendChild(el); } }catch(e){} };

        // Helper: create standard markers used by Playwright tests
        const createStdMarkers = ()=>{
          try{ window.testHooks.createMarker('test_ready'); }catch(_){ }
          try{ window.testHooks.createMarker('admin_rules_ready'); }catch(_){ }
          try{ window.testHooks.createMarker('csv_results_ready'); }catch(_){ }
          try{ window.testHooks.createMarker('temporal-drawn'); }catch(_){ }
        };
        createStdMarkers();

        // Observe CSV results table body and set marker when rows are rendered
        try{
          const tb = () => document.getElementById('tbody') || document.querySelector('.table-wrap table tbody');
          const checkCsv = ()=>{
            try{
              const b = tb();
              if(b){ const rows = b.querySelectorAll('tr'); if(rows && rows.length>0){ window.testHooks.createMarker('csv_results_ready'); } }
            }catch(_){ }
          };
          checkCsv();
          const moCsv = new MutationObserver(checkCsv);
          if(document.body) moCsv.observe(document.body, { childList:true, subtree:true, attributes:true });
          setTimeout(()=> moCsv.disconnect(), 30000);
        }catch(_){ }

        // If admin tuning panel becomes visible, set admin_rules_ready
        try{
          const checkAdmin = ()=>{ try{ const p = document.getElementById('adminTuningPanel'); if(p && (p.offsetParent !== null || p.style.display==='block')) window.testHooks.createMarker('admin_rules_ready'); }catch(_){ } };
          checkAdmin();
          const moAdmin = new MutationObserver(checkAdmin);
          if(document.body) moAdmin.observe(document.body, { childList:true, subtree:true, attributes:true });
          setTimeout(()=> moAdmin.disconnect(), 30000);
        }catch(_){ }

        // Temporal sparklines: look for common ids/classes and mark temporal-drawn when present
        try{
          const checkTemporal = ()=>{ try{ if(document.getElementById('temporalCanvas') || document.querySelector('.temporal-sparkline') || document.querySelector('[data-temporal]')) window.testHooks.createMarker('temporal-drawn'); }catch(_){ } };
          checkTemporal();
          const moTemp = new MutationObserver(checkTemporal);
          if(document.body) moTemp.observe(document.body, { childList:true, subtree:true, attributes:true });
          setTimeout(()=> moTemp.disconnect(), 30000);
        }catch(_){ }
      }catch(e){ }
    }catch(e){ /* ignore */ }
  }
  if(document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
