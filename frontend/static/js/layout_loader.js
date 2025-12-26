// Layout loader: inject page content into #contentWrapper, set auth state, env switching.
(function(){
  function detectApiKey(){
    try{ return localStorage.getItem('apiKey') || 'devkey123'; }catch(_){ return 'devkey123'; }
  }
  function updateAuthState(){
    const el = document.getElementById('authState');
    if(!el) return;
    const key = detectApiKey();
    const masked = key.length > 8 ? key.slice(0,4)+'…'+key.slice(-3) : key;
    el.textContent = 'auth: '+masked;
  }
  function wireEnvSelect(){
    const sel = document.getElementById('envSelect');
    if(!sel) return;
    try{ sel.value = (localStorage.getItem('envSelect')||'dev'); }catch(_){ }
    sel.addEventListener('change', ()=>{
      try{ localStorage.setItem('envSelect', sel.value); }catch(_){ }
      window.showToast('Environment switched to '+sel.value, 'success');
    });
  }

  // Feature flags UI: modal settings panel
  function initFeatureFlags(){
    try{
      window.featureFlags = window.featureFlags || {};
      const model = JSON.parse(localStorage.getItem('featureFlags')||'{}');
      window.featureFlags._m = model;
      window.featureFlags.isEnabled = (k)=> !!(window.featureFlags._m && window.featureFlags._m[k]);

      const container = document.getElementById('topBar') || document.body;
      const fbtn = document.createElement('button');
      fbtn.className = 'btn'; fbtn.style.marginLeft='8px'; fbtn.textContent='Settings';
      fbtn.onclick = ()=>{
        openFlagsModal();
      };
      container.appendChild(fbtn);

      // modal builder
      function openFlagsModal(){
        if(document.getElementById('flagsModal')) return;
        const modal = document.createElement('div'); modal.id='flagsModal'; modal.style.position='fixed'; modal.style.inset='0'; modal.style.display='flex'; modal.style.alignItems='center'; modal.style.justifyContent='center'; modal.style.background='rgba(0,0,0,0.45)'; modal.style.zIndex=99999;
        const panel = document.createElement('div'); panel.style.background='#fff'; panel.style.color='#000'; panel.style.padding='16px'; panel.style.borderRadius='8px'; panel.style.width='420px';
        const title = document.createElement('h3'); title.textContent='Feature Flags'; title.style.marginTop='0'; panel.appendChild(title);
        const list = document.createElement('div'); list.id='flagsList'; panel.appendChild(list);
        const inp = document.createElement('input'); inp.placeholder='flag_key'; inp.style.width='60%'; panel.appendChild(inp);
        const add = document.createElement('button'); add.textContent='Add/Enable'; add.className='btn'; add.style.marginLeft='8px'; add.onclick = ()=>{ if(!inp.value) return; window.featureFlags._m[inp.value]=true; render(); try{ localStorage.setItem('featureFlags', JSON.stringify(window.featureFlags._m)); }catch(_){ } };
        panel.appendChild(add);
        const reset = document.createElement('button'); reset.textContent='Reset Flags'; reset.className='btn'; reset.style.marginLeft='8px'; reset.onclick = ()=>{ window.featureFlags._m={}; try{ localStorage.removeItem('featureFlags'); }catch(_){ } render(); };
        panel.appendChild(reset);
        const close = document.createElement('button'); close.textContent='Close'; close.className='btn'; close.style.float='right'; close.onclick = ()=>{ document.body.removeChild(modal); };
        panel.appendChild(close);
        modal.appendChild(panel);
        document.body.appendChild(modal);
        function render(){
          list.innerHTML='';
          const keys = Object.keys(window.featureFlags._m||{});
          if(!keys.length) list.textContent='No flags set.';
          keys.forEach(k=>{
            const row = document.createElement('div'); row.style.display='flex'; row.style.alignItems='center'; row.style.marginTop='6px';
            const txt = document.createElement('div'); txt.textContent=k; txt.style.flex='1'; row.appendChild(txt);
            const del = document.createElement('button'); del.textContent='Disable'; del.className='btn'; del.onclick=()=>{ delete window.featureFlags._m[k]; try{ localStorage.setItem('featureFlags', JSON.stringify(window.featureFlags._m)); }catch(_){ } render(); };
            row.appendChild(del);
            list.appendChild(row);
          });
        }
        render();
      }
    }catch(_){ }
  }
  // Basic content injection: if page has a main content container `.page-root`, move it inside layout wrapper.
  function adoptContent(){
    const wrap = document.getElementById('contentWrapper');
    if(!wrap) return;
    const pageRoot = document.querySelector('.page-root');
    if(pageRoot){ wrap.appendChild(pageRoot); return; }
    // Fallback: gather body children except layout shell, re-parent
    const shellIds = new Set(['globalBanner','topBar','toastContainer','contentWrapper']);
    const fr = document.createDocumentFragment();
    Array.from(document.body.children).forEach(ch=>{ if(!shellIds.has(ch.id)) fr.appendChild(ch); });
    wrap.appendChild(fr);
  }
  function init(){
    updateAuthState();
    wireEnvSelect();
    adoptContent();
    document.body.classList.add('with-topbar');
    initFeatureFlags();
    // Telemetry UI: show queued count if telemetry is present
    try{
      const tbadge = document.createElement('span'); tbadge.id='telemetryBadge'; tbadge.style.marginLeft='8px'; tbadge.style.color='var(--text-muted)';
      const top = document.getElementById('topBar') || document.body; top.appendChild(tbadge);
      const refreshBadge = ()=>{ try{ const q= (window.__janusec_telemetry && window.__janusec_telemetry._queueCount) ? window.__janusec_telemetry._queueCount() : 0; tbadge.textContent = 'telemetry: '+(q||0); }catch(_){ } };
      setInterval(refreshBadge, 1500); refreshBadge();
    }catch(_){ }
    // Attempt to load telemetry client if available
    try{
      if(!document.querySelector('script[src="/static/js/telemetry.js"]')){
        const s = document.createElement('script'); s.src='/static/js/telemetry.js'; s.async=true; document.head.appendChild(s);
      }
    }catch(_){ }
    // global error capture to enqueue telemetry
    try{ window.addEventListener('error', (ev)=>{ try{ if(window.__janusec_telemetry && window.__janusec_telemetry.enqueue) window.__janusec_telemetry.enqueue({ level:'error', msg: ev.message || String(ev), src: ev.filename || '' }); }catch(_){ } }); }catch(_){ }
    // Accessibility: focus main wrapper
    setTimeout(()=>{ const wrap = document.getElementById('contentWrapper'); if(wrap) wrap.focus(); }, 50);
    // Service worker registration (optional) + update message handling
    try{
      if('serviceWorker' in navigator){
        navigator.serviceWorker.register('/static/service-worker.js').then(()=>{
          console.info('service worker registered');
        }).catch(()=>{});
        // Listen for postMessage from SW about updates
        navigator.serviceWorker.addEventListener('message', (ev)=>{
          try{
            const msg = ev.data || {};
            if(msg && msg.type === 'SW_UPDATED'){
              if(window.showSwUpdate) window.showSwUpdate(msg.version || 'new');
            }
          }catch(_){ }
        });
      }
    }catch(_){ }
  }
  if(document.readyState==='loading'){ document.addEventListener('DOMContentLoaded', init); } else { init(); }
  window.refreshAuthState = updateAuthState;
})();
