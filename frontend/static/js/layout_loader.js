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
    // Accessibility: focus main wrapper
    setTimeout(()=>{ const wrap = document.getElementById('contentWrapper'); if(wrap) wrap.focus(); }, 50);
  }
  if(document.readyState==='loading'){ document.addEventListener('DOMContentLoaded', init); } else { init(); }
  window.refreshAuthState = updateAuthState;
})();
