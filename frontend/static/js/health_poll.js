(function(){
  const POLL_INTERVAL = 15000; // 15s fallback poll
  const SSE_URL = '/api/v1/stream/decisions'; // primary SSE endpoint
  const SSE_FALLBACK = '/api/v1/stream/artifacts';
  let sse; let lastOk = Date.now(); let degradedShown = false;

  function showBanner(msg, level){
    const b = document.getElementById('globalBanner'); if(!b) return;
    b.textContent = msg;
    b.classList.toggle('warn', level==='warn');
    b.style.display='block';
  }
  function markHealthy(){ lastOk = Date.now(); window.__healthLastOk = lastOk; if(degradedShown){ degradedShown=false; const b=document.getElementById('globalBanner'); if(b) b.style.display='none'; } }
  function checkDegraded(){
    const diff = Date.now()-lastOk;
    if(diff > POLL_INTERVAL*2 && !degradedShown){ degradedShown=true; showBanner('Realtime channel inactive; falling back','warn'); }
  }
  function startFallbackPoll(){
    setInterval(async ()=>{
      try{
        const r = await (window.safeFetch? window.safeFetch('/api/v1/status/dashboard',{ headers: authHeaders() }) : fetch('/api/v1/status/dashboard',{ headers: authHeaders() }));
        if(r.ok){ markHealthy(); }
      }catch{ /* ignore network error */ }
      checkDegraded();
    }, POLL_INTERVAL);
  }
  function authHeaders(){ try{ const k=localStorage.getItem('apiKey')||'devkey123'; return {'x-api-key':k}; }catch{ return {'x-api-key':'devkey123'}; } }
  function startSSE(){
    try{
      sse = new EventSource(SSE_URL);
      sse.onopen = ()=>{ markHealthy(); };
      sse.onmessage = (ev)=>{ markHealthy(); try{ const data = JSON.parse(ev.data); window.dispatchEvent(new CustomEvent('health-event',{ detail:data })); }catch{ } };
      sse.onerror = ()=>{ checkDegraded(); };
    }catch{
      // try artifacts alias as fallback
      try{
        sse = new EventSource(SSE_FALLBACK);
        sse.onopen = ()=>{ markHealthy(); };
        sse.onmessage = (ev)=>{ markHealthy(); try{ const data = JSON.parse(ev.data); window.dispatchEvent(new CustomEvent('health-event',{ detail:data })); }catch{ } };
        sse.onerror = ()=>{ checkDegraded(); };
      }catch{ /* SSE not available */ }
    }
  }
  function init(){ window.__healthLastOk = lastOk; startSSE(); startFallbackPoll(); }
  if(document.readyState==='loading'){ document.addEventListener('DOMContentLoaded', init); } else { init(); }
})();