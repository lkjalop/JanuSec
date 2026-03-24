(function(){
  const POLL_INTERVAL = 15000; // 15s fallback poll
  const SSE_URL = '/api/v1/stream/decisions'; // primary SSE endpoint
  const SSE_FALLBACK = '/api/v1/stream/artifacts';
  let lastOk = Date.now(); let degradedShown = false;
  let streamClientPrimary = null;

  function showBanner(msg, level){
    const b = document.getElementById('globalBanner'); if(!b) return;
    b.textContent = msg;
    b.classList.toggle('warn', level==='warn');
    b.style.display='block';
  }
  function hideBanner(){ const b=document.getElementById('globalBanner'); if(!b) return; b.style.display='none'; }
  function markHealthy(){ lastOk = Date.now(); window.__healthLastOk = lastOk; if(degradedShown){ degradedShown=false; hideBanner(); } }
  function checkDegraded(){
    const diff = Date.now()-lastOk;
    if(diff > POLL_INTERVAL*2 && !degradedShown){ degradedShown=true; showBanner('Realtime channel inactive; falling back','warn'); }
  }
  function startFallbackPoll(){
    setInterval(async ()=>{
      try{
        const r = await (window.safeFetch || fetch)('/api/v1/status/dashboard',{ headers: authHeaders() });
        if(r && r.ok){ markHealthy(); }
      }catch(e){ /* ignore network error */ }
      checkDegraded();
    }, POLL_INTERVAL);
  }
  function authHeaders(){
    try{
      const k = localStorage.getItem('apiKey');
      return k ? {'x-api-key':k} : {};
    }catch{
      return {};
    }
  }

  function createStreamClient(url){
    try{
      const client = new window.StreamClient(url, { type: 'sse' });
      client.subscribe('open', ()=>{ markHealthy(); });
      client.subscribe('message', (ev)=>{ markHealthy(); try{ const data = JSON.parse(ev.data); window.dispatchEvent(new CustomEvent('health-event',{ detail:data })); }catch(e){} });
      client.subscribe('error', ()=>{ checkDegraded(); });
      return client;
    }catch(e){ return null; }
  }

  function startSSE(){
    // primary
    streamClientPrimary = createStreamClient(SSE_URL);
    if(streamClientPrimary){ streamClientPrimary.start(); return; }
    // fallback
    streamClientPrimary = createStreamClient(SSE_FALLBACK);
    if(streamClientPrimary) streamClientPrimary.start();
  }

  // Public helper to allow other modules to subscribe to low-level stream events
  function subscribeToStream(eventType, cb){
    if(!streamClientPrimary) return null;
    return streamClientPrimary.subscribe(eventType, cb);
  }
  function unsubscribeFromStream(eventType, id){ if(streamClientPrimary) streamClientPrimary.unsubscribe(eventType, id); }

  function init(){ window.__healthLastOk = lastOk; startSSE(); startFallbackPoll();
    // expose helpers
    window.streamClient = streamClientPrimary; window.streamSubscribe = subscribeToStream; window.streamUnsubscribe = unsubscribeFromStream;
  }
  if(document.readyState==='loading'){ document.addEventListener('DOMContentLoaded', init); } else { init(); }
})();
