// SSE client helper with reconnect/backoff and heartbeat handling
(function(){
  function getApiKey(){ try{ return localStorage.getItem('apiKey') || ''; }catch(_){ return ''; } }
  function getTenantId(){ try{ return localStorage.getItem('tenantId') || ''; }catch(_){ return ''; } }

  function appendAuthToUrl(url){
    try{
      const u = new URL(url, location.origin);
      if(!u.searchParams.get('x-api-key')) u.searchParams.set('x-api-key', getApiKey());
      if(!u.searchParams.get('x-tenant-id')) u.searchParams.set('x-tenant-id', getTenantId());
      return u.toString();
    }catch(_){ return url; }
  }

  function createSSEClient(url, opts){
    opts = Object.assign({ heartbeat: 30000, reconnectBase: 500, reconnectMax: 30000, log: false }, opts || {});
    let es = null;
    let closed = false;
    let reconnectAttempts = 0;
    let lastEventAt = Date.now();
    let heartbeatTimer = null;

    function log(){ if(opts.log) console.debug.apply(console, arguments); }

    function start(){
      closed = false;
      const finalUrl = appendAuthToUrl(url);
      log('SSE connecting to', finalUrl);
      try{
        es = new EventSource(finalUrl);
      }catch(err){
        scheduleReconnect();
        return;
      }

      es.onopen = (e)=>{
        reconnectAttempts = 0;
        lastEventAt = Date.now();
        resetHeartbeat();
        if(typeof opts.onopen === 'function') opts.onopen(e);
        log('SSE open');
      };

      es.onmessage = (ev)=>{
        lastEventAt = Date.now();
        resetHeartbeat();
        if(typeof opts.onmessage === 'function') opts.onmessage(ev);
      };

      es.onerror = (err)=>{
        log('SSE error', err);
        if(typeof opts.onerror === 'function') opts.onerror(err);
        // close underlying and reconnect
        try{ es.close(); }catch(_){ }
        es = null;
        scheduleReconnect();
      };

      if(typeof opts.onopen === 'function') opts.onopen();
    }

    function resetHeartbeat(){
      if(heartbeatTimer) clearInterval(heartbeatTimer);
      heartbeatTimer = setInterval(()=>{
        const now = Date.now();
        if(now - lastEventAt > Math.max(1000, opts.heartbeat || 30000)){
          // no events recently — force reconnect
          log('SSE heartbeat missed, reconnecting');
          try{ if(es) es.close(); }catch(_){ }
          es = null;
          scheduleReconnect();
        }
      }, Math.max(1000, Math.floor((opts.heartbeat||30000)/3)));
    }

    function scheduleReconnect(){
      if(closed) return;
      reconnectAttempts++;
      const base = opts.reconnectBase || 500;
      const max = opts.reconnectMax || 30000;
      const backoff = Math.min(max, base * Math.pow(2, reconnectAttempts-1)) + Math.floor(Math.random()*200);
      log('SSE reconnect in', backoff);
      setTimeout(()=>{ if(!closed) start(); }, backoff);
    }

    function close(){
      closed = true;
      if(heartbeatTimer) clearInterval(heartbeatTimer);
      try{ if(es) es.close(); }catch(_){ }
      es = null;
      if(typeof opts.onclose === 'function') opts.onclose();
    }

    function isConnected(){ return !!es; }

    // Start automatically
    start();

    return { start, close, isConnected };
  }

  try{ window.createSSEClient = createSSEClient; }catch(_){ }
  if(typeof module !== 'undefined' && module.exports){ module.exports = { createSSEClient }; }
})();
