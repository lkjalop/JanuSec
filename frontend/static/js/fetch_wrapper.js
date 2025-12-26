// Fetch wrapper with degraded mode banner
(function(){
  // Advanced fetch wrapper with retries, backoff, timeout and simple circuit breaker
  const DEFAULT_MAX_RETRIES = 3;
  const DEFAULT_TIMEOUT_MS = 10000;
  const FAILURE_THRESHOLD = 6; // total failures before global degraded banner
  const CIRCUIT_RESET_MS = 60 * 1000; // 1 minute

  let globalFailureCount = 0;
  const circuitState = new Map(); // host -> { openUntil: <ts> }

  function showBanner(msg, level){
    const b = document.getElementById('globalBanner'); if(!b) return;
    b.textContent = msg;
    b.classList.toggle('warn', level==='warn');
    b.style.display='block';
  }

  function sleep(ms){ return new Promise(r => setTimeout(r, ms)); }

  function timeoutPromise(promise, ms){
    let id;
    const timer = new Promise((_, rej) => { id = setTimeout(()=> rej(new Error('timeout')), ms); });
    return Promise.race([promise.then(v=>{ clearTimeout(id); return v; }), timer]);
  }

  function getHost(url){ try{ const u = new URL(url, location.href); return u.host; }catch(_){ return url; } }

  async function safeFetch(url, opts={}){
    // consult simple client cache for certain GET endpoints
    try{
      if(window.LRUCache && (!opts || (opts.method||'GET').toUpperCase()==='GET')){
        const key = url.toString();
        // cache only status/dashboard endpoints
        if(key.includes('/api/v1/status') || key.includes('/api/v1/dashboard') || key.includes('/api/v1/metrics')){
          if(!window.__clientCache) window.__clientCache = new window.LRUCache({ capacity: 200, ttl: 15000 });
          const cached = window.__clientCache.get(key);
          if(cached){
            // return a Response-like object for callers expecting fetch Response
            return new Response(JSON.stringify(cached.body), { status: 200, headers: {'content-type':'application/json'} });
          }
        }
      }
    }catch(e){ /* ignore cache errors */ }
    const maxRetries = Number(opts._maxRetries ?? DEFAULT_MAX_RETRIES);
    const timeoutMs = Number(opts._timeoutMs ?? DEFAULT_TIMEOUT_MS);
    const host = getHost(url);

    // Circuit breaker: if open, throw immediately
    const state = circuitState.get(host);
    if(state && state.openUntil && Date.now() < state.openUntil){
      throw new Error('circuit_open');
    }

    let attempt = 0;
    let lastErr = null;
    while(attempt <= maxRetries){
      try{
        const controller = new AbortController();
        const signal = controller.signal;
        const fetchOpts = Object.assign({}, opts, { signal });
        // Remove internal options before passing to fetch
        delete fetchOpts._maxRetries; delete fetchOpts._timeoutMs;

        const prom = fetch(url, fetchOpts);
        const res = await timeoutPromise(prom, timeoutMs);
        if(!res.ok){
          lastErr = new Error('http:'+res.status);
          // Treat 5xx as retryable
          if(res.status >= 500 && res.status < 600){ throw lastErr; }
          // Non-retryable: return response so callers can inspect
          return res;
        }
        // If JSON and cacheable endpoint, store body snapshot
        try{
          const ct = res.headers.get('content-type')||'';
          if(ct.includes('application/json')){
            const clone = await res.clone().json();
            if(window.__clientCache){
              const key = url.toString();
              if(key.includes('/api/v1/status') || key.includes('/api/v1/dashboard') || key.includes('/api/v1/metrics')){
                window.__clientCache.set(key, { body: clone });
              }
            }
          }
        }catch(e){}
        // success -> reset counters
        globalFailureCount = Math.max(0, globalFailureCount-1);
        if(state && state.openUntil){ circuitState.delete(host); }
        return res;
      }catch(err){
        lastErr = err;
        attempt++;
        globalFailureCount++;
        // On repeated failures open circuit for host
        if(attempt > Math.max(1, Math.floor(maxRetries/2))){
          circuitState.set(host, { openUntil: Date.now() + CIRCUIT_RESET_MS });
        }
        // Trigger global degraded banner if many failures
        if(globalFailureCount >= FAILURE_THRESHOLD){
          try{ showBanner('Service degraded — some features may be limited','warn'); }catch(_){ }
        }
        if(attempt > maxRetries) break;
        // exponential backoff with jitter
        const backoff = Math.pow(2, attempt) * 200 + Math.floor(Math.random()*200);
        await sleep(backoff);
        continue;
      }
    }
    throw lastErr || new Error('fetch_failed');
  }

  window.safeFetch = safeFetch;
})();
