// Centralized fetch helper: injects auth headers, timeout, retry and normalizes responses
(function(){
  function getApiKey(){ try{ return localStorage.getItem('apiKey') || ''; }catch(_){ return ''; } }
  function getTenantId(){ try{ return localStorage.getItem('tenantId') || '' }catch(_){ return ''; } }

  function isIdempotent(method){ if(!method) return true; const m=method.toUpperCase(); return ['GET','HEAD','OPTIONS'].includes(m); }

  function sleep(ms){ return new Promise(res => setTimeout(res, ms)); }

  async function apiFetch(input, opts){
    opts = Object.assign({}, opts || {});
    const method = (opts.method || 'GET').toUpperCase();

    // Merge headers, do not mutate original
    const headers = Object.assign({}, opts.headers || {});
    // Only set content-type when a body is present and not FormData
    if(opts.body && !(opts.body instanceof FormData) && !headers['Content-Type'] && !headers['content-type']){
      headers['Content-Type'] = 'application/json';
    }

    // Inject auth/tenant headers if not present
    try{ if(!headers['x-api-key'] && !headers['X-Api-Key']) headers['x-api-key'] = getApiKey(); }catch(_){ }
    try{ if(!headers['x-tenant-id'] && !headers['X-Tenant-Id']) headers['x-tenant-id'] = getTenantId(); }catch(_){ }

    const finalOpts = Object.assign({}, opts, { headers });

    const timeout = typeof opts.timeout === 'number' ? opts.timeout : null; // milliseconds
    const retries = Number.isFinite(opts.retry) ? Math.max(0, Math.floor(opts.retry)) : 0;
    const retryOn = opts.retryOn || ((status) => status >= 500);

    let attempt = 0;
    let lastErr = null;

    while(true){
      attempt++;
      let controller = null;
      let timer = null;
      try{
        if(timeout){ controller = new AbortController(); finalOpts.signal = controller.signal; timer = setTimeout(()=> controller.abort(), timeout); }
        const resp = await fetch(input, finalOpts);
        if(timer) clearTimeout(timer);
        // If retry requested and response status matches, retry for idempotent methods
        if(attempt <= retries && isIdempotent(method) && retryOn && retryOn(resp.status)){
          const backoff = Math.min(1000 * Math.pow(2, attempt-1), 10000) + Math.floor(Math.random()*200);
          await sleep(backoff);
          continue;
        }
        return resp;
      }catch(err){
        lastErr = err;
        if(timer) clearTimeout(timer);
        // AbortError or other network error: retry only for idempotent
        if(attempt <= retries && isIdempotent(method)){
          const backoff = Math.min(1000 * Math.pow(2, attempt-1), 10000) + Math.floor(Math.random()*200);
          await sleep(backoff);
          continue;
        }
        throw err;
      }
    }
  }

  // Parse response text->json safely
  async function _parseResponse(resp){
    const out = { ok: !!resp && !!resp.ok, status: resp && resp.status ? resp.status : 0, headers: resp && resp.headers };
    try{
      const txt = await resp.text();
      out.text = txt;
      try{ out.body = txt ? JSON.parse(txt) : null; }catch(_){ out.body = null; }
    }catch(e){ out.text = null; out.body = null; }
    return out;
  }

  // safeFetch returns a Response-like wrapper that includes parsed body/text and preserves .ok and .status
  async function safeFetch(input, opts){
    const resp = await apiFetch(input, opts);
    // read and parse body once
    const parsed = await _parseResponse(resp);
    // Build wrapper
    const wrapper = {
      ok: parsed.ok,
      status: parsed.status,
      headers: parsed.headers,
      // Provide .text() and .json() for compatibility with callers expecting a Response
      text: async () => parsed.text,
      json: async () => {
        if(parsed.body !== null) return parsed.body;
        try{ return parsed.text ? JSON.parse(parsed.text) : null; }catch(e){ throw e; }
      },
      // convenience access
      body: parsed.body,
      rawText: parsed.text,
      // original response reference (if available)
      response: resp
    };
    return wrapper;
  }

  // Also expose a helper that returns parsed body or throws structured error
  async function apiFetchOk(input, opts){
    const resp = await apiFetch(input, opts);
    const parsed = await _parseResponse(resp);
    if(!resp.ok){
      const err = new Error((parsed.body && (parsed.body.detail || parsed.body.error)) || parsed.text || `HTTP ${resp.status}`);
      err.status = parsed.status; err.body = parsed.body; err.text = parsed.text; throw err;
    }
    return parsed.body;
  }

  // Expose globally
  try{ window.apiFetch = apiFetch; window.safeFetch = safeFetch; window.apiFetchOk = apiFetchOk; }catch(_){ /* noop in non-browser contexts */ }

  // UMD-ish export for modules if needed
  if(typeof module !== 'undefined' && module.exports){ module.exports = { apiFetch, safeFetch, apiFetchOk }; }

})();
