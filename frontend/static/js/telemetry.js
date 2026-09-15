// Lightweight telemetry queue for frontend (local-only, no external telemetry by default)
(function(){
  const KEY = 'janusec_telemetry_queue_v1';
  // Developer local collector (prefer explicit localhost port when available)
  const ENDPOINT = (location.hostname === 'localhost' || location.hostname === '127.0.0.1') ? 'http://localhost:5001/telemetry/ingest' : '/telemetry/ingest';
  let queue = [];
  try{ queue = JSON.parse(localStorage.getItem(KEY) || '[]'); }catch(_) { queue = []; }

  function persist(){ try{ localStorage.setItem(KEY, JSON.stringify(queue)); }catch(_){} }

  async function sendBatch(){
    if(!queue.length) return;
    const batch = queue.slice(0,10);
    try{
      const r = await fetch(ENDPOINT, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(batch) });
      if(r.ok){ queue = queue.slice(batch.length); persist(); }
    }catch(e){ /* ignore, will retry later */ }
  }

  // test helper: force immediate send and return the fetch promise
  function flushNow(){ return sendBatch(); }

  function enqueue(evt){
    queue.push(Object.assign({ ts: Date.now() }, evt)); persist();
    // schedule immediate send in background
    setTimeout(()=> sendBatch(), 1000);
  }

  function _queueCount(){ return queue.length; }

  // periodic flush with backoff
  let interval = 60 * 1000; // 1 minute
  setInterval(()=>{ sendBatch(); }, interval);

  window.__janusec_telemetry = { enqueue, _queueCount };
  window.__janusec_telemetry.flushNow = flushNow;
})();
