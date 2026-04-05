const SW_VERSION = 'v2';
const CACHE_NAME = `janusec-shell-${SW_VERSION}`;
const SHELL_ASSETS = [
  '/',
  '/static/janusec-platform-complete-LIVE.html',
  '/static/css/tokens.css',
  '/static/css/components.css',
  '/static/js/layout_loader.js',
  '/static/js/fetch_wrapper.js'
];

// TTL map (milliseconds) for specific paths or asset types
const ASSET_TTL = {
  '/static/js/': 1000 * 60 * 5, // 5 minutes
  '/static/css/': 1000 * 60 * 60 // 1 hour
};

const MAX_CACHE_BYTES = 1024 * 1024; // 1MB - skip caching responses larger than this
const CACHE_META_KEY = '/__cache_meta__';

async function readCacheMeta(){
  try{
    const c = await caches.open(CACHE_NAME);
    const r = await c.match(CACHE_META_KEY);
    if(!r) return {};
    const j = await r.json(); return j||{};
  }catch(_){ return {}; }
}

async function writeCacheMeta(meta){
  try{
    const c = await caches.open(CACHE_NAME);
    const blob = new Blob([JSON.stringify(meta)], { type: 'application/json' });
    const resp = new Response(blob, { headers: { 'content-type':'application/json' } });
    await c.put(CACHE_META_KEY, resp);
  }catch(_){ }
}

async function pruneCacheIfNeeded(){
  try{
    const meta = await readCacheMeta();
    const entries = Object.entries(meta); // [url, {ts,size}]
    // Remove expired entries
    const now = Date.now();
    let changed = false;
    for(const [url, info] of entries){
      const ttl = Object.keys(ASSET_TTL).find(p=> url.includes(p));
      const ttlMs = ttl ? ASSET_TTL[ttl] : (1000*60*5);
      if(info.ts + ttlMs < now){
        const c = await caches.open(CACHE_NAME);
        await c.delete(url);
        delete meta[url];
        changed = true;
      }
    }
    // Enforce max total size by LRU-ish eviction
    const total = Object.values(meta).reduce((s,i)=>(s+(i.size||0)),0);
    if(total > MAX_CACHE_BYTES){
      const sorted = Object.entries(meta).sort((a,b)=> a[1].ts - b[1].ts);
      let t = total;
      for(const [url, info] of sorted){
        const c = await caches.open(CACHE_NAME);
        await c.delete(url);
        t -= (info.size||0);
        delete meta[url];
        changed = true;
        if(t <= MAX_CACHE_BYTES) break;
      }
    }
    if(changed) await writeCacheMeta(meta);
  }catch(_){ }
}

self.addEventListener('install', (ev) => {
  ev.waitUntil(
    caches.open(CACHE_NAME)
      .then((c) => c.addAll(SHELL_ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (ev) => {
  ev.waitUntil(
    caches.keys().then((keys) => Promise.all(
      keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
    )).then(() => self.clients.claim()).then(()=>{
      // Notify clients that a new SW is active
      self.clients.matchAll().then(clients => {
        clients.forEach(client => client.postMessage({ type: 'SW_UPDATED', version: SW_VERSION }));
      });
    })
  );
});

// Simple stale-while-revalidate strategy for shell/static assets
self.addEventListener('fetch', (ev) => {
  const url = new URL(ev.request.url);

  // Always bypass caching for API endpoints
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/metrics') || url.pathname === '/health') {
    ev.respondWith(fetch(ev.request).catch(() => caches.match(ev.request)));
    return;
  }

  // For static/shell assets: respond with cache then background update
  if (SHELL_ASSETS.includes(url.pathname) || url.pathname.startsWith('/static/')) {
    ev.respondWith(
      caches.match(ev.request).then((cached) => {
        const networkFetch = fetch(ev.request).then((networkResp) => {
          // try to update cache in background but avoid very large responses
          try{
            const ct = networkResp.headers.get('content-length');
            const size = ct? parseInt(ct,10) : 0;
            if(size && size > MAX_CACHE_BYTES) return networkResp;
            // clone and put into cache
            networkResp.clone().arrayBuffer().then(async buf=>{
              if(buf && buf.byteLength <= MAX_CACHE_BYTES){
                const c = await caches.open(CACHE_NAME);
                await c.put(ev.request, networkResp.clone());
                // update metadata
                const meta = await readCacheMeta();
                meta[ev.request.url] = { ts: Date.now(), size: buf.byteLength };
                await writeCacheMeta(meta);
                // prune if necessary
                await pruneCacheIfNeeded();
              }
            }).catch(()=>{});
          }catch(_){ /* ignore cache errors */ }
          return networkResp;
        }).catch(() => null);
        return cached || networkFetch || caches.match('/static/janusec-platform-complete-LIVE.html');
      })
    );
    return;
  }

  // Default: network-first with cache fallback
  ev.respondWith(fetch(ev.request).catch(() => caches.match(ev.request)));
});
