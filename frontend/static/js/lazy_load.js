/* lazyLoadScript(url): returns Promise that resolves when script loads */
(function(global){
  function lazyLoadScript(url){
    return new Promise((resolve, reject)=>{
      if(document.querySelector('script[data-lazy="'+url+'"]')) return resolve();
      const s = document.createElement('script');
      s.src = url; s.async = true; s.setAttribute('data-lazy', url);
      s.onload = ()=> resolve(); s.onerror = (e)=> reject(e);
      document.head.appendChild(s);
    });
  }
  global.lazyLoadScript = lazyLoadScript;
  
  // Try to dynamically import an ES module; if not possible, fallback to script injection
  async function lazyLoadModule(url){
    if(window.__moduleCache && window.__moduleCache[url]) return window.__moduleCache[url];
    try{
      if(url.endsWith('.mjs') || url.endsWith('.js')){
        // dynamic import needs absolute or same-origin URL
        const mod = await import(url.startsWith('/') ? location.origin + url : url);
        window.__moduleCache = window.__moduleCache || {};
        window.__moduleCache[url] = mod;
        return mod;
      }
    }catch(_){ /* ignore import failures */ }
    // fallback: inject script
    await lazyLoadScript(url);
    return window.__moduleCache = window.__moduleCache || {};
  }
  global.lazyLoadModule = lazyLoadModule;
})(window);
