// Fetch wrapper with degraded mode banner
(function(){
  let failureCount = 0;
  const failureThreshold = 5; // adjustable
  function showBanner(msg, level){
    const b = document.getElementById('globalBanner'); if(!b) return;
    b.textContent = msg;
    b.classList.toggle('warn', level==='warn');
    b.style.display='block';
  }
  async function safeFetch(url, opts){
    try{
      const r = await fetch(url, opts);
      if(!r.ok){ failureCount++; if(failureCount===failureThreshold){ showBanner('Service degraded: multiple failures','warn'); } }
      return r;
    }catch(err){
      failureCount++; if(failureCount===failureThreshold){ showBanner('Network issues detected','warn'); }
      throw err;
    }
  }
  window.safeFetch = safeFetch;
})();
