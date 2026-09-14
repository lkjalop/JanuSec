// Factor drill-down modal helpers
(function(){
  function openFactorDrilldown(factorName){
    try{
      const overlay = document.getElementById('factorModal');
      const title = document.getElementById('factorTitle');
      const content = document.getElementById('factorDetailsContent');
      if (title) title.textContent = factorName || '';
      if (overlay) overlay.style.display = 'flex';
      if (content) content.innerHTML = '<div class="evidence-item">Loading factor context…</div>';

      const fe = (window._lastFrameworkEnrichment || {});
      const fw = fe && factorName ? fe[factorName] : null;
      const inc = (window._lastFrameworkIncident || {});
      const rows = [];
      if (fw && typeof fw === 'object'){
        try {
          if (fw.value) rows.push(`<div class='evidence-item'><b>Value</b>: ${fw.value}</div>`);
        }catch(_err){}
        try {
          const hosts = Array.isArray(fw.hosts) ? fw.hosts.slice(0,10).join(', ') : null;
          if (hosts) rows.push(`<div class='evidence-item'><b>Associated Hosts</b>: ${hosts}</div>`);
        }catch(_err){}
        try {
          const ips = Array.isArray(fw.ips) ? fw.ips.slice(0,10).join(', ') : null;
          if (ips) rows.push(`<div class='evidence-item'><b>IPs</b>: ${ips}</div>`);
        }catch(_err){}
        try {
          const first = fw.first_seen || fw.first || null;
          const last = fw.last_seen || fw.last || null;
          if (first || last) rows.push(`<div class='evidence-item'><b>First/Last Seen</b>: ${first || 'n/a'} / ${last || 'n/a'}</div>`);
        }catch(_err){}
        try {
          const count = (fw.count || fw.frequency || (Array.isArray(fw.values)? fw.values.length : null));
          if (count != null) rows.push(`<div class='evidence-item'><b>Frequency</b>: ${count}</div>`);
        }catch(_err){}
      }
      // Fallback summary from incident if available
      if (!rows.length && inc && inc.explanations){
        try {
          const ex = inc.explanations || {};
          const keys = Object.keys(ex);
          rows.push(`<div class='evidence-item'>No structured enrichment found for <code>${factorName}</code>. Incident has ${keys.length} explanation keys.</div>`);
        }catch(_err){}
      }
      if (content) content.innerHTML = rows.length ? rows.join('') : `<div class='evidence-item'>No additional context available for <code>${factorName}</code>.</div>`;
    }catch(_err){
      console.error('openFactorDrilldown failed', _err);
      const content = document.getElementById('factorDetailsContent');
      if (content) content.innerHTML = `<div class='evidence-item'>Failed to load factor context: ${_err && _err.message}</div>`;
    }
  }

  function closeFactorDetails(){
    const overlay = document.getElementById('factorModal');
    if (overlay) overlay.style.display = 'none';
  }

  window.openFactorDrilldown = openFactorDrilldown;
  window.closeFactorDetails = closeFactorDetails;
})();

