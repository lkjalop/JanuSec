// Playwright setup helper injected via --require or used with page.addInitScript
(function(){
  // This script is executed in Node context when required, but we export a helper
  // string that tests or the runner can pass to page.addInitScript to run in the browser.
  const initScript = `(() => {
    try { localStorage.setItem('TEST_FORCE_MAPPING_MODAL','1'); localStorage.setItem('offerMappingOnUploadConfirm','1'); localStorage.setItem('csvMultiEwmaSettings', JSON.stringify({alpha:0.6,enable:true,adaptive:true})); }catch(e){}
    try{
      if(!window.XLSX){ window.XLSX = { read: function(){ return { Sheets:{}, SheetNames:[] }; }, utils: { sheet_to_json: function(){ return []; } } }; console.log('[playwright_setup] Injected XLSX stub'); }
    }catch(e){}
    try{
      // expose convenient test init for page-level scripts
      window.__csvMultiTestInit = window.__csvMultiTestInit || function(){ try{ localStorage.setItem('TEST_FORCE_MAPPING_MODAL','1'); }catch(_){} };
    }catch(e){}
    try{
      // wrap fetch to surface SBOM upload toasts in UI tests
      const orig = window.fetch.bind(window);
      window.fetch = async function(url, opts){ const res = await orig(url, opts); try{ const s = (typeof url==='string'? url : (url && url.url)) || ''; if(s.indexOf('/api/v1/sbom/upload')!==-1){ try{ const msg = res && res.ok ? 'SBOM uploaded' : ('SBOM upload failed: '+(res && res.status)); const ev = new CustomEvent('__sbom_upload_result', { detail: { ok: !!(res && res.ok), status: res && res.status } }); window.dispatchEvent(ev); console.log('[playwright_setup] sbom event', msg); }catch(_){ } } }catch(_){ } return res; };
    }catch(e){}
  })();`;

  // Export for require()
  module.exports = { initScript };
})();
