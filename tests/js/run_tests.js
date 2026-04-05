// Minimal JS UI tests using jsdom to exercise the batch settings modal and aggregation helper
const { JSDOM } = require('jsdom');
const fs = require('fs');
const path = require('path');

function loadScript(dom, filePath){
  const code = fs.readFileSync(filePath,'utf8');
  // Evaluate the script directly in the jsdom window context so globals like localStorage are available
  try{ 
    // Predeclare commonly used globals so scripts that reference them as unqualified identifiers work
    var pre = 'var localStorage = window.localStorage; var fetch = window.fetch; var authHeaders = window.authHeaders || function(){ return {}; };\n';
    dom.window.eval(pre + code);
  }catch(e){
    // fallback: append script element
    const scriptEl = dom.window.document.createElement('script');
    scriptEl.textContent = code;
    dom.window.document.body.appendChild(scriptEl);
  }
}

(async function(){
  try{
    // Create a clean JSDOM and inject csv_analyzer.js after we ensure globals exist
    const dom = new JSDOM('<!doctype html><html><head></head><body></body></html>', { url: 'http://localhost', runScripts: 'dangerously', resources: 'usable' });
    // Provide simple localStorage mock before any script runs
    dom.window.localStorage = (function(){
      const store = {}; return {
        getItem: function(k){ return Object.prototype.hasOwnProperty.call(store,k)? store[k] : null; },
        setItem: function(k,v){ store[k]=String(v); },
        removeItem: function(k){ delete store[k]; },
        clear: function(){ Object.keys(store).forEach(k=>delete store[k]); }
      };
    })();
    // Expose fetch (node-fetch) to the window
    dom.window.fetch = require('node-fetch');
    // Make jsdom window globals available to node environment so loaded scripts can reference them
    global.window = dom.window;
    global.document = dom.window.document;
    global.localStorage = dom.window.localStorage;
    global.fetch = dom.window.fetch;
    // wait briefly
    await new Promise(r=>setTimeout(r,50));
    // Load csv_analyzer.js into the environment
    loadScript(dom, path.join(__dirname,'../../frontend/static/js/csv_analyzer.js'));
    await new Promise(r=>setTimeout(r,200));

    // Test 1: Settings modal shows and saves values
    console.log('Test 1: settings modal');
    try{
      dom.window.showBatchSettingsModal();
      await new Promise(r=>setTimeout(r,50));
      const modal = dom.window.document.getElementById('csvBatchSettingsModal');
      if(!modal) throw new Error('Modal not created');
      const saveBtn = dom.window.document.getElementById('csvBatchSettingsSave');
      dom.window.document.getElementById('csv_batch_critical_max_input').value = '800';
      dom.window.document.getElementById('csv_batch_high_max_input').value = '700';
      saveBtn.click();
      await new Promise(r=>setTimeout(r,50));
      if(dom.window.localStorage.getItem('csv_batch_critical_max') !== '800') throw new Error('critical_max not saved');
      console.log('  ✓ settings saved to localStorage');
    }catch(e){ console.error('  ✗', e.message); process.exitCode = 2; }

    // Test 2: aggregate helper merges rows and tags suggested tokens
    console.log('Test 2: aggregation helper');
    try{
      // Insert fake parent batch listing endpoint by stubbing fetch
      dom.window.fetch = async function(url, opts){
        if(url.endsWith('/batches')){
          return { ok:true, json: async ()=> [{ assessment_id:'child-1', batch_meta:{ priority_label:'critical' } }, { assessment_id:'child-2', batch_meta:{ priority_label:'low' } }] };
        }
        if(url.indexOf('/api/v1/assessments/child-1')!==-1){
          return { ok:true, json: async ()=> ({ llm_rows: [ { row_index: 1, llm_summary: 'x' } ] }) };
        }
        if(url.indexOf('/api/v1/assessments/child-2')!==-1){
          return { ok:true, json: async ()=> ({ llm_rows: [ { row_index: 2, llm_summary: 'y' } ] }) };
        }
        return { ok:false };
      };
      // Ensure localStorage overrides are present
      dom.window.localStorage.setItem('csv_batch_critical_max','900');
      dom.window.localStorage.setItem('csv_batch_low_max','150');
      const merged = await dom.window.aggregateBatchesToDrawer('parent-1');
      if(!Array.isArray(merged)) throw new Error('merged not array');
      if(merged.length !== 2) throw new Error('merged length incorrect');
      if(merged[0]._batch_meta._suggested_max_tokens != 900) throw new Error('critical token cap not applied');
      if(merged[1]._batch_meta._suggested_max_tokens != 150) throw new Error('low token cap not applied');
      console.log('  ✓ aggregation merged and applied caps');
    }catch(e){ console.error('  ✗', e.message); process.exitCode = 2; }

    console.log('All JS tests completed');
  }catch(e){ console.error('Test harness failed', e); process.exitCode = 3; }
})();
