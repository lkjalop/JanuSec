const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

(async function(){
  try{
    const p = path.resolve(process.cwd(), 'csv_analyzer_served.html');
    if(!fs.existsSync(p)){
      console.error(JSON.stringify({ok:false, reason:'csv_analyzer_served.html not found'}));
      process.exit(1);
    }
    const html = fs.readFileSync(p,'utf8');
    const dom = new JSDOM(html, { runScripts: 'dangerously', resources: 'usable', url: 'http://localhost:8080/' });
    const { window } = dom;
    // Wait a short moment for inline scripts to execute
    await new Promise(r => setTimeout(r, 100));
    const showFn = window.showDeepAnalyzeModal;
    if(typeof showFn !== 'function'){
      console.log(JSON.stringify({ok:false, reason:'showDeepAnalyzeModal not found'}));
      process.exit(0);
    }
    try{
      showFn([{ process_name:'proc', file_path:'/tmp/f', host:'host1' }]);
    }catch(e){
      console.log(JSON.stringify({ok:false, reason:'showDeepAnalyzeModal threw', error: String(e)}));
      process.exit(0);
    }
    const modal = window.document.getElementById('deepAnalyzeModal');
    const display = modal ? (modal.style.display || window.getComputedStyle(modal).display) : null;
    const mappingPreview = window.document.getElementById('daMappingPreview');
    console.log(JSON.stringify({ok:true, modal_display: display, mapping_preview_exists: !!mappingPreview}));
    process.exit(0);
  }catch(e){ console.error(JSON.stringify({ok:false, error: String(e)})); process.exit(1); }
})();