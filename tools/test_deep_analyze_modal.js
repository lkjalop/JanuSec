const fs = require('fs');
const jsdom = require('jsdom');
const { JSDOM } = jsdom;

(async () => {
  try {
    const html = fs.readFileSync('tmp_csv_analyzer.html','utf8');
    const dom = new JSDOM(html, { runScripts: 'dangerously', resources: 'usable' });
    const window = dom.window;
    // Inject threat_ranking.js directly so we don't rely on network fetches
    try {
      const trCode = fs.readFileSync('frontend/static/js/threat_ranking.js', 'utf8');
      const scriptEl = window.document.createElement('script');
      scriptEl.textContent = trCode;
      window.document.head.appendChild(scriptEl);
    } catch (e) {
      // ignore if file missing; test will reflect absence
    }
    // prepare a simple row set
    const rows = [{process_name:'proc.exe', file_path:'/tmp/a', host:'host1', verdict:'SUSPICIOUS'}];
    window.showDeepAnalyzeModal && window.showDeepAnalyzeModal(rows);
    const modal = window.document.getElementById('deepAnalyzeModal');
    const visible = modal && modal.style.display && modal.style.display !== 'none';
    console.log('modal_visible=' + !!visible);
    console.log('threat_ranking_present=' + (typeof window.ThreatRanking !== 'undefined'));
  } catch (e) {
    console.error('error', e && e.message);
    process.exit(2);
  }
})();
