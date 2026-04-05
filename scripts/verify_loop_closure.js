const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

async function run() {
  const base = 'http://localhost:8080';
  const csvContent = 'process_name,file_path,sha256\nnotepad.exe,C:/Windows/notepad.exe,\n';
  const tmpCsvPath = path.join(__dirname, 'tmp_verify.csv');
  fs.writeFileSync(tmpCsvPath, csvContent, 'utf8');

  const results = { incidents: [], sboms: [], domSnapshot: null, errors: [] };
  results.console = [];

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  // capture console messages for diagnostics
  page.on('console', msg => {
    try { results.console.push({ type: msg.type(), text: msg.text() }); } catch (e) { /* ignore */ }
  });

  // Intercept network responses of interest
  page.on('response', async (resp) => {
    try {
      const url = resp.url();
      if (url.includes('/api/v1/incidents')) {
        const status = resp.status();
        let body = null;
        try { body = await resp.json(); } catch (e) { body = await resp.text(); }
        results.incidents.push({ url, status, body });
      }
      if (url.includes('/api/v1/test_helpers/create_incident')) {
        const status = resp.status();
        let body = null;
        try { body = await resp.json(); } catch (e) { body = await resp.text(); }
        results.incidents.push({ url, status, body, helper: true });
      }
      if (url.includes('/api/v1/sbom/upload')) {
        const status = resp.status();
        let body = null;
        try { body = await resp.json(); } catch (e) { body = await resp.text(); }
        results.sboms.push({ url, status, body });
      }
    } catch (err) {
      results.errors.push(String(err));
    }
  });

  try {
    // Navigate and set API key in localStorage so client fetches use it
    await page.goto(base + '/static/csv_analyzer.html', { waitUntil: 'domcontentloaded' });
    await page.evaluate(() => { localStorage.setItem('apiKey', 'devkey123'); });
    // reload to ensure any startup code sees the key if needed
    await page.reload({ waitUntil: 'domcontentloaded' });

    // Upload CSV
    const inputHandle = await page.waitForSelector('input[type=file]', { timeout: 5000 });
    await inputHandle.setInputFiles(tmpCsvPath);
    // Click the load button if present
    try { await page.click('#btnLoad'); } catch (e) { /* ignore if missing */ }

    // Wait for client to process the uploaded CSV and populate LAST_RESULTS
    try{
      await page.waitForFunction(() => (window.LAST_RESULTS && window.LAST_RESULTS.length>0) || (document.querySelectorAll('#tbody tr[data-row]').length>0), { timeout: 10000 });
    }catch(e){
      // fallback short sleep to allow UI to settle
      await page.waitForTimeout(1500);
    }

    // Open inline details by invoking the page's function directly
    await page.evaluate(() => { try { if (typeof openCsvRowDetails === 'function') { openCsvRowDetails(0); } } catch (e) { /* ignore */ } });

    // Snapshot DOM around push buttons
    const domSnap = await page.evaluate(() => {
      const btn = document.getElementById('pushIncident-0') || document.querySelector('[id^="pushIncident-"]');
      if (!btn) return { found: false, html: null };
      const wrapper = btn.closest('div') || btn.parentElement || btn;
      return { found: true, html: wrapper.outerHTML.substring(0, 2000) };
    });
    results.domSnapshot = domSnap;

    // Invoke pushIncidentForRow and pushSbomDeltaForRow in page context
    const incidentPromise = page.evaluate(() => {
      if (typeof pushIncidentForRow === 'function') {
        return pushIncidentForRow(0).catch(e => ({__err: String(e)}));
      }
      return {__err: 'pushIncidentForRow not defined'};
    });

    const sbomPromise = page.evaluate(() => {
      if (typeof pushSbomDeltaForRow === 'function') {
        return pushSbomDeltaForRow(0).catch(e => ({__err: String(e)}));
      }
      return {__err: 'pushSbomDeltaForRow not defined'};
    });

    // Wait for both to finish or timeout
    const [incRes, sbomRes] = await Promise.all([incidentPromise, sbomPromise]);
    results.incInvoke = incRes;
    results.sbomInvoke = sbomRes;

    // Allow time for network events to be captured
    await page.waitForTimeout(1500);

  } catch (err) {
    results.errors.push(String(err));
  } finally {
    await browser.close();
    // persist results
    const outPath = path.join(__dirname, 'verify_loop_closure_result.json');
    fs.writeFileSync(outPath, JSON.stringify(results, null, 2), 'utf8');
    console.log('Results saved to', outPath);
  }
}

run().catch(e => {
  console.error('Fatal error', e);
  process.exit(2);
});
