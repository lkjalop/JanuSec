import { test, expect } from '@playwright/test';

test('Deep Analyze UI flow shows drawer with LLM rows', async ({ page }) => {
  // Seed LAST_RESULTS into localStorage before loading the page so it renders on load
  const rows = [
    { process_name: 'rundll32', file_path: '/windows/system32/rundll32.exe', sha256: 'deadbeef', host: 'host1', verdict: 'SUSPICIOUS', factors: ['lolbin'], raw: { event_id: 'evt-1' } }
  ];
  // Load the CSV Analyzer static page, then set localStorage and reload to ensure UI picks it up
  await page.goto('http://localhost:8080/static/csv_analyzer.html');
  await page.evaluate((r) => { try{ localStorage.setItem('csv_last_results', JSON.stringify(r)); localStorage.setItem('csv_last_results_ts', String(Date.now()/1000)); }catch(e){ } }, rows);
  await page.reload();
  // Wait for the in-page helper to be available, then render rows directly for reliability
  await page.waitForFunction(() => typeof window.ensureTbodyRowsFromList === 'function', { timeout: 5000 });
  await page.evaluate((r) => { try{ window.LAST_RESULTS = r; window.ensureTbodyRowsFromList(r); }catch(e){ /* ignore */ } }, rows);

  // Wait for results to render
  await page.waitForSelector('#tbody tr[data-row]');

    // Start Deep Analyze directly via the client helper to avoid modal timing
    await page.evaluate(() => { try{ if(typeof window.initiateDeepAnalyze === 'function'){ window.initiateDeepAnalyze({ auto_llm: true, max_rows: 10 }); } }catch(e){ /* ignore */ } });
    // Capture console logs to help debugging
    page.on('console', msg => { try{ console.log('PAGE LOG:', msg.text()); }catch(_){} });

    // Wait for the client to set currentAssessmentId (means request created)
    await page.waitForFunction(() => !!(window.currentAssessmentId || window.LAST_DEEP_ANALYZE || window.LAST_CORR_SUMMARY), { timeout: 10000 });

    // Wait for drawer to appear and show a row card
    await page.waitForSelector('#deepAnalyzeDrawer', { timeout: 15000 });
  const content = await page.$('#deepAnalyzeRows');
  expect(content).not.toBeNull();

  // Ensure a card appears
  const card = await page.$('#deepAnalyzeRows div');
  expect(card).not.toBeNull();
});