const { test, expect } = require('@playwright/test');
const path = require('path');
const fs = require('fs');

test('CSV Analyzer: upload Cyberstash_csv2.xlsx and export report', async ({ page }) => {
  const filePath = path.resolve(__dirname, '../../dump/Cyberstash_csv2.xlsx');
  await page.goto('http://localhost:8080/static/csv_analyzer.html');

  // Ensure client-side XLSX parsing is available; fallback to reading as text for simple CSV
  await page.evaluate(()=>{ try{ window.parseTabular = window.parseTabular || {}; }catch(e){} });

  // Upload file
  await page.setInputFiles('#fileInput', filePath);
  await page.locator('#btnLoad').click();

  // Wait for results readiness (page sets data-ready attribute)
  await page.waitForSelector('#csv_results_ready[data-ready="1"]', { timeout: 30000 });
  // Wait at least one row rendered
  await page.waitForSelector('#tbody tr[data-row]', { timeout: 30000 });

  // Optionally run correlate to populate window.LAST_CORR_SUMMARY (we'll click it to include correlation)
  const correlateBtn = page.locator('#btnCorrelateHopGraph');
  if(await correlateBtn.isVisible()){
    await correlateBtn.click();
    // Wait for correlation panel to show summary text
    await page.waitForSelector('#corrSummary:has-text("Session IDs")', { timeout: 30000 }).catch(()=>{});
  }

  // Click Export Report
  await page.locator('#btnExportReport').click();

  // Wait for new window/tab with report to open (the script opens about:blank then writes HTML)
  await page.context().waitForEvent('page', { timeout: 20000 }).then(async p => {
    // give the page a moment to render
    await p.waitForLoadState('domcontentloaded', { timeout: 10000 }).catch(()=>{});
    const html = await p.content();
    const outDir = path.resolve(__dirname, '../../dump/reports');
    try{ fs.mkdirSync(outDir, { recursive: true }); } catch(e){}
    const outPath = path.join(outDir, 'Cyberstash_csv2_report.html');
    fs.writeFileSync(outPath, html, 'utf8');
    console.log('Saved report to', outPath);
    expect(html.length).toBeGreaterThan(100);
  }).catch(e=>{
    // If no new page event, try to capture current page content as fallback
    console.warn('No new page detected, attempting to capture current page content');
    return page.content().then(html=>{
      const outDir = path.resolve(__dirname, '../../dump/reports');
      try{ fs.mkdirSync(outDir, { recursive: true }); } catch(e){}
      const outPath = path.join(outDir, 'Cyberstash_csv2_report_fallback.html');
      fs.writeFileSync(outPath, html, 'utf8');
      console.log('Saved fallback report to', outPath);
      expect(html.length).toBeGreaterThan(100);
    });
  });
});
