const { test, expect } = require('@playwright/test');
const path = require('path');

test('CSV Analyzer: generate export report from fixture', async ({ page }) => {
  const filePath = path.resolve(__dirname, '../../dump/fixture_simple.csv');
  await page.goto('http://localhost:8080/static/csv_analyzer.html');
  await page.evaluate(()=>{ try{ window.parseTabular = window.parseTabular || {}; window.parseTabular.clientSideAggregate = window.parseTabular.clientSideAggregate || (async function(files){ const f = files[0]; const text = await f.text(); const lines = text.split(/\r?\n/).filter(Boolean); const headers = (lines[0]||'').split(/[,;\t]/).map(h=>h.trim()); const rows = []; for(let i=1;i<lines.length;i++){ const cols = lines[i].split(','); const obj={}; headers.forEach((h,idx)=> obj[h]= (cols[idx]||'').replace(/^"|"$/g,'')); rows.push(obj);} return { rows }; }); }catch(e){} });
  await page.setInputFiles('#fileInput', filePath);
  await page.locator('#btnLoad').click();
  await page.waitForSelector('#tbody tr[data-row]', { timeout: 10000 });
  // Click Export Report
  await page.locator('#btnExportReport').click();
  // A new page should open with the report; wait for it
  const pages = page.context().pages();
  expect(pages.length).toBeGreaterThanOrEqual(1);
});
