const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

const BASE_URL = process.env.BASE_URL || 'http://localhost:8080';
function makeCsvContent(){
  const headers = ['process_name','file_path','sha256','host','verdict','avPositives','threatWeight'];
  const rows = [
    ['powershell','C:\\Windows\\System32\\cmd.exe','deadbeefdeadbeefdeadbeefdeadbeefdeadbeef','host1','SUSPICIOUS','2','3'],
    ['notepad','C:\\Temp\\bad.exe','cafebabecafebabecafebabecafebabecafebabe','host2','BENIGN','0','0']
  ];
  const lines = [headers.join(','), ...rows.map(r=>r.join(','))];
  return lines.join('\n');
}

test('csv analyzer UI - upload and buttons', async ({ page }) => {
  const errors = [];
  page.on('pageerror', (err) => { errors.push(String(err)); });
  page.on('console', msg => { if(msg.type()==='error') errors.push(msg.text()); });

  await page.goto(BASE_URL + '/static/csv_analyzer.html');

  const tmpDir = process.cwd();
  const tmpFile = path.join(tmpDir, 'tests_temp_csv_for_playwright.csv');
  fs.writeFileSync(tmpFile, makeCsvContent(), 'utf8');

  const input = await page.$('input#fileInput');
  expect(input).not.toBeNull();
  await input.setInputFiles(tmpFile);

  await page.click('#btnLoad');
  await page.waitForSelector('#tbody tr[data-row]', { timeout: 5000 });
  await page.click('#tbody tr[data-row]');
  await page.waitForSelector('tr.csv-inline-details', { timeout: 3000 });

  const llmBtn = await page.$('tr.csv-inline-details button:has-text("LLM T1")');
  if(llmBtn){
    await llmBtn.click();
    await page.waitForSelector('#llmSidebar.visible, #llmSidebarBody', { timeout: 5000 }).catch(()=>{});
  }

  const deepBtn = await page.$('tr.csv-inline-details button:has-text("Per-row Deep Explain")');
  if(deepBtn){
    await deepBtn.click();
    await page.waitForTimeout(500);
  }

  const viewBtn = await page.$('tr.csv-inline-details button:has-text("View Attack Path")');
  if(viewBtn){
    await viewBtn.click();
    await page.waitForTimeout(200);
  }

  expect(errors).toEqual([]);
});
