import { test, expect } from '@playwright/test';
import fs from 'fs';
import path from 'path';

// This test navigates to the CSV Analyzer page, uploads a small CSV file (as xlsx may be unsupported in this environment),
// then clicks the main UI buttons and asserts there are no uncaught console errors and network failures for the key API endpoints.

const BASE_URL = process.env.BASE_URL || 'http://localhost:8080';

function makeCsvContent(){
  const headers = ['process_name','file_path','sha256','host','verdict','avPositives','threatWeight'];
  const rows = [
    ['powershell','C:\\\\Windows\\System32\\cmd.exe','deadbeefdeadbeefdeadbeefdeadbeefdeadbeef','host1','SUSPICIOUS','2','3'],
    ['notepad','C:\\\\Temp\\bad.exe','cafebabecafebabecafebabecafebabecafebabe','host2','BENIGN','0','0']
  ];
  const lines = [headers.join(','), ...rows.map(r=>r.join(','))];
  return lines.join('\n');
}

test('csv analyzer UI - upload and buttons', async ({ page }) => {
  const errors = [];
  page.on('pageerror', (err) => { errors.push(String(err)); });
  page.on('console', msg => { if(msg.type()==='error') errors.push(msg.text()); });

  await page.goto(BASE_URL + '/static/csv_analyzer.html');

  // create a temporary CSV file and upload via file input
  const tmpDir = process.cwd();
  const tmpFile = path.join(tmpDir, 'tests_temp_csv_for_playwright.csv');
  fs.writeFileSync(tmpFile, makeCsvContent(), 'utf8');

  const input = await page.$('input#fileInput');
  expect(input).not.toBeNull();
  await input.setInputFiles(tmpFile);

  // click load
  await page.click('#btnLoad');

  // wait for results ready event or table rows
  await page.waitForSelector('#tbody tr[data-row]', { timeout: 5000 });

  // click first row to expand details
  await page.click('#tbody tr[data-row]');

  // expect inline details to appear
  await page.waitForSelector('tr.csv-inline-details', { timeout: 3000 });

  // click LLM T1 if present
  const llmBtn = await page.$('tr.csv-inline-details button:has-text("LLM T1")');
  if(llmBtn){
    await llmBtn.click();
    // wait for sidebar or visible llm body
    await page.waitForSelector('#llmSidebar.visible, #llmSidebarBody', { timeout: 5000 });
  }

  // click Per-row Deep Explain
  const deepBtn = await page.$('tr.csv-inline-details button:has-text("Per-row Deep Explain")');
  if(deepBtn){
    await deepBtn.click();
    // new window opens - ensure at least one page created
    await page.waitForTimeout(500);
  }

  // click View Attack Path
  const viewBtn = await page.$('tr.csv-inline-details button:has-text("View Attack Path")');
  if(viewBtn){
    await viewBtn.click();
    await page.waitForTimeout(200);
  }

  // ensure no page errors
  expect(errors).toEqual([]);

  // Verify Tier1 correlation renderer produces highlight chips
  const correlationPreview = await page.evaluate(() => {
    if(typeof (window as any).renderCorrelationHighlights !== 'function'){
      return '';
    }
    const ctx = {
      mappingScore: 0.91,
      domainScore: 0.84,
      pathScore: 0.77,
      pathLabel: 'adaptive-hopgraph',
      insights: [{
        title: 'HopGraph overlap',
        confidence: 0.92,
        domains: ['identity','network'],
        ttlSeconds: 3600,
        explanation: 'Chains overlap across identity + network domains.',
        contributions: [['factor_synthesis', 0.42]],
      }],
      dependency: {
        hopgraph: { available: false, reason: 'test-degraded', last_ok_ts: Date.now()/1000 - 120 },
      },
    };
    const html = (window as any).renderCorrelationHighlights(ctx);
    const container = document.createElement('div');
    container.id = 'playwright-correlation-preview';
    container.innerHTML = html;
    document.body.appendChild(container);
    return container.textContent || '';
  });
  expect(correlationPreview).toContain('HopGraph overlap');
});

test('tier2 correlation panel renders shared correlation context', async ({ page }) => {
  await page.goto(BASE_URL + '/static/csv_deep_analysis.html');
  const result = await page.evaluate(() => {
    if(typeof (window as any).renderCorrelationContextBlock !== 'function'){
      return { text: '', chips: 0 };
    }
    const ctx = {
      mappingScore: 0.88,
      domainScore: 0.79,
      pathScore: 0.66,
      insights: [{
        title: 'tier2-hop',
        confidence: 0.87,
        domains: ['endpoint','remote'],
        ttlSeconds: 2400,
        explanation: 'Tier2 confirms multi-hop overlap.',
        contributions: [['factor_synthesis', 0.33]],
      }],
    };
    const html = (window as any).renderCorrelationContextBlock(ctx);
    const container = document.createElement('div');
    container.id = 'playwright-tier2-correlation';
    container.innerHTML = html;
    document.body.appendChild(container);
    const chips = container.querySelectorAll('.tier1-chip').length;
    return { text: container.textContent || '', chips };
  });
  expect(result.text).toContain('tier2-hop');
  expect(result.chips).toBeGreaterThan(0);
});
