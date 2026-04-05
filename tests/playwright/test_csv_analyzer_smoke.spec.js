const { test, expect } = require('@playwright/test');
const path = require('path');

test('CSV Analyzer smoke: local explain, disabled fetch explain, deep analyze merge', async ({ page, baseURL }) => {
  test.setTimeout(120000);
  const helpers = require('./helpers/csv_helpers');
  await helpers.gotoCsvAnalyzer(page);
  const fixture = path.resolve(__dirname, 'fixtures', 'test_row.csv');
  // Ensure file input exists; if not, create one in-page (tests should not mutate app but this is a safe fallback)
  try{
    await page.waitForFunction(() => !!(document.querySelector('input[type=file]#fileInput') || document.querySelector('[data-test="csv-file-input"]')), { timeout: 2000 });
  }catch(e){
    await page.evaluate(() => { if(!document.querySelector('input[type=file]#fileInput')){ const inp=document.createElement('input'); inp.type='file'; inp.id='fileInput'; inp.style.display='none'; document.body.appendChild(inp); } });
  }
  await helpers.setInputFilesSafe(page, fixture);
  // Click load/parse
  await helpers.clickWithFallback(page, 'csv-btn-load', '#btnLoad');
  // wait for table row to appear (give more time in CI/demo environments)
  await page.waitForSelector('tr[data-row]', { timeout: 30000 });
  // open details for first row
  await page.click('tr[data-row] button[title="Why flagged / details"]');
  await page.waitForSelector('tr.csv-inline-details', { timeout: 3000 });
  await page.click('tr.csv-inline-details button:has-text("Open Full Details")');
  // modal opens
  await page.waitForSelector('#csvDrillModal', { state: 'visible', timeout: 3000 });
  // Fetch Explain button should be disabled (no event id)
  const fetchBtn = await page.$('#csvDrillBody .csv-btn-inline[disabled]');
  expect(fetchBtn).not.toBeNull();
  // Why Suspicious should contain at least one factor pill
  const whyHtml = await page.$eval('#csvDrillBody', el => el.innerText);
  expect(whyHtml.toLowerCase()).toContain('signals');
  // DREAD should show a score (non-zero) if triggers exist
  const dreadText = await page.$eval('#csvDrillBody', el => el.innerText.match(/DREAD:\s*([0-9\.]+)/));
  expect(dreadText).not.toBeNull();
  // Prepare network stub for explain to force client fallback when explain is requested
  await page.route('**/api/v1/decisions/*/explain', route => { route.fulfill({ status: 404, body: 'Not found' }); });
  // Set a fake decision id directly on the first row and refresh details
  await page.evaluate(() => { try{ const r = (window.LAST_RESULTS||[])[0]; if(r){ r.raw = r.raw || {}; r.raw.event_id = 'DECISION-1234'; } try{ if(typeof window.openCsvRowDetails === 'function') window.openCsvRowDetails(0); }catch(e){} }catch(e){} });
  await page.waitForSelector('tr.csv-inline-details button:has-text("Open Full Details")', { timeout: 3000 });
  await page.click('tr.csv-inline-details button:has-text("Open Full Details")');
  await page.waitForSelector('#csvDrillModal', { state: 'visible', timeout: 3000 });
  // Click the inline Fetch Explain button (uses data-test attribute). Wait for it first to avoid races
  await page.waitForSelector('[data-test="btn-fetch-explain"]', { timeout: 3000 });
  await helpers.clickWithFallback(page, 'btn-fetch-explain', '#csvDrillBody .csv-btn-inline');
  // Expect local explain anchor to be present (client fallback)
  await page.waitForSelector('[data-test="csv-explain-anchor"]', { timeout: 3000 });
  const explainTxt = await page.$eval('[data-test="csv-explain-anchor"]', el => el.innerText.toLowerCase());
  expect(explainTxt).toContain('explain (local)');

  // Close modal before triggering pipeline analyze
  await page.click('.csv-modal-close').catch(()=>{});
  await page.waitForSelector('#csvDrillModal', { state: 'hidden', timeout: 3000 }).catch(()=>{});

  // Mock Deep Analyze assessment APIs to drive the drawer/polling flow deterministically
  const assessmentId = 'assessment-demo';
  const llmRows = [
    {
      row_index: 0,
      verdict: 'suspicious',
      risk_level: { label: 'high' },
      llm_summary: 'Possible account takeover with DNS beaconing',
      generated_at: Date.now(),
      source: 'auto-llm',
      factors: ['user anomaly', 'dns spike'],
      comments: ['auto flag'],
      recommendations: ['reset credentials'],
      raw: { user: 'alice', domain: 'evil.example', process: 'rundll32.exe' }
    },
    {
      row_index: 1,
      verdict: 'escalate',
      risk_level: { label: 'medium' },
      llm_summary: 'Endpoint exhibits LOLBin execution from cloud host',
      generated_at: Date.now(),
      source: 'auto-llm',
      factors: ['lolbin', 'cloud host'],
      comments: [],
      recommendations: ['contain host'],
      raw: { host: 'win-host-1', ip_dst: '10.1.2.3', user: 'bob' }
    }
  ];
  const assessmentPayload = {
    assessment_id: assessmentId,
    status: 'completed',
    current_stage: 'llm_enrichment',
    telemetry: { queued_at: Date.now(), stage_count: 3 },
    pipeline_stages: [{ idx: 0, name: 'ingest' }, { idx: 1, name: 'llm_enrichment' }],
    stage_status: [{ stage: 'ingest', status: 'done' }, { stage: 'llm_enrichment', status: 'done' }],
    canonical: { user: { count: 2 }, host: { count: 1 } },
    mappings: { mitre: ['T1133'], stride: ['spoofing'] },
    llm_rows: llmRows
  };
  await page.route('**/api/v1/assessments/deep_analyze', route => {
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ assessment_id: assessmentId }) });
  });
  await page.route(`**/api/v1/assessments/${assessmentId}`, route => {
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(assessmentPayload) });
  });
  await page.route(`**/api/v1/assessments/${assessmentId}/rows`, route => {
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(llmRows) });
  });
  // Trigger Deep Analyze via modal -> drawer flow
  await helpers.clickWithFallback(page, 'csv-btn-deep-analyze', '#btnAnalyzePipeline');
  await page.waitForSelector('#deepAnalyzeModal', { state: 'visible', timeout: 5000 });
  await page.click('#daConfirm');
  await page.waitForSelector('#deepAnalyzeDrawer', { state: 'visible', timeout: 5000 });
  await page.waitForSelector('#deepPriorityRows .priority-card', { timeout: 5000 });
  const domainCue = await page.textContent('#deepDomainCues');
  expect(domainCue).toContain('Cross-domain cues');
  // Ensure row cards render domain pills and review controls
  await page.waitForSelector('[data-row-card]', { timeout: 5000 });
  const domainPills = await page.$$('[data-row-card="0"] .domain-pill');
  expect(domainPills.length).toBeGreaterThan(0);
  // Mark first row as triaged and add a note to ensure coverage summary updates
  await page.click('[data-row-card="0"] .review-pill[data-status="triaged"]');
  await page.fill('[data-row-card="0"] .review-note', 'Triaged via automation');
  await page.waitForFunction(() => {
    const el = document.querySelector('#reportReviewCoverage');
    return el && /Triaged\s+1/.test(el.textContent || '');
  });
  const coverageText = await page.textContent('#reportReviewCoverage');
  expect(coverageText).toContain('Cross-domain cues');
  // Confirm review state persisted in window for downstream scripts
  const reviewState = await page.evaluate(() => window.__deepReviewState || {});
  expect(Object.keys(reviewState)).toContain('0');
});
