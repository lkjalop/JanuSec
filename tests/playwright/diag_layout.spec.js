const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

const BASE = 'http://127.0.0.1:8080';
const DUMP_DIR = path.resolve('dump/test files');
const FILES_V11 = [
  { file: 'janusec_net_c2_bgp.v1.1.csv', mime: 'text/csv' },
  { file: 'janusec_okta_m365_events.v1.1.json', mime: 'application/json' },
  { file: 'janusec_ep_endpoint.v1.1.xlsx', mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' },
];

test('layout diagnostic after full analysis', async ({ page }) => {
  test.setTimeout(180000);
  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'devkey123');
    localStorage.setItem('tenantId', 'default');
  });
  await page.goto(`${BASE}/static/investigate.html`, { waitUntil: 'domcontentloaded' });
  const files = FILES_V11.map(({file, mime}) => {
    const fp = path.join(DUMP_DIR, file);
    return { name: file, mimeType: mime, buffer: fs.readFileSync(fp) };
  });
  await page.locator('#fileInput').setInputFiles(files);
  await page.waitForSelector('#sourceList .source-item', { timeout: 10000 });
  await page.click('#btnAnalyze');
  // Wait for FULL analysis: reportLoading disappears (reportContent or reportEmpty shows)
  await page.waitForFunction(() => {
    var rl = document.getElementById('reportLoading');
    return rl && window.getComputedStyle(rl).display === 'none';
  }, { timeout: 120000 });

  const info = await page.evaluate(() => {
    function elInfo(id) {
      var e = document.getElementById(id);
      if (!e) return {exists: false};
      var r = e.getBoundingClientRect();
      var s = window.getComputedStyle(e);
      return {exists: true, display: s.display, h: Math.round(r.height), w: Math.round(r.width), top: Math.round(r.top), display_style: e.style.display};
    }
    return {
      investigateLayout: (() => { var e = document.querySelector('.investigate-layout'); if(!e) return null; var r=e.getBoundingClientRect(); return {h:Math.round(r.height),w:Math.round(r.width),top:Math.round(r.top)}; })(),
      tabScroll: (() => { var e = document.querySelector('.tab-scroll'); if(!e) return null; var r=e.getBoundingClientRect(); return {h:Math.round(r.height),top:Math.round(r.top)}; })(),
      reportContent: elInfo('reportContent'),
      reportLoading: elInfo('reportLoading'),
      reportBody: elInfo('reportBody'),
      clusterListPanel: elInfo('clusterListPanel'),
      operatorQueuePanel: elInfo('operatorQueuePanel'),
    };
  });
  console.log(JSON.stringify(info, null, 2));
  await page.screenshot({ path: 'tmp_diag_screenshot.png', fullPage: false });
});
