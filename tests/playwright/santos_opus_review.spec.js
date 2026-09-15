/**
 * santos_opus_review.spec.js
 *
 * Uploads the 4 Santos files with REAL qwen3:30b LLM (no mocks),
 * waits for full Tier-1 analysis, then captures screenshots of every
 * major UI component for Claude Opus 4.7 review.
 *
 * Screenshots saved to: test-results/opus-review/
 */

const { test, expect } = require('@playwright/test');
const path = require('path');
const fs = require('fs');

test.describe.configure({ mode: 'serial' });

const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:8000';
const BREACH_URL = BASE + '/static/breach.html';
const FILES_DIR = path.join(__dirname, '../../dump/test files');
const OUT_DIR = path.join(__dirname, '../../test-results/opus-review');

const AUTH_HEADERS = { 'X-API-Key': 'janusec-playwright-local', 'X-Tenant-ID': 'default' };

let assessmentId = '';

function ensureOutDir() {
  if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });
}

async function setAuth(page) {
  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'janusec-playwright-local');
    localStorage.setItem('tenantId', 'default');
    localStorage.setItem('selectedModel', 'qwen3:30b');
  });
}

// ── 1. Upload all 4 Santos files ─────────────────────────────────────────────
test('1. Upload 4 Santos files → assessment created', async ({ page }) => {
  test.setTimeout(180000);
  ensureOutDir();
  await setAuth(page);
  await page.goto(BREACH_URL);
  await expect(page.locator('[data-testid="br-drop-zone"]')).toBeVisible({ timeout: 10000 });

  const [fileChooser] = await Promise.all([
    page.waitForEvent('filechooser'),
    page.locator('[data-testid="br-drop-zone"]').click(),
  ]);
  await fileChooser.setFiles([
    path.join(FILES_DIR, 'janusec_endpoint_k8s_v1.ndjson'),
    path.join(FILES_DIR, 'janusec_cloud_identity_v1.json'),
    path.join(FILES_DIR, 'janusec_network_v1.csv'),
    path.join(FILES_DIR, 'janusec_enrichment_context_v1.xlsx'),
  ]);

  await page.waitForURL(/\?assessment=/, { timeout: 150000 });
  assessmentId = new URL(page.url()).searchParams.get('assessment') || '';
  expect(assessmentId).toBeTruthy();
  console.log('Assessment ID:', assessmentId);

  await page.screenshot({ path: path.join(OUT_DIR, '01_upload_complete.png'), fullPage: false });
});

// ── 2. Wait for Tier-1 LLM to complete, capture home page ────────────────────
test('2. Home page — clusters + hero after full LLM analysis', async ({ page }) => {
  test.setTimeout(300000);
  await setAuth(page);
  await page.goto(BREACH_URL + '?assessment=' + assessmentId);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 30000 });

  // Wait for lead cluster card to be populated (loading state has title even before LLM)
  await page.waitForFunction(() => {
    // Cards are rendered as <div id="br-card-{id}"> wrappers; title is inside
    const wrapper = document.querySelector('[id^="br-card-"]');
    if (!wrapper) return false;
    const title = wrapper.querySelector('.br-card__title');
    return title && title.textContent.trim().length > 10;
  }, null, { timeout: 60000 });

  await page.screenshot({ path: path.join(OUT_DIR, '02_home_clusters.png'), fullPage: true });

  // Log meta stats
  const metaText = await page.locator('[data-testid="br-meta"]').textContent().catch(() => '');
  console.log('Meta line:', metaText.trim());

  // Log card subtitles (the quality signal)
  const cards = await page.locator('[data-testid^="br-card-"]').all();
  for (let i = 0; i < cards.length; i++) {
    const title = await cards[i].locator('.br-card__title').textContent().catch(() => '');
    const subtitle = await cards[i].locator('.br-card__subtitle').textContent().catch(() => '');
    const verdict = await cards[i].locator('.br-card__verdict').textContent().catch(() => '');
    console.log(`Card ${i+1}: [${verdict.trim()}] ${title.trim()} | ${subtitle.trim().slice(0, 120)}`);
  }
});

// ── 3. HopGraph tab ───────────────────────────────────────────────────────────
test('3. HopGraph tab — screenshot', async ({ page }) => {
  test.setTimeout(60000);
  await setAuth(page);
  await page.goto(BREACH_URL + '?assessment=' + assessmentId + '&tab=hopgraph');
  await page.waitForSelector('svg', { timeout: 30000 });
  await page.waitForTimeout(2000); // let D3 settle
  await page.screenshot({ path: path.join(OUT_DIR, '03_hopgraph.png'), fullPage: true });

  const nodes = await page.locator('svg circle, svg .node').count();
  const edges = await page.locator('svg line, svg .link, svg path.link').count();
  console.log('HopGraph nodes:', nodes, 'edges:', edges);
});

// ── 4. Lead cluster detail (Tier-2 tab) ──────────────────────────────────────
test('4. Lead cluster detail — Tier-2 deep dive', async ({ page }) => {
  test.setTimeout(120000);
  await setAuth(page);

  // Get cluster list from API
  const res = await page.request.get(`${BASE}/api/v1/assessments/${assessmentId}`, {
    headers: AUTH_HEADERS,
  });
  const body = await res.json().catch(() => ({}));
  const clusters = body.correlation_clusters || body.clusters || [];
  const leadCluster = clusters[0];
  if (!leadCluster) { console.log('No clusters found — skipping'); return; }

  const clusterUrl = BREACH_URL + '?cluster=' + leadCluster.cluster_id + '&assessment=' + assessmentId;
  await page.goto(clusterUrl);
  await page.waitForSelector('.br-tier2, .tier2-wrap, [data-testid="tier2-wrap"]', { timeout: 30000 }).catch(() => {});
  await page.waitForTimeout(1500);
  await page.screenshot({ path: path.join(OUT_DIR, '04_cluster_detail.png'), fullPage: true });

  const stepCount = await page.locator('.persona-step, .tier2-step, .step-block').count();
  console.log('Tier-2 steps visible:', stepCount);
});

// ── 5. Evidence tab ───────────────────────────────────────────────────────────
test('5. Evidence tab — row table', async ({ page }) => {
  test.setTimeout(60000);
  await setAuth(page);
  await page.goto(BREACH_URL + '?assessment=' + assessmentId + '&tab=evidence');
  await page.waitForSelector('table, .ev-table, [data-testid="ev-table"]', { timeout: 20000 }).catch(() => {});
  await page.waitForTimeout(1000);
  await page.screenshot({ path: path.join(OUT_DIR, '05_evidence_tab.png'), fullPage: true });
});

// ── 6. Full-page home scroll (captures hero + all cards) ─────────────────────
test('6. Full home scroll — hero verdict + all cluster cards', async ({ page }) => {
  test.setTimeout(60000);
  await setAuth(page);
  await page.goto(BREACH_URL + '?assessment=' + assessmentId);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 20000 });
  await page.waitForTimeout(1000);

  // Capture hero section
  const heroEl = page.locator('[data-testid="br-hero"], .br-hero, .breach-hero').first();
  if (await heroEl.isVisible().catch(() => false)) {
    await heroEl.screenshot({ path: path.join(OUT_DIR, '06a_hero.png') });
  }

  // Full page
  await page.screenshot({ path: path.join(OUT_DIR, '06b_full_home.png'), fullPage: true });

  // Collect quality metrics for Opus review
  const allText = await page.evaluate(() => document.body.innerText);
  const verdicts = ['VALIDATED_BREACH','CONFIRMED_INTRUSION','LIKELY_COMPROMISE','SUSPICIOUS_ACTIVITY','INSUFFICIENT_TELEMETRY','BENIGN_EXPECTED'];
  const verdict = verdicts.find(v => allText.includes(v)) || 'NOT FOUND';
  const rowCount = (allText.match(/[\d,]+ rows analyzed/) || [''])[0];
  const sourceCount = (allText.match(/(\d+) sources/) || [''])[0];
  console.log('Verdict:', verdict);
  console.log('Row count:', rowCount);
  console.log('Source count:', sourceCount);
  console.log('Screenshots saved to:', OUT_DIR);
});
