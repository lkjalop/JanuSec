/**
 * three_file_upload.spec.js
 *
 * Quality-assessment E2E spec using the real v1.1 test datasets.
 * Uploads all three files to breach.html (no LLM mocking — real pipeline),
 * waits for analysis to complete, then captures and logs the actual output
 * of every major UI component for qualitative review.
 *
 * Reports on:
 *   1. Upload + pipeline mechanics (rows, clusters, timing)
 *   2. Breach answer hero (verdict, confidence, severity)
 *   3. Executive summary text quality
 *   4. HopGraph D3 visualization (node/edge counts, color legend)
 *   5. Temporal RAG swimlane (row counts, timeline spans)
 *   6. Per-cluster lead card content (title, subtitle, evidence chain)
 *   7. Tier 2 deep-dive tab (persona steps, EXPAND panel, IOCs)
 *   8. Row coverage disclosure (⚠ warning when at 2000 limit)
 *
 * Files: C:\AI\janusec\dump\test files\
 *   - janusec_net_c2_bgp.v1.1.csv      (70 network rows)
 *   - janusec_okta_m365_events.v1.1.json (88 Okta/M365 rows)
 *   - janusec_ep_endpoint.v1.1.xlsx     (83 endpoint rows)
 *
 * Run:
 *   PLAYWRIGHT_BASE_URL=http://127.0.0.1:8000 npx playwright test tests/playwright/three_file_upload.spec.js --headed
 */

const { test, expect } = require('@playwright/test');
const path = require('path');
const fs   = require('fs');

test.describe.configure({ mode: 'serial' });

const BASE      = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:8000';
const BREACH    = BASE + '/static/breach.html';
const DUMP_DIR  = path.join(__dirname, '../../dump/test files');
const NET_CSV   = path.join(DUMP_DIR, 'janusec_net_c2_bgp.v1.1.csv');
const OKTA_JSON = path.join(DUMP_DIR, 'janusec_okta_m365_events.v1.1.json');
const EP_XLSX   = path.join(DUMP_DIR, 'janusec_ep_endpoint.v1.1.xlsx');

// Shared across serial tests
let assessmentId = '';
let firstClusterId = '';
const capturedOutput = {};

function log(section, content) {
  const bar = '─'.repeat(70);
  console.log(`\n${'═'.repeat(70)}`);
  console.log(`  QUALITY REPORT: ${section}`);
  console.log(bar);
  if (typeof content === 'object') {
    Object.entries(content).forEach(([k, v]) => console.log(`  ${k}: ${v}`));
  } else {
    const lines = String(content).split('\n');
    lines.slice(0, 40).forEach(l => console.log(`  ${l}`));
    if (lines.length > 40) console.log(`  ... (${lines.length - 40} more lines)`);
  }
  console.log('═'.repeat(70));
}

// ── 0. Pre-flight: verify test files exist ────────────────────────────────────
test('0. Verify test files exist on disk', async () => {
  for (const [label, fp] of [['NET CSV', NET_CSV], ['OKTA JSON', OKTA_JSON], ['EP XLSX', EP_XLSX]]) {
    expect(fs.existsSync(fp), `${label} not found at: ${fp}`).toBe(true);
    const stat = fs.statSync(fp);
    console.log(`  ${label}: ${fp} (${(stat.size / 1024).toFixed(1)} KB)`);
  }
});

// ── 1. Upload zone renders on bare breach.html ────────────────────────────────
test('1. Upload zone renders', async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'janusec-playwright-local');
    localStorage.setItem('tenantId', 'default');
  });
  await page.goto(BREACH);
  // Accept either new upload zone or old drop zone selector
  const zone = page.locator('[data-testid="br-drop-zone"], [data-testid="br-upload"], .upload-zone, #uploadZone, .drop-zone').first();
  await expect(zone).toBeVisible({ timeout: 10000 });
  log('Upload Zone', 'Visible ✓');
});

// ── 2. Upload 3 files → full pipeline runs, redirect to ?assessment= ──────────
test('2. Upload 3 files → assessment redirect (real pipeline, no LLM mock)', async ({ page }) => {
  test.setTimeout(300000); // 5 min — real LLM may be slow

  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'janusec-playwright-local');
    localStorage.setItem('tenantId', 'default');
  });

  const errors = [];
  page.on('pageerror', err => { if (!err.message.includes('favicon')) errors.push(err.message); });

  await page.goto(BREACH);

  // Find the file input — try multiple selectors
  const fileInput = page.locator('input[type="file"]').first();
  await expect(fileInput).toBeAttached({ timeout: 10000 });
  await fileInput.setInputFiles([NET_CSV, OKTA_JSON, EP_XLSX]);

  // Wait up to 5 min for redirect with ?assessment=
  await page.waitForURL(/\?assessment=/, { timeout: 270000 });

  const url  = page.url();
  assessmentId = new URL(url).searchParams.get('assessment') || '';
  expect(assessmentId, 'Assessment ID must be non-empty after upload').toBeTruthy();

  log('Pipeline Redirect', {
    'URL': url.slice(0, 100),
    'Assessment ID': assessmentId,
    'JS Errors': errors.length === 0 ? 'None ✓' : errors.slice(0, 3).join('; '),
  });

  if (errors.length > 0) console.warn('  JS ERRORS detected:', errors);
});

// ── 3. Home page meta-line: N sources / M rows / K clusters ──────────────────
test('3. Home page meta-line shows real counts', async ({ page }) => {
  test.setTimeout(120000);

  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'janusec-playwright-local');
    localStorage.setItem('tenantId', 'default');
  });

  await page.goto(`${BREACH}?assessment=${assessmentId}`);

  // Wait for meta line or any summary indicator
  const metaSel = '[data-testid="br-meta"], .br-meta, #br-meta, .meta-line, .assessment-meta';
  await page.waitForSelector(metaSel, { timeout: 30000 }).catch(() => {});

  // Capture whatever counts are in the page
  const pageSummary = await page.evaluate(() => {
    const getText = (sel) => { const el = document.querySelector(sel); return el ? el.textContent.trim() : null; };
    return {
      metaLine: getText('[data-testid="br-meta"]') || getText('.br-meta') || getText('#br-meta') || getText('.meta-line'),
      sourceCount: getText('[data-testid="br-source-count"]') || getText('.br-source-count'),
      rowCount: getText('[data-testid="br-row-count"]') || getText('.br-row-count'),
      clusterCount: getText('[data-testid="br-cluster-count"]') || getText('.br-cluster-count'),
      heroText: getText('[data-testid="br-hero"]') || getText('.br-hero') || getText('#br-hero'),
      pageTitle: document.title,
    };
  });

  log('Meta-Line Counts', pageSummary);
  capturedOutput.meta = pageSummary;

  // Soft assertion: page should have loaded something meaningful
  const pageText = await page.locator('body').textContent();
  expect(pageText.length, 'Page should have substantive content after load').toBeGreaterThan(200);
});

// ── 4. Breach answer hero ─────────────────────────────────────────────────────
test('4. Breach answer hero — verdict, confidence, coverage warning', async ({ page }) => {
  test.setTimeout(60000);

  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'janusec-playwright-local');
    localStorage.setItem('tenantId', 'default');
  });

  await page.goto(`${BREACH}?assessment=${assessmentId}`);
  await page.waitForLoadState('networkidle');

  const heroData = await page.evaluate(() => {
    const allText = document.body.innerText;
    const selectors = {
      hero: '[data-testid="br-hero"]',
      heroVerdict: '.br-hero__verdict, .hero-verdict, .verdict-label',
      heroConf: '.br-hero__confidence, .hero-confidence',
      coverageWarn: '.br-coverage-warning, [data-coverage-warning]',
    };
    const result = {};
    for (const [k, sel] of Object.entries(selectors)) {
      const el = document.querySelector(sel);
      result[k] = el ? el.textContent.trim().slice(0, 200) : null;
    }
    // Search for verdict keywords in full page text
    const verdicts = ['VALIDATED_BREACH', 'CONFIRMED_INTRUSION', 'LIKELY_COMPROMISE',
                      'SUSPICIOUS_ACTIVITY', 'INSUFFICIENT_TELEMETRY', 'BENIGN_EXPECTED'];
    result.verdictInPage = verdicts.find(v => allText.includes(v)) || 'NOT FOUND';
    result.coverageWarningInPage = allText.includes('⚠') && allText.includes('analyzed') ? 'YES ⚠' : 'no';
    return result;
  });

  log('Breach Answer Hero', heroData);
  capturedOutput.hero = heroData;

  const validVerdicts = ['VALIDATED', 'CONFIRMED', 'LIKELY', 'SUSPICIOUS', 'INSUFFICIENT', 'BENIGN'];
  expect(validVerdicts.some(v => (heroData.heroVerdict || '').toUpperCase().includes(v) || heroData.verdictInPage !== 'NOT FOUND'), 'Hero should show a valid verdict').toBe(true);
  expect(heroData.coverageWarningInPage, '241-row upload should not show a row-limit coverage warning').toBe('no');
});

// ── 5. Executive summary text quality ────────────────────────────────────────
test('5. Executive summary — full text capture for quality review', async ({ page }) => {
  test.setTimeout(180000); // LLM call

  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'janusec-playwright-local');
    localStorage.setItem('tenantId', 'default');
  });

  await page.goto(`${BREACH}?assessment=${assessmentId}`);

  // Wait for exec summary block
  const execSel = '[data-testid="br-exec-block"], #br-exec-block, #br-exec-det, .exec-summary, .executive-summary';
  const execEl = await page.waitForSelector(execSel, { timeout: 60000 }).catch(() => null);

  let execText = '(not found)';
  if (execEl) {
    execText = (await execEl.textContent()).trim();
  } else {
    // Fallback: scan all text blocks
    execText = await page.evaluate(() => {
      const candidates = Array.from(document.querySelectorAll('p, .summary, .narrative, [class*="exec"]'));
      const long = candidates.filter(el => el.textContent.trim().length > 100);
      return long.slice(0, 3).map(el => el.textContent.trim()).join('\n\n---\n\n');
    });
  }

  log('Executive Summary Text', execText || '(empty)');
  capturedOutput.execSummary = execText;
  await page.screenshot({ path: 'test-results/three-file-breach-home.png', fullPage: true });

  // Quality assertions
  expect(execText.length, 'Executive summary should have meaningful content').toBeGreaterThan(50);
  expect(execText, 'Executive summary should not expose backend cluster IDs').not.toMatch(/cluster-\d+/i);
  expect(execText, 'Executive summary should use newspaper-style breach answer copy').toMatch(/validated breach|highest finding|no validated breach/i);
  const hasCapitalWords = /[A-Z]{3,}/.test(execText);
  console.log(`  Capital acronyms present: ${hasCapitalWords}`);
});

// ── 6. Lead clusters — card titles, subtitles, verdict, evidence ──────────────
test('6. Lead cluster cards — title, subtitle, verdict, evidence chain', async ({ page }) => {
  test.setTimeout(120000);

  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'janusec-playwright-local');
    localStorage.setItem('tenantId', 'default');
  });

  await page.goto(`${BREACH}?assessment=${assessmentId}`);
  await page.waitForLoadState('networkidle');

  // Wait for cluster cards
  const cardSel = '[data-testid^="br-card-"], .br-card, .cluster-card, .lead-card, [class*="cluster"]';
  await page.waitForSelector(cardSel, { timeout: 30000 }).catch(() => {});

  const clusterCards = await page.evaluate(() => {
    const cards = Array.from(document.querySelectorAll('[data-testid^="br-card-"], .br-card, .cluster-card, .lead-card'));
    return cards.slice(0, 5).map(card => {
      const get = (sel) => { const el = card.querySelector(sel); return el ? el.textContent.trim().slice(0, 150) : null; };
      return {
        id: card.getAttribute('data-testid') || card.id || card.className.split(' ')[0],
        title: get('.br-card__title, .card-title, .cluster-title, h3, h4') || get('strong'),
        subtitle: get('.br-card__subtitle, .card-subtitle, .cluster-subtitle, p'),
        verdict: get('.verdict, .br-verdict, [class*="verdict"]'),
        severity: get('.severity, .br-severity, [class*="severity"]'),
        confidence: get('.confidence, .br-confidence, [class*="confidence"]'),
        evidenceChain: get('.evidence-chain, .br-evidence, [class*="evidence"]'),
        gating: get('.gate-banner, .hvr-gate, [class*="gate"]'),
      };
    });
  });

  // Store first cluster ID for tier-2 tests
  if (clusterCards.length > 0) {
    const firstCard = clusterCards[0];
    firstClusterId = (firstCard.id || '').replace('br-card-', '');
  }

  log('Cluster Cards (first 5)', clusterCards.length > 0
    ? clusterCards.map((c, i) => `\n  [${i+1}] ID=${c.id}\n      Title: ${c.title}\n      Subtitle: ${c.subtitle}\n      Verdict: ${c.verdict} | Severity: ${c.severity}\n      Evidence: ${c.evidenceChain}\n      Gate: ${c.gating}`).join('\n')
    : '(no cluster cards found)');

  capturedOutput.clusterCards = clusterCards;

  // At least some cards should exist
  const pageText = await page.locator('body').textContent();
  const hasClusterIndicators = /cluster|incident|investigation|activity/i.test(pageText);
  expect(hasClusterIndicators, 'Page should contain cluster/incident content').toBe(true);
});

// ── 7. HopGraph D3 swimlane ───────────────────────────────────────────────────
test('7. HopGraph D3 — node count, edge count, legend, colors', async ({ page }) => {
  test.setTimeout(60000);

  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'janusec-playwright-local');
    localStorage.setItem('tenantId', 'default');
  });

  await page.goto(`${BREACH}?assessment=${assessmentId}`);
  await page.waitForLoadState('networkidle');

  // Wait for SVG/canvas to render
  await page.waitForSelector('svg, canvas, [id*="hopgraph"], [id*="swim"], [class*="hop"], [class*="swim"]',
    { timeout: 20000 }).catch(() => {});
  await page.waitForTimeout(2000); // let D3 settle

  const graphData = await page.evaluate(() => {
    const result = {};

    // Hopgraph SVG
    const svgEls = Array.from(document.querySelectorAll('svg'));
    result.svgCount = svgEls.length;

    // Count nodes and edges in D3 SVGs
    const circles = document.querySelectorAll('svg circle').length;
    const lines   = document.querySelectorAll('svg line').length;
    const rects   = document.querySelectorAll('svg rect').length;
    const texts   = document.querySelectorAll('svg text').length;
    result.nodes = circles + rects;
    result.edges = lines;
    result.svgTexts = texts;

    // Legend items
    const legend = document.querySelector('.hopgraph-legend, [class*="legend"], #hopgraph-legend');
    result.legendText = legend ? legend.textContent.trim().slice(0, 200) : null;
    result.legendItems = document.querySelectorAll('.hopgraph-legend .pill, [class*="legend"] span, [class*="legend"] li').length;

    // Swimlane / timeline
    const swimlane = document.querySelector('#swimlane, [id*="swim"], [class*="swim"], [class*="timeline"]');
    result.swimlanePresent = !!swimlane;
    result.swimlaneText = swimlane ? swimlane.textContent.trim().slice(0, 200) : null;

    // HopGraph overlay stream panel
    const streamPanel = document.getElementById('hopgraphStreamPanel');
    result.streamPanelPresent = !!streamPanel;
    result.streamStatus = document.getElementById('hopgraphStreamStatus')?.textContent || null;

    // Edge colors in SVG (look for stroke attributes)
    const coloredEdges = Array.from(document.querySelectorAll('svg line[stroke], svg path[stroke]'));
    const colors = [...new Set(coloredEdges.map(e => e.getAttribute('stroke')).filter(Boolean))];
    result.edgeColors = colors.slice(0, 8);

    return result;
  });

  log('HopGraph D3 Visualization', graphData);
  capturedOutput.hopgraph = graphData;

  console.log(`  SVGs on page: ${graphData.svgCount}`);
  console.log(`  Nodes (circles+rects): ${graphData.nodes}`);
  console.log(`  Edges (lines): ${graphData.edges}`);
  console.log(`  Edge colors: ${(graphData.edgeColors || []).join(', ')}`);
  console.log(`  Legend items: ${graphData.legendItems}`);
  console.log(`  Swimlane present: ${graphData.swimlanePresent}`);
  console.log(`  Stream panel: ${graphData.streamPanelPresent}, status: ${graphData.streamStatus}`);
});

// ── 8. Temporal RAG swimlane quality ─────────────────────────────────────────
test('8. Temporal RAG swimlane — timeline, row markers, time span', async ({ page }) => {
  test.setTimeout(60000);

  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'janusec-playwright-local');
    localStorage.setItem('tenantId', 'default');
  });

  await page.goto(`${BREACH}?assessment=${assessmentId}`);
  await page.waitForLoadState('networkidle');

  const swimData = await page.evaluate(() => {
    const result = {};
    // Timeline elements
    const ticks     = document.querySelectorAll('.tick, .timeline-tick, [class*="tick"]');
    const labels    = document.querySelectorAll('.tick text, .timeline-label, [class*="timeline"] text');
    const markers   = document.querySelectorAll('.row-marker, circle.event, [class*="marker"]');
    const swimSVG   = document.querySelector('#swimSvg, [id*="swim"] svg, [class*="swim"] svg');
    result.tickCount   = ticks.length;
    result.labelCount  = labels.length;
    result.markerCount = markers.length;
    result.swimSvgPresent = !!swimSVG;
    // Time span labels
    const timeTexts = Array.from(labels).map(el => el.textContent.trim()).filter(Boolean);
    result.timeLabels = timeTexts.slice(0, 8);
    // Row count in swim
    result.swimContent = swimSVG ? swimSVG.innerHTML.length : 0;
    return result;
  });

  log('Temporal RAG Swimlane', swimData);
  capturedOutput.swimlane = swimData;

  console.log(`  Timeline ticks: ${swimData.tickCount}`);
  console.log(`  Time labels: ${(swimData.timeLabels || []).join(', ')}`);
  console.log(`  Event markers: ${swimData.markerCount}`);
  console.log(`  Swimlane SVG size: ${swimData.swimContent} chars`);
});

// ── 9. Open first cluster in Tier 2 tab ──────────────────────────────────────
test('9. Tier 2 cluster tab — open and inspect content', async ({ page }) => {
  test.setTimeout(180000);

  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'janusec-playwright-local');
    localStorage.setItem('tenantId', 'default');
  });

  await page.goto(`${BREACH}?assessment=${assessmentId}`);
  await page.waitForLoadState('networkidle');

  // Try to find and click "Open" button on first cluster card
  const openBtn = page.locator('.br-card__open, [class*="open-tab"], [data-action="open-cluster"], button:has-text("Open"), a:has-text("Open")').first();
  const openBtnVisible = await openBtn.isVisible({ timeout: 15000 }).catch(() => false);

  let tier2Page = null;
  if (openBtnVisible) {
    const [newPage] = await Promise.all([
      page.context().waitForEvent('page', { timeout: 10000 }).catch(() => null),
      openBtn.click(),
    ]);
    tier2Page = newPage;
  }

  if (!tier2Page && firstClusterId) {
    // Direct navigation fallback
    tier2Page = await page.context().newPage();
    await tier2Page.addInitScript(() => {
      localStorage.setItem('apiKey', 'janusec-playwright-local');
      localStorage.setItem('tenantId', 'default');
    });
    await tier2Page.goto(`${BREACH}?assessment=${assessmentId}&cluster=${firstClusterId}`);
  }

  if (!tier2Page) {
    log('Tier 2 Tab', '(could not open — no Open button found, no cluster ID)');
    return;
  }

  await tier2Page.waitForLoadState('domcontentloaded');
  // Wait for content to load
  await tier2Page.waitForSelector('[data-testid="bct-wrap"], .bct-wrap, #bct-wrap, .cluster-tab, .tier2', { timeout: 30000 }).catch(() => {});
  await tier2Page.waitForTimeout(3000); // let LLM prefill render

  const tier2Data = await tier2Page.evaluate(() => {
    const get = (sel) => { const el = document.querySelector(sel); return el ? el.textContent.trim().slice(0, 300) : null; };
    const getAll = (sel) => Array.from(document.querySelectorAll(sel)).map(el => el.textContent.trim().slice(0, 100));

    return {
      url: window.location.href,
      wrapPresent: !!document.querySelector('[data-testid="bct-wrap"], .bct-wrap, #bct-wrap'),
      whatHappened: get('[class*="what-happened"], [data-field="what_happened"], .narrative-text, .what-happened'),
      rootCause: get('[class*="root-cause"], [data-field="root_cause"], .root-cause'),
      evidenceChain: getAll('.evidence-chain li, .evidence-step, [class*="evidence-chain"] li').slice(0, 5),
      evidenceGaps: getAll('.evidence-gap, .evidence-gaps li, [class*="gap"] li').slice(0, 3),
      immediateActions: getAll('.immediate-action, .action-step, [class*="action"] li, .bct-step').slice(0, 5),
      personaBody: get('[data-testid="bct-persona-body"], .bct-persona-body, #persona-body'),
      verdict: get('.verdict, [class*="verdict"], [data-verdict]'),
      confidence: get('.confidence, [class*="confidence"], [data-confidence]'),
      mitreList: getAll('.mitre-badge, [class*="mitre"] span, [class*="technique"] span').slice(0, 6),
      gatingBanner: get('.gate-banner, .hvr-gate, [class*="hvr"]'),
      jargonWarning: get('.jargon-warn, [class*="jargon"], [class*="quality-flag"]'),
      validationBasis: get('[class*="validation-basis"], .validation-basis'),
      tier2Url: window.location.href,
    };
  });

  log('Tier 2 Cluster Tab', {
    'URL': (tier2Data.url || '').slice(0, 100),
    'Wrap present': tier2Data.wrapPresent,
    'Verdict': tier2Data.verdict,
    'Confidence': tier2Data.confidence,
    'What Happened': tier2Data.whatHappened,
    'Root Cause': tier2Data.rootCause,
    'Evidence Chain items': (tier2Data.evidenceChain || []).length,
    'Evidence Gaps items': (tier2Data.evidenceGaps || []).length,
    'Immediate Actions': (tier2Data.immediateActions || []).length,
    'MITRE badges': (tier2Data.mitreList || []).join(', '),
    'Gating Banner': tier2Data.gatingBanner,
    'Jargon Warning': tier2Data.jargonWarning,
  });

  log('Tier 2 — Immediate Actions (first 5)', (tier2Data.immediateActions || ['(none found)']).join('\n  '));
  log('Tier 2 — Evidence Chain', (tier2Data.evidenceChain || ['(none found)']).join('\n  '));
  log('Tier 2 — Evidence Gaps', (tier2Data.evidenceGaps || ['(none found)']).join('\n  '));
  log('Tier 2 — What Happened', tier2Data.whatHappened || '(not found)');

  capturedOutput.tier2 = tier2Data;
  await tier2Page.screenshot({ path: 'test-results/three-file-breach-tier2.png', fullPage: true });

  expect(tier2Data.wrapPresent, 'Tier-2 cluster detail should render').toBe(true);
  expect(tier2Data.whatHappened, 'Tier-2 should explain what happened').toBeTruthy();
  expect((tier2Data.evidenceChain || []).length, 'Tier-2 should show a grounded evidence chain').toBeGreaterThanOrEqual(3);
  expect((tier2Data.mitreList || []).length, 'Tier-2 should show MITRE techniques').toBeGreaterThanOrEqual(1);
  expect(tier2Data.gatingBanner, 'Tier-2 should show human validation gate state').toBeTruthy();
  await tier2Page.close();
});

// ── 10. Row coverage disclosure ───────────────────────────────────────────────
test('10. Row coverage disclosure — ⚠ warning when at 2000-row limit', async ({ page }) => {
  test.setTimeout(30000);

  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'janusec-playwright-local');
    localStorage.setItem('tenantId', 'default');
  });

  await page.goto(`${BREACH}?assessment=${assessmentId}`);
  await page.waitForLoadState('networkidle');

  const coverage = await page.evaluate(() => {
    const allText = document.body.innerText;
    return {
      hasWarningSymbol: allText.includes('⚠'),
      warningSnippet: (() => {
        const idx = allText.indexOf('⚠');
        return idx >= 0 ? allText.slice(Math.max(0, idx - 20), idx + 80).trim() : null;
      })(),
      rowCountMentioned: /\d+\s*rows?/i.test(allText),
      atLimit: allText.includes('2000') || allText.includes('2,000'),
    };
  });

  log('Row Coverage Disclosure', coverage);
  // 241 rows is well under 2000, so no warning expected
  console.log(`  ⚠ warning present: ${coverage.hasWarningSymbol} (expected: false for 241-row dataset)`);
  console.log(`  Row count in page: ${coverage.rowCountMentioned}`);
  expect(coverage.hasWarningSymbol, 'Small upload should not show warning icon as coverage disclosure').toBe(false);
  expect(coverage.atLimit, 'Small upload should not mention the 2000-row fetch limit').toBe(false);
});

// ── 11. Final quality summary ─────────────────────────────────────────────────
test('11. Final quality summary printout', async () => {
  console.log('\n');
  log('FULL QUALITY REPORT SUMMARY', {
    'Assessment ID': assessmentId,
    'First Cluster ID': firstClusterId,
    'Meta line': capturedOutput.meta?.metaLine || '(not captured)',
    'Verdict in page': capturedOutput.hero?.verdictInPage || '(not captured)',
    'Coverage warning': capturedOutput.hero?.coverageWarningInPage || '(not captured)',
    'Exec summary len': capturedOutput.execSummary?.length || 0,
    'Cluster cards found': (capturedOutput.clusterCards || []).length,
    'HopGraph SVGs': capturedOutput.hopgraph?.svgCount || 0,
    'HopGraph nodes': capturedOutput.hopgraph?.nodes || 0,
    'HopGraph edges': capturedOutput.hopgraph?.edges || 0,
    'Swimlane ticks': capturedOutput.swimlane?.tickCount || 0,
    'Tier2 wrap present': capturedOutput.tier2?.wrapPresent || false,
    'Tier2 actions count': (capturedOutput.tier2?.immediateActions || []).length,
    'Tier2 evidence steps': (capturedOutput.tier2?.evidenceChain || []).length,
  });
});
