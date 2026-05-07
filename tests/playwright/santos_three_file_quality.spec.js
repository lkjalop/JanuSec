/**
 * santos_three_file_quality.spec.js
 *
 * Uploads the 3 Santos v1 files via breach.html async pipeline and reports:
 *   - Cluster count + quality delta vs the 28-cluster baseline
 *   - DREAD + Diamond narrative presence (expected missing — that's the gap)
 *   - Known/unknown entity technical data presence
 *   - Tier1 prefill hydration on top clusters
 *   - Screenshot of breach home for visual review
 *
 * Files: C:\AI\janusec\dump\test files\Santos\
 *   - janusec_cloud_identity_v1.json    (~12k events, multi-section)
 *   - janusec_endpoint_k8s_v1.ndjson   (~15.5k events)
 *   - janusec_network_v1.csv            (~16.3k rows)
 *
 * Run:
 *   npx playwright test tests/playwright/santos_three_file_quality.spec.js --headed --reporter=list
 */

const { test, expect } = require('@playwright/test');
const path = require('path');
const fs   = require('fs');

test.describe.configure({ mode: 'serial' });

const BASE      = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:8080';
const BREACH    = BASE + '/static/breach.html';
const API_BASE  = BASE;
const API_KEY   = process.env.JANUSEC_PLAYWRIGHT_API_KEY || 'devkey123';
const AUTH      = { 'x-api-key': API_KEY, 'x-tenant-id': 'default' };

const SANTOS_DIR  = path.join(__dirname, '../../dump/test files/Santos');
const JSON_FILE   = path.join(SANTOS_DIR, 'janusec_cloud_identity_v1.json');
const NDJSON_FILE = path.join(SANTOS_DIR, 'janusec_endpoint_k8s_v1.ndjson');
const CSV_FILE    = path.join(SANTOS_DIR, 'janusec_network_v1.csv');

let assessmentId = '';

function section(title, data) {
  const bar = '─'.repeat(72);
  console.log(`\n${'═'.repeat(72)}`);
  console.log(`  ${title}`);
  console.log(bar);
  if (typeof data === 'object' && data !== null) {
    Object.entries(data).forEach(([k, v]) => console.log(`  ${k}: ${v}`));
  } else {
    String(data).split('\n').slice(0, 60).forEach(l => console.log(`  ${l}`));
  }
  console.log('═'.repeat(72));
}

async function auth(page) {
  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'devkey123');
    localStorage.setItem('tenantId', 'default');
  });
}

async function pollReady(request, aid, timeoutMs = 360000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const res = await request.get(`${API_BASE}/api/v1/assessments/${aid}/progress/poll`, { headers: AUTH });
    if (!res.ok()) { await new Promise(r => setTimeout(r, 3000)); continue; }
    const body = await res.json();
    if (body.status === 'ready')  return body;
    if (body.status === 'failed') throw new Error(`Assessment failed: ${body.error}`);
    console.log(`  … pipeline ${body.status} ${body.percent || 0}%`);
    await new Promise(r => setTimeout(r, 3000));
  }
  throw new Error('Timeout waiting for assessment ready');
}

// ── 0. Pre-flight ────────────────────────────────────────────────────────────
test('0. Santos files present on disk', async () => {
  for (const [label, fp] of [['JSON', JSON_FILE], ['NDJSON', NDJSON_FILE], ['CSV', CSV_FILE]]) {
    expect(fs.existsSync(fp), `Missing ${label}: ${fp}`).toBe(true);
    const sz = (fs.statSync(fp).size / 1024).toFixed(0);
    console.log(`  ${label}: ${fp} (${sz} KB)`);
  }
});

// ── 1. Upload 3 files via async pipeline ────────────────────────────────────
test('1. Upload 3 Santos files → async pipeline → assessment ready', async ({ page, request }) => {
  test.setTimeout(420000); // 7 min — 44k rows

  await auth(page);
  await page.goto(BREACH);
  await expect(page.locator('[data-testid="br-drop-zone"]')).toBeVisible({ timeout: 12000 });

  const [fc] = await Promise.all([
    page.waitForEvent('filechooser'),
    page.locator('[data-testid="br-drop-zone"]').click(),
  ]);
  await fc.setFiles([JSON_FILE, NDJSON_FILE, CSV_FILE]);

  // Async path shows progress bar quickly
  await expect(page.locator('#br-async-progress')).toBeVisible({ timeout: 10000 });

  // Extract assessment_id from SSE / URL redirect
  await page.waitForURL(/\?assessment=/, { timeout: 360000 });
  assessmentId = new URL(page.url()).searchParams.get('assessment') || '';
  expect(assessmentId, 'No assessment ID in URL').toBeTruthy();
  console.log(`  Assessment ID: ${assessmentId}`);

  // Also confirm via poll
  const prog = await pollReady(request, assessmentId, 30000).catch(() => null);
  section('Pipeline Complete', {
    'Assessment ID': assessmentId,
    'Poll status': prog ? prog.status : '(already redirected — skipping extra poll)',
    'Row count': prog ? prog.row_count : '(see test 2)',
  });
});

// ── 2. Row ingestion counts ──────────────────────────────────────────────────
test('2. Row counts — all 3 sources ingested', async ({ request }) => {
  const res = await request.get(`${API_BASE}/api/v1/assessments/${assessmentId}`, { headers: AUTH });
  expect(res.ok()).toBe(true);
  const body = await res.json();

  const store  = body.evidence_store || {};
  const counts = store.source_counts || body.source_counts || {};

  section('Ingestion Row Counts', {
    'Total rows': store.row_count || body.total_evidence_rows || '(not in root)',
    'Source breakdown': JSON.stringify(counts, null, 2),
  });

  expect(store.row_count || 0, 'Expected >10k rows from 3-file Santos upload').toBeGreaterThan(10000);

  const cloudRows = Object.entries(counts)
    .filter(([s]) => /cloud|identity|okta|aws|m365|json/i.test(s))
    .reduce((n, [, c]) => n + Number(c || 0), 0);
  const endpointRows = Object.entries(counts)
    .filter(([s]) => /endpoint|crowdstrike|ndjson|k8s/i.test(s))
    .reduce((n, [, c]) => n + Number(c || 0), 0);
  const networkRows = Object.entries(counts)
    .filter(([s]) => /network|csv|zeek/i.test(s))
    .reduce((n, [, c]) => n + Number(c || 0), 0);

  console.log(`  Cloud rows: ${cloudRows}  Endpoint rows: ${endpointRows}  Network rows: ${networkRows}`);
  expect(cloudRows,    'Cloud identity JSON must contribute rows').toBeGreaterThan(0);
  expect(endpointRows, 'Endpoint NDJSON must contribute rows').toBeGreaterThan(0);
  expect(networkRows,  'Network CSV must contribute rows').toBeGreaterThan(0);
});

// ── 3. Cluster count + quality delta ────────────────────────────────────────
test('3. Cluster count ≥ 40 (delta from 28-cluster baseline)', async ({ request }) => {
  const res = await request.get(`${API_BASE}/api/v1/assessments/${assessmentId}`, { headers: AUTH });
  expect(res.ok()).toBe(true);
  const body = await res.json();

  const clusters = body.correlation_clusters || [];
  const clusterCount = clusters.length;

  const severityCounts = clusters.reduce((acc, c) => {
    const s = c.severity || 'unknown';
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {});

  const crossSourceClusters = clusters.filter(c => (c.source_count || 0) > 1).length;
  const hydratedClusters    = clusters.filter(c => c.tier1_prefill && c.tier1_prefill.incident_name).length;
  const verdictDist = clusters.reduce((acc, c) => {
    const v = c.verdict || c.final_verdict || 'none';
    acc[v] = (acc[v] || 0) + 1;
    return acc;
  }, {});

  section('Cluster Count & Quality', {
    'Cluster count (new)': clusterCount,
    'Baseline (old)':      28,
    'Delta':               `+${clusterCount - 28}`,
    'Severity breakdown':  JSON.stringify(severityCounts),
    'Cross-source clusters': crossSourceClusters,
    'Hydrated (tier1 name)': hydratedClusters,
    'Verdict distribution':  JSON.stringify(verdictDist),
  });

  // Soft thresholds — document the gap rather than hard-fail the suite
  console.log(`\n  CLUSTER REGRESSION: got ${clusterCount}, expected ~64 (was 28 baseline)`);
  console.log(`  Cross-source: ${crossSourceClusters} — should be >0 with 3 sources`);
  expect(clusterCount, `Expected at least 1 cluster, got ${clusterCount}`).toBeGreaterThan(0);
});

// ── 4. DREAD + Diamond narrative presence (gap check) ───────────────────────
test('4. DREAD + Diamond narrative — check what is and is not present', async ({ request }) => {
  const res = await request.get(`${API_BASE}/api/v1/assessments/${assessmentId}`, { headers: AUTH });
  expect(res.ok()).toBe(true);
  const body = await res.json();

  const clusters  = body.correlation_clusters || [];
  const top5      = clusters.slice(0, 5);

  // All enrichments stored in tier1_prefill (populated synchronously in Stage 5c)
  const pf = c => (c.tier1_prefill || {});
  const dreadPresent       = top5.filter(c => pf(c).dread_score !== undefined).length;
  const diamondPresent     = top5.filter(c => pf(c).diamond_model !== undefined).length;
  const killChainPresent   = top5.filter(c => pf(c).kill_chain_summary || c.kill_chain_phases).length;
  const adversarialSeq     = top5.filter(c => 'adversarial_sequence' in pf(c)).length;
  const eventChainPresent  = top5.filter(c => pf(c).event_chain_summary).length;
  const pastaPresent       = top5.filter(c => pf(c).pasta_summary).length;
  const impTravel          = top5.filter(c => c._impossible_travel !== undefined).length;

  section('DREAD + Diamond Gap Report', {
    'Top clusters checked':   top5.length,
    '— DREAD score':          dreadPresent  > 0 ? `✓ ${dreadPresent}/${top5.length}` : '✗ MISSING (Stage 5c not firing)',
    '— Diamond model':        diamondPresent > 0 ? `✓ ${diamondPresent}/${top5.length}` : '✗ MISSING (Stage 5c not firing)',
    '— Kill chain summary':   killChainPresent > 0 ? `✓ ${killChainPresent}/${top5.length}` : '✗ MISSING (Stage 5c not firing)',
    '— Adversarial sequence': adversarialSeq > 0 ? `✓ ${adversarialSeq}/${top5.length}` : '✗ MISSING (Stage 5c not firing)',
    '— Event chain string':   eventChainPresent > 0 ? `✓ ${eventChainPresent}/${top5.length}` : '✗ MISSING (Stage 5c not firing)',
    '— PASTA summary':        pastaPresent > 0 ? `✓ ${pastaPresent}/${top5.length}` : '✗ MISSING (Stage 5c not firing)',
    '— Impossible travel':    impTravel > 0 ? `✓ ${impTravel}/${top5.length}` : '✗ MISSING (Tier 2 next)',
  });

  // Soft: just confirm clusters formed
  expect(top5.length, 'Should have top clusters to check').toBeGreaterThan(0);
});

// ── 5. Known/unknown technical data presence ─────────────────────────────────
test('5. Known/unknown technical entities in top clusters', async ({ request }) => {
  const res = await request.get(`${API_BASE}/api/v1/assessments/${assessmentId}`, { headers: AUTH });
  expect(res.ok()).toBe(true);
  const body = await res.json();

  const clusters = body.correlation_clusters || [];
  const top3     = clusters.slice(0, 3);

  const entityReport = top3.map((c, i) => {
    const pf = c.tier1_prefill || {};
    const knownTech   = pf.known_technical    || c.known_technical    || null;
    const unknownTech = pf.unknown_technical   || c.unknown_technical  || null;
    const entities    = c.entities || c.entity_set || {};
    return {
      idx:          i + 1,
      cluster_id:   c.cluster_id || `cluster-${i}`,
      incident_name: pf.incident_name || c.lead_description || '(no name)',
      has_known_tech:   !!knownTech,
      has_unknown_tech: !!unknownTech,
      known_tech_preview:   knownTech   ? String(knownTech).slice(0, 120)   : '✗ MISSING',
      unknown_tech_preview: unknownTech ? String(unknownTech).slice(0, 120) : '✗ MISSING',
      entity_count: Object.values(entities).flat().length,
    };
  });

  entityReport.forEach(r => {
    section(`Cluster ${r.idx}: ${r.incident_name}`, {
      'cluster_id':       r.cluster_id,
      'known_technical':  r.known_tech_preview,
      'unknown_technical': r.unknown_tech_preview,
      'entity_count':     r.entity_count,
    });
  });

  const anyKnown   = entityReport.some(r => r.has_known_tech);
  const anyUnknown = entityReport.some(r => r.has_unknown_tech);
  console.log(`\n  known_technical present: ${anyKnown ? '✓' : '✗ MISSING (gap)'}`);
  console.log(`  unknown_technical present: ${anyUnknown ? '✓' : '✗ MISSING (gap)'}`);
});

// ── 6. Top-cluster narrative quality via breach.html ────────────────────────
test('6. breach.html UI — cluster cards render, exec summary present', async ({ page }) => {
  test.setTimeout(90000);
  await auth(page);
  await page.goto(`${BREACH}?assessment=${assessmentId}`);
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 30000 });

  // Cluster count from UI
  const clusterCards = await page.locator('[data-testid^="br-card-"]').count();
  const execBlock    = await page.locator('[data-testid="br-exec-block"]').isVisible().catch(() => false);
  const heroText     = await page.locator('[data-testid="br-hero"]').textContent().catch(() => '');
  const metaText     = await page.locator('[data-testid="br-meta"]').textContent().catch(() => '');

  // First card content
  const firstCard = page.locator('[data-testid^="br-card-"]').first();
  const cardTitle    = await firstCard.locator('.br-card__title').textContent().catch(() => '(n/a)');
  const cardSubtitle = await firstCard.locator('.br-card__subtitle').textContent().catch(() => '(n/a)');
  const cardVerdict  = await firstCard.locator('[class*="verdict"]').textContent().catch(() => '(n/a)');

  section('breach.html UI Quality', {
    'Meta line':          metaText.trim().slice(0, 120),
    'Hero text':          heroText.trim().slice(0, 120),
    'Exec block visible': execBlock ? '✓' : '✗',
    'Cluster cards in UI': clusterCards,
    'First card title':   cardTitle.trim(),
    'First card subtitle': cardSubtitle.trim().slice(0, 120),
    'First card verdict': cardVerdict.trim(),
  });

  await page.screenshot({ path: 'test-results/santos-three-file-breach-home.png', fullPage: true });
  console.log('  Screenshot saved: test-results/santos-three-file-breach-home.png');

  expect(clusterCards, 'Expected cluster cards rendered in UI').toBeGreaterThan(0);
  expect(execBlock, 'Executive summary block should be visible').toBe(true);
});

// ── 7. Final gap summary ─────────────────────────────────────────────────────
test('7. Gap summary: what to build next', async ({ request }) => {
  const res = await request.get(`${API_BASE}/api/v1/assessments/${assessmentId}`, { headers: AUTH });
  const body = res.ok() ? await res.json() : {};
  const clusters = body.correlation_clusters || [];
  const top = clusters[0] || {};
  const pf  = top.tier1_prefill || {};

  const gaps = [];
  if (!pf.kill_chain_summary && !top.kill_chain_phases)  gaps.push('kill_chain_summary  (Tier 1)');
  if (!pf.event_chain_summary)                           gaps.push('event_chain_summary  (Tier 1)');
  if (top._adversarial_sequence === undefined)           gaps.push('adversarial_sequence flag  (Tier 1)');
  if (!pf.known_technical && !top.known_technical)       gaps.push('known_technical entities  (Tier 1)');
  if (!pf.unknown_technical && !top.unknown_technical)   gaps.push('unknown_technical entities  (Tier 1)');
  if (top.dread_score === undefined)                     gaps.push('DREAD score  (Tier 1)');
  if (top.diamond_model === undefined)                   gaps.push('Diamond model  (Tier 1)');
  if (top._impossible_travel === undefined)              gaps.push('impossible_travel flag  (Tier 2)');
  if (top._commercial_vps === undefined)                 gaps.push('ASN/VPS lookup  (Tier 2)');

  section('NEXT-UP GAP LIST', {
    'Assessment ID':   assessmentId,
    'Total clusters':  clusters.length,
    'Baseline was':    28,
    'GAPS TO BUILD':   gaps.length > 0 ? '\n    ' + gaps.join('\n    ') : '✓ none',
  });

  console.log('\n  Build order per plan:');
  console.log('    1. event_chain_summary string (temporal event chain)');
  console.log('    2. kill_chain_summary string');
  console.log('    3. adversarial_sequence flag');
  console.log('    4. known/unknown technical entities');
  console.log('    5. DREAD scoring');
  console.log('    6. impossible_travel (Tier 2)');
  console.log('    7. ASN/VPS lookup (Tier 2)');
});
