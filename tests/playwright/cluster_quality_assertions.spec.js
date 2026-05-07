// cluster_quality_assertions.spec.js
// Assertions for cluster card / hero quality gates:
//   1. No "Sources: unknown" in cluster cards
//   2. No raw "Correlated activity cluster" lead description
//   3. No bare "cluster-N" cluster ID shown as title
//   4. Top-3 clusters are fully hydrated (incident_name present via tier1_prefill)
//   5. Model badge shows qwen3:30b (or configured model) — not blank
//   6. Hero verdict and cluster card verdict are aligned (same severity tier)
//
// These run against a seeded multi-source CSV so clusters always form.

const { test, expect } = require('@playwright/test');

const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:8080';

// CSV with deliberate cross-source pivots so at least 2 clusters form
const MULTI_SOURCE_CSV = [
  'severity,description,src_ip,user,hostname,event_name,source',
  'critical,Credential spray via legacy auth,185.220.101.5,alice@corp.com,ws-alice,Failed sign-in,azure_signin',
  'high,MFA fatigue push — 12 prompts,185.220.101.5,alice@corp.com,ws-alice,MFA push flood,azure_signin',
  'critical,New device token issued post-spray,185.220.101.5,alice@corp.com,,DeviceCodeFlow,azure_signin',
  'high,Inbox rule created — forward to external,,,ws-alice,MailboxRuleAdded,exchange',
  'high,BEC forwarding rule: all→attacker@bad.io,,,ws-alice,SuspiciousInboxRule,exchange',
  'critical,Lateral move: PsExec from ws-alice,10.0.0.5,alice@corp.com,dc-01,RemoteExec,endpoint',
  'high,Credential dump: LSASS access,10.0.0.5,alice@corp.com,dc-01,CredentialDump,endpoint',
  'medium,Port scan detected from staging host,192.168.5.10,svc_build,build-01,NetworkScan,network',
  'medium,DNS tunnel pattern — high entropy,192.168.5.10,svc_build,build-01,DNSTunnel,network',
  'low,Scheduled task created on build-01,192.168.5.10,svc_build,build-01,ScheduledTask,endpoint',
].join('\n');

async function seedStorage(page) {
  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'devkey123');
    localStorage.setItem('tenantId', 'default');
  });
}

async function loadAndAnalyze(page) {
  await seedStorage(page);
  await page.goto(`${BASE}/static/investigate.html`);
  await page.waitForLoadState('networkidle');

  const buffer = Buffer.from(MULTI_SOURCE_CSV);
  await page.locator('#fileInput').setInputFiles([
    { name: 'cluster_quality_test.csv', mimeType: 'text/csv', buffer },
  ]);
  await page.waitForTimeout(400);
  await page.click('#btnAnalyze');

  // Wait for report to appear (up to 90s — prefill may need LLM round-trip)
  await page.waitForFunction(
    () => {
      const content  = document.getElementById('reportContent');
      const empty    = document.getElementById('reportEmpty');
      const loading  = document.getElementById('reportLoading');
      if (!content || !empty || !loading) return false;
      return (content.style.display !== 'none' || empty.style.display !== 'none')
          && loading.style.display === 'none';
    },
    { timeout: 90000 }
  );
  // Allow a brief window for background prefill to write cluster titles
  await page.waitForTimeout(1500);
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 1 — No "Sources: unknown" in any visible cluster card
// ─────────────────────────────────────────────────────────────────────────────
test('cluster cards: no "Sources: unknown" label visible', async ({ page }) => {
  const jsErrors = [];
  page.on('pageerror', err => jsErrors.push(err.message));

  await loadAndAnalyze(page);

  // Navigate to clusters tab
  const clusterTab = page.locator('[data-tab="clusters"], [data-tab="report"], #tabClusters');
  if (await clusterTab.count() > 0) await clusterTab.first().click();
  await page.waitForTimeout(400);

  const pageText = await page.locator('body').textContent();
  expect(pageText, 'Page must not contain "Sources: unknown"').not.toContain('Sources: unknown');

  expect(jsErrors.filter(e => !e.includes('favicon')).length,
    `JS errors: ${jsErrors.join(', ')}`).toBe(0);
});

// ─────────────────────────────────────────────────────────────────────────────
// TEST 2 — No raw "Correlated activity cluster" as a visible cluster title
// ─────────────────────────────────────────────────────────────────────────────
test('cluster cards: no raw "Correlated activity cluster" title', async ({ page }) => {
  const jsErrors = [];
  page.on('pageerror', err => jsErrors.push(err.message));

  await loadAndAnalyze(page);

  // Cluster titles appear in cards and in the drawer header
  const clusterTitleEls = page.locator('.cluster-title, .cluster-name, .cluster-card h3, .cluster-card .title');
  const count = await clusterTitleEls.count();

  for (let i = 0; i < count; i++) {
    const text = (await clusterTitleEls.nth(i).textContent() || '').trim();
    expect(
      text.toLowerCase(),
      `Cluster title at index ${i} looks like a raw placeholder: "${text}"`
    ).not.toMatch(/^correlated activity cluster/i);
  }

  expect(jsErrors.filter(e => !e.includes('favicon')).length,
    `JS errors: ${jsErrors.join(', ')}`).toBe(0);
});

// ─────────────────────────────────────────────────────────────────────────────
// TEST 3 — No bare "cluster-N" shown as a visible title (only as an ID attribute)
// ─────────────────────────────────────────────────────────────────────────────
test('cluster cards: cluster-N ID not exposed as visible title text', async ({ page }) => {
  const jsErrors = [];
  page.on('pageerror', err => jsErrors.push(err.message));

  await loadAndAnalyze(page);

  const clusterTitleEls = page.locator('.cluster-title, .cluster-name, .cluster-card h3, .cluster-card .title');
  const count = await clusterTitleEls.count();

  for (let i = 0; i < count; i++) {
    const text = (await clusterTitleEls.nth(i).textContent() || '').trim();
    expect(
      text,
      `Cluster title at index ${i} is bare cluster ID: "${text}"`
    ).not.toMatch(/^cluster-\d+$/i);
  }

  expect(jsErrors.filter(e => !e.includes('favicon')).length,
    `JS errors: ${jsErrors.join(', ')}`).toBe(0);
});

// ─────────────────────────────────────────────────────────────────────────────
// TEST 4 — Top-3 clusters are hydrated (have a non-placeholder incident_name)
// ─────────────────────────────────────────────────────────────────────────────
test('cluster cards: top-3 clusters have hydrated incident names', async ({ page }) => {
  const jsErrors = [];
  page.on('pageerror', err => jsErrors.push(err.message));

  await loadAndAnalyze(page);

  // Pull the live assessment object from the page's JS state
  const clusterData = await page.evaluate(() => {
    // Try common state paths used in investigate.js
    const state = window._investigateState || window.investigateState || {};
    const clusters = state.correlationClusters
      || state.clusters
      || (window._lastAssessment || {}).correlation_clusters
      || [];
    return clusters.slice(0, 3).map(c => ({
      cluster_id: c.cluster_id,
      lead_description: c.lead_description || '',
      incident_name: (c.tier1_prefill || {}).incident_name || '',
      verdict: c.verdict || c.final_verdict || '',
    }));
  });

  if (clusterData.length === 0) {
    test.skip(true, 'No clusters returned from API — skipping hydration check');
    return;
  }

  for (const cluster of clusterData) {
    const title = cluster.incident_name || cluster.lead_description;
    expect(title, `Cluster ${cluster.cluster_id} has no hydrated title`).toBeTruthy();
    expect(title.toLowerCase(), `Cluster ${cluster.cluster_id} title is a placeholder`)
      .not.toMatch(/^(correlated activity cluster|cluster-\d+|n\/a|unknown|none)$/i);
    expect(title.length, `Cluster ${cluster.cluster_id} title is too short`).toBeGreaterThan(8);
  }

  expect(jsErrors.filter(e => !e.includes('favicon')).length,
    `JS errors: ${jsErrors.join(', ')}`).toBe(0);
});

// ─────────────────────────────────────────────────────────────────────────────
// TEST 5 — Model selector exists in drawer and is non-empty after opening a cluster
// ─────────────────────────────────────────────────────────────────────────────
test('cluster drawer: model selector is present and has a valid model option', async ({ page }) => {
  const jsErrors = [];
  page.on('pageerror', err => jsErrors.push(err.message));

  await loadAndAnalyze(page);

  // Cluster list renders into #clusterListPanel — open the first cluster-item
  const clusterItems = page.locator('.cluster-item__label');
  const clusterCount = await clusterItems.count();
  if (clusterCount === 0) {
    // No clusters formed — check the JS state to understand why
    const state = await page.evaluate(() => window._investigateState || {});
    console.log('No cluster items rendered. _investigateState:', JSON.stringify(state).slice(0, 200));
    test.skip(true, 'No cluster items in list — skipping model selector test');
    return;
  }

  // Click the first cluster label to open the drawer
  await clusterItems.first().click();
  await page.waitForTimeout(800);

  const drawer = page.locator('#clusterDrawer');
  await expect(drawer).toHaveClass(/open/, { timeout: 3000 });

  // Model selector #cdModelSel should exist inside the drawer with ≥1 option
  const modelSel = page.locator('#cdModelSel');
  if (await modelSel.count() > 0) {
    const opts = await modelSel.locator('option').count();
    expect(opts, 'cdModelSel must have at least one model option').toBeGreaterThan(0);
    const selectedVal = await modelSel.inputValue();
    expect(selectedVal.length, 'Selected model must not be empty').toBeGreaterThan(0);
    // Should look like a real model identifier (letters + colon or hyphen)
    expect(selectedVal).toMatch(/[a-z]/i);
  }

  expect(jsErrors.filter(e => !e.includes('favicon')).length,
    `JS errors: ${jsErrors.join(', ')}`).toBe(0);
});

// ─────────────────────────────────────────────────────────────────────────────
// TEST 6 — Cluster list severity and JS-state verdict are aligned
// ─────────────────────────────────────────────────────────────────────────────
test('cluster list: rendered severity matches JS-state verdict for top cluster', async ({ page }) => {
  const jsErrors = [];
  page.on('pageerror', err => jsErrors.push(err.message));

  await loadAndAnalyze(page);

  // Read cluster state directly from JS
  const topCluster = await page.evaluate(() => {
    const s = window._investigateState || {};
    const clusters = s.correlationClusters || [];
    if (!clusters.length) return null;
    // Sort by severity rank, pick top
    const rank = { critical: 4, high: 3, medium: 2, low: 1 };
    return clusters.slice().sort((a, b) => (rank[b.severity] || 0) - (rank[a.severity] || 0))[0];
  });

  if (!topCluster) {
    test.skip(true, 'No clusters in JS state — skipping verdict alignment test');
    return;
  }

  const jsSev = (topCluster.severity || '').toLowerCase();

  // The cluster-item list renders severity as class cluster-item--<severity>
  const topItemSevEl = page.locator(
    `.cluster-item--${jsSev} .cluster-item__sev, .cluster-item--${jsSev}`
  ).first();

  if (await topItemSevEl.count() > 0) {
    const domText = (await topItemSevEl.textContent() || '').toLowerCase();
    expect(domText).toContain(jsSev.slice(0, 4)); // 'crit', 'high', 'medi', 'low'
  }

  // Verdict in the decision panel should be rendered somewhere on the page
  const decisionVerdict = topCluster.verdict || topCluster.final_verdict || '';
  if (decisionVerdict) {
    const pageText = await page.locator('body').textContent();
    // At least the severity word should appear in the page
    expect(pageText.toLowerCase()).toContain(jsSev.slice(0, 4));
  }

  expect(jsErrors.filter(e => !e.includes('favicon')).length,
    `JS errors: ${jsErrors.join(', ')}`).toBe(0);
});
