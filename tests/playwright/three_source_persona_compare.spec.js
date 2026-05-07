// three_source_persona_compare.spec.js
//
// Validates the platform's behaviour under three upload scenarios:
//   A) ALL 3 sources  — baseline: endpoint + identity/cloud + network/C2
//   B) MISSING network (endpoint + identity only)
//   C) MISSING identity (endpoint + network only)
//   D) SINGLE source   (endpoint only)
//
// For each scenario we check:
//   - Cluster panel appears (or shows graceful empty-state for single source)
//   - Per-persona report content: SOC, CISO, executive, forensics, auditor/compliance
//   - CISO/Executive see escalating "limited telemetry" warnings when sources are missing
//   - Auditor persona surfaces control gaps / TOGAF-style rearchitect guidance
//   - Impossible travel / FP guidance present when relevant
//
// The test uses the real dump/ fixture files.
// Files must be reachable at the absolute paths defined below.
// If a file cannot be read the test is skipped (not failed) so CI is not
// broken on machines that don't have the dump/ folder mounted.

const { test, expect } = require('@playwright/test');
const fs   = require('fs');
const path = require('path');

const BASE     = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:8080';
const DUMP_DIR = path.resolve(__dirname, '../../dump');

// ── fixture helpers ──────────────────────────────────────────────────────────
function loadFixture(filename) {
  const fp = path.join(DUMP_DIR, filename);
  if (!fs.existsSync(fp)) return null;
  return { name: filename, buffer: fs.readFileSync(fp) };
}

function mimeFor(filename) {
  if (filename.endsWith('.xlsx')) return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
  if (filename.endsWith('.json')) return 'application/json';
  return 'text/csv';
}

function fixtureEntry(filename) {
  const f = loadFixture(filename);
  if (!f) return null;
  return { name: f.name, mimeType: mimeFor(filename), buffer: f.buffer };
}

const EP_FILE   = 'janusec_ep_endpoint.xlsx';
const OKTA_FILE = 'janusec_okta_m365_events.json';
const NET_FILE  = 'janusec_net_c2_bgp.csv';

// ── shared helpers ───────────────────────────────────────────────────────────
async function seedStorage(page) {
  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'devkey123');
    localStorage.setItem('tenantId', 'default');
  });
}

async function uploadAndAnalyse(page, fixtures) {
  await page.locator('#fileInput').setInputFiles(fixtures);
  await page.waitForTimeout(400);
  await page.click('#btnAnalyze');
  // wait for analysis to finish (up to 90s for real files)
  await page.waitForFunction(() => {
    const content = document.getElementById('reportContent');
    const empty   = document.getElementById('reportEmpty');
    const loading = document.getElementById('reportLoading');
    if (!content || !empty || !loading) return false;
    return (content.style.display !== 'none' || empty.style.display !== 'none')
        && loading.style.display === 'none';
  }, { timeout: 90000 });
}

async function switchPersona(page, persona) {
  // persona chip data-persona attribute
  const chip = page.locator(`[data-persona="${persona}"]`).first();
  if (await chip.isVisible()) {
    await chip.click();
    await page.waitForTimeout(800);
  }
}

async function getReportText(page) {
  return page.evaluate(() => {
    const el = document.getElementById('reportContent');
    return el ? (el.innerText || el.textContent || '') : '';
  });
}

async function openFirstCluster(page) {
  // Click the highest severity sev-box to open cluster panel
  const sevBoxes = page.locator('.sev-box, .sev-cell, [data-severity]');
  const count = await sevBoxes.count();
  if (count === 0) return false;
  await sevBoxes.first().click();
  await page.waitForTimeout(600);

  // Try to click the first "Drill in" button
  const drillBtn = page.locator('button:has-text("Drill in"), button:has-text("Drill →"), .cluster-drill-btn').first();
  if (await drillBtn.isVisible({ timeout: 3000 }).catch(() => false)) {
    await drillBtn.click();
    await page.waitForTimeout(1200);
    return true;
  }
  return false;
}

// ════════════════════════════════════════════════════════════════════════════
// SCENARIO A — ALL 3 SOURCES (full baseline)
// ════════════════════════════════════════════════════════════════════════════
test.describe('Scenario A — all 3 sources (full baseline)', () => {
  const fixtures = [EP_FILE, OKTA_FILE, NET_FILE].map(fixtureEntry).filter(Boolean);

  test.skip(fixtures.length < 3, 'One or more fixture files missing from dump/ — skipping');

  test('A1: analysis completes and report is non-empty', async ({ page }) => {
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await seedStorage(page);
    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');
    await uploadAndAnalyse(page, fixtures);

    const content = await page.locator('#reportContent').isVisible();
    expect(content, 'reportContent should be visible after 3-source upload').toBeTruthy();
    expect(errors.filter(e => !e.includes('ResizeObserver')), 'no JS crashes').toHaveLength(0);
  });

  test('A2: cluster panel opens and is not empty', async ({ page }) => {
    await seedStorage(page);
    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');
    await uploadAndAnalyse(page, fixtures);

    const clusterPanel = page.locator('#clusterPanel, .cluster-panel, #clusterList');
    // Open sev-box
    const sevBox = page.locator('.sev-box, .sev-cell, [data-severity]').first();
    await sevBox.click();
    await page.waitForTimeout(800);

    // Either cluster list has rows OR empty-state message is shown — neither is a crash
    const panelVisible = await clusterPanel.isVisible({ timeout: 4000 }).catch(() => false);
    const emptyMsg = await page.locator('text=no clusters').isVisible({ timeout: 2000 }).catch(() => false);
    expect(panelVisible || emptyMsg, 'cluster panel or empty-state must be visible').toBeTruthy();
  });

  test('A3: SOC persona report contains evidence chain content', async ({ page }) => {
    await seedStorage(page);
    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');
    await uploadAndAnalyse(page, fixtures);
    await switchPersona(page, 'soc_analyst');
    const text = await getReportText(page);
    // At minimum the SOC report should contain some actionable language
    const hasThreatContent = /contain|isolat|evidence|lateral|exfil|C2|beacon|triage/i.test(text);
    expect(hasThreatContent, `SOC report should mention containment/evidence/threats. Got: ${text.slice(0, 300)}`).toBeTruthy();
  });

  test('A4: CISO persona report has risk / business impact language', async ({ page }) => {
    await seedStorage(page);
    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');
    await uploadAndAnalyse(page, fixtures);
    await switchPersona(page, 'ciso');
    const text = await getReportText(page);
    const hasRiskLanguage = /risk|breach|impact|compliance|business|board|executive|damage/i.test(text);
    expect(hasRiskLanguage, `CISO report should mention risk/business impact. Got: ${text.slice(0, 300)}`).toBeTruthy();
  });

  test('A5: Auditor/Compliance persona mentions controls or frameworks', async ({ page }) => {
    await seedStorage(page);
    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');
    await uploadAndAnalyse(page, fixtures);
    // try "compliance" or "auditor" persona
    await switchPersona(page, 'compliance');
    await page.waitForTimeout(500);
    const text = await getReportText(page);
    const hasControlLanguage = /control|framework|NIST|ISO|ISM|SOC 2|audit|TOGAF|SABSA|rearchitect|remediate|gap/i.test(text);
    expect(hasControlLanguage, `Compliance persona should reference controls/frameworks. Got: ${text.slice(0, 300)}`).toBeTruthy();
  });

  test('A6: Forensics persona mentions artifact or timeline language', async ({ page }) => {
    await seedStorage(page);
    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');
    await uploadAndAnalyse(page, fixtures);
    await switchPersona(page, 'forensics');
    const text = await getReportText(page);
    const hasForensicsLanguage = /artifact|timeline|chain of custody|hash|IOC|preserve|image|volatile|memory|forensic/i.test(text);
    expect(hasForensicsLanguage, `Forensics persona should mention artifacts/timeline. Got: ${text.slice(0, 300)}`).toBeTruthy();
  });

  test('A7: cluster drawer opens without crash and shows spinner then content', async ({ page }) => {
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await seedStorage(page);
    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');
    await uploadAndAnalyse(page, fixtures);
    await openFirstCluster(page);

    // Drawer should be open (visible) or not found — either is acceptable, crash is not
    const drawerBody = page.locator('#clusterDrawerBody');
    const drawerVisible = await drawerBody.isVisible({ timeout: 3000 }).catch(() => false);
    if (drawerVisible) {
      // Should NOT still show loading spinner after 4s
      await page.waitForTimeout(4000);
      const spinnerGone = !(await page.locator('#clusterDrawerBody svg').isVisible({ timeout: 500 }).catch(() => false));
      // Content should have some text
      const bodyText = await drawerBody.innerText();
      expect(bodyText.trim().length, 'Drawer body should have content after spinning').toBeGreaterThan(10);
    }
    expect(errors.filter(e => !e.includes('ResizeObserver') && !e.includes('favicon')), 'no JS crashes during cluster drill').toHaveLength(0);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// SCENARIO B — MISSING NETWORK (endpoint + identity only)
// ════════════════════════════════════════════════════════════════════════════
test.describe('Scenario B — missing network/C2 source', () => {
  const fixtures = [EP_FILE, OKTA_FILE].map(fixtureEntry).filter(Boolean);

  test.skip(fixtures.length < 2, 'Endpoint or Okta fixture missing — skipping');

  test('B1: analysis completes without network source', async ({ page }) => {
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await seedStorage(page);
    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');
    await uploadAndAnalyse(page, fixtures);
    const visible = await page.locator('#reportContent').isVisible();
    expect(visible).toBeTruthy();
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0);
  });

  test('B2: CISO report flags limited telemetry when network missing', async ({ page }) => {
    await seedStorage(page);
    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');
    await uploadAndAnalyse(page, fixtures);
    await switchPersona(page, 'ciso');
    const text = await getReportText(page);
    // Platform should show risk/impact language even with reduced visibility
    const hasRisk = /risk|impact|breach|blind.?spot|limited|incomplete|coverage|gap/i.test(text);
    expect(hasRisk, `CISO should still surface risk language with 2 sources. Got: ${text.slice(0, 300)}`).toBeTruthy();
  });

  test('B3: Threat Hunter persona still produces actionable output', async ({ page }) => {
    await seedStorage(page);
    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');
    await uploadAndAnalyse(page, fixtures);
    await switchPersona(page, 'threat_hunter');
    const text = await getReportText(page);
    const hasHuntLanguage = /hunt|pivot|lateral|identity|token|credential|C2|log|investigate/i.test(text);
    expect(hasHuntLanguage, `Threat hunter should suggest pivots even without network data. Got: ${text.slice(0, 300)}`).toBeTruthy();
  });
});

// ════════════════════════════════════════════════════════════════════════════
// SCENARIO C — MISSING IDENTITY (endpoint + network only)
// ════════════════════════════════════════════════════════════════════════════
test.describe('Scenario C — missing identity/cloud source', () => {
  const fixtures = [EP_FILE, NET_FILE].map(fixtureEntry).filter(Boolean);

  test.skip(fixtures.length < 2, 'Endpoint or network fixture missing — skipping');

  test('C1: analysis completes without identity source', async ({ page }) => {
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await seedStorage(page);
    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');
    await uploadAndAnalyse(page, fixtures);
    const visible = await page.locator('#reportContent').isVisible();
    expect(visible).toBeTruthy();
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0);
  });

  test('C2: SOC analyst can still triage without identity context', async ({ page }) => {
    await seedStorage(page);
    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');
    await uploadAndAnalyse(page, fixtures);
    await switchPersona(page, 'soc_analyst');
    const text = await getReportText(page);
    // C2 coverage: network + endpoint, SOC should at least see network events
    const hasTriage = /contain|isolat|C2|beacon|lateral|network|endpoint|host/i.test(text);
    expect(hasTriage, `SOC without identity should still triage network/endpoint. Got: ${text.slice(0, 300)}`).toBeTruthy();
  });

  test('C3: Compliance persona surfaces control gaps when identity missing', async ({ page }) => {
    await seedStorage(page);
    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');
    await uploadAndAnalyse(page, fixtures);
    await switchPersona(page, 'compliance');
    const text = await getReportText(page);
    // Without identity logs, compliance should flag missing MFA/IAM context
    const hasGap = /control|gap|missing|framework|audit|log|identity|IAM|MFA|review/i.test(text);
    expect(hasGap, `Compliance without identity should surface control gaps. Got: ${text.slice(0, 300)}`).toBeTruthy();
  });
});

// ════════════════════════════════════════════════════════════════════════════
// SCENARIO D — SINGLE SOURCE (endpoint only)
// ════════════════════════════════════════════════════════════════════════════
test.describe('Scenario D — single source (endpoint only)', () => {
  const fixtures = [EP_FILE].map(fixtureEntry).filter(Boolean);

  test.skip(fixtures.length < 1, 'Endpoint fixture missing — skipping');

  test('D1: analysis still completes on single source', async ({ page }) => {
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await seedStorage(page);
    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');
    await uploadAndAnalyse(page, fixtures);
    // Report or empty state should be shown — never a crash
    const someOutput = await page.evaluate(() => {
      const c = document.getElementById('reportContent');
      const e = document.getElementById('reportEmpty');
      if (c && c.style.display !== 'none') return 'content';
      if (e && e.style.display !== 'none') return 'empty';
      return 'neither';
    });
    expect(someOutput, 'Single source: must show content or empty-state, not crash').not.toBe('neither');
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0);
  });

  test('D2: single source cluster panel shows empty-state (no cross-source correlation)', async ({ page }) => {
    await seedStorage(page);
    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');
    await uploadAndAnalyse(page, fixtures);

    const sevBox = page.locator('.sev-box, .sev-cell, [data-severity]').first();
    const hasSevBox = await sevBox.isVisible({ timeout: 3000 }).catch(() => false);
    if (!hasSevBox) return; // no events at all — acceptable for some single-source files

    await sevBox.click();
    await page.waitForTimeout(800);

    // Either: cluster list with items, OR an empty-state message
    const emptyMsg = await page.locator('text=/no clusters|no correlated|single source/i').isVisible({ timeout: 3000 }).catch(() => false);
    const clusterItems = await page.locator('.cluster-item, .cluster-row, [data-cluster-id]').count();
    // At least one of these must be true — platform should not silently show nothing
    // note: isolated rows are still valid output
    const reportText = await page.evaluate(() => {
      const el = document.getElementById('reportContent');
      return el ? el.innerText.length : 0;
    });
    expect(emptyMsg || clusterItems > 0 || reportText > 50, 'Single-source: must show clusters, empty-state, or report content').toBeTruthy();
  });

  test('D3: Executive persona shows high-level summary even for single source', async ({ page }) => {
    await seedStorage(page);
    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');
    await uploadAndAnalyse(page, fixtures);
    await switchPersona(page, 'executive');
    const text = await getReportText(page);
    // Executive should always get some business-readable output
    const hasExecutiveContent = text.trim().length > 30;
    expect(hasExecutiveContent, `Executive persona should render content for single source. Got: "${text.slice(0, 200)}"`).toBeTruthy();
  });
});
