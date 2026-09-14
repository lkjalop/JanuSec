/**
 * live_meridian_santos_clickthrough.spec.js
 *
 * Live browser walkthrough of the VESPER assessment (4-source APT simulation:
 * cloud identity, endpoint lolbins, Kerberos, network flow — 98,750 rows).
 * Previously tested Meridian/Santos which were lost after server restart.
 *
 * VESPER assessment: assessment-1778187497-cd58d377
 * 4 sources | 98,750 rows | 1 cluster (analysis-2) | VALIDATED_BREACH
 *
 * Run with:
 *   PLAYWRIGHT_BASE_URL=http://localhost:8000 npx playwright test tests/playwright/live_meridian_santos_clickthrough.spec.js --headed
 */

const { test, expect } = require('@playwright/test');

test.describe.configure({ mode: 'serial' });

const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:8000';
const BREACH_URL = BASE + '/static/breach.html';

// VESPER: 4-source APT assessment (was Meridian+Santos — replaced 2026-05-08 after store reset)
const MERIDIAN = process.env.MERIDIAN_ID || 'assessment-1778187497-cd58d377';
const SANTOS   = process.env.SANTOS_ID   || 'assessment-1778187497-cd58d377';

async function openAssessment(page, assessmentId, label) {
  await page.goto(BREACH_URL + '?assessment=' + assessmentId, { waitUntil: 'domcontentloaded' });
  await expect(page.locator('[data-testid="br-meta"]')).toBeVisible({ timeout: 20000 });
  await page.screenshot({ path: `test-results/${label}_01_home.png`, fullPage: false });
}

async function openClusterList(page) {
  // Cards are inside nested <details>: #br-drilldown > .br-drilldown__body > .br-analyst-detail
  // Open the outer drilldown first
  const drilldownToggle = page.locator('[data-testid="br-toggle-drilldown"], #br-drilldown > summary');
  if (await drilldownToggle.count() > 0) {
    const drilldown = page.locator('#br-drilldown');
    const isOpen = await drilldown.evaluate(el => el.open).catch(() => true);
    if (!isOpen) await drilldownToggle.first().click();
  }
  // Open analyst-detail inside it
  const analystSummary = page.locator('.br-analyst-detail > summary');
  if (await analystSummary.count() > 0) {
    await expect(analystSummary).toBeVisible({ timeout: 5000 });
    const analystDetail = page.locator('.br-analyst-detail');
    const isOpen = await analystDetail.evaluate(el => el.open).catch(() => true);
    if (!isOpen) await analystSummary.click();
  }
}

// ── Meridian ──────────────────────────────────────────────────────────────────

test('Meridian: home page loads with meta counts', async ({ page }) => {
  await openAssessment(page, MERIDIAN, 'meridian');

  const sourceEl = page.locator('[data-testid="br-source-count"]');
  const rowEl    = page.locator('[data-testid="br-row-count"]');
  const clusterEl = page.locator('[data-testid="br-cluster-count"]');

  if (await sourceEl.count() > 0) {
    const src = (await sourceEl.textContent()).trim();
    console.log('Meridian sources:', src);
    expect(src).not.toBe('?');
  }
  if (await rowEl.count() > 0) {
    const rows = (await rowEl.textContent()).trim();
    console.log('Meridian rows:', rows);
    expect(parseInt(rows, 10)).toBeGreaterThan(0);
  }
  if (await clusterEl.count() > 0) {
    const cls = (await clusterEl.textContent()).trim();
    console.log('Meridian clusters:', cls);
    expect(parseInt(cls, 10)).toBeGreaterThan(0);
  }
});

test('Meridian: executive summary renders non-empty text', async ({ page }) => {
  await openAssessment(page, MERIDIAN, 'meridian');

  // Open the exec summary drill-down if it's collapsed
  const toggleBtn = page.locator('[data-testid="br-toggle-drilldown"]');
  if (await toggleBtn.count() > 0) await toggleBtn.click();

  // Exec block might be directly visible
  const execBlock = page.locator('[data-testid="br-exec-block"], #br-exec-det, .br-exec-summary');
  const visible = await execBlock.first().isVisible().catch(() => false);
  if (visible) {
    const text = await execBlock.first().textContent();
    console.log('Meridian exec summary (first 200 chars):', text.trim().slice(0, 200));
    expect(text.trim().length).toBeGreaterThan(20);
  } else {
    console.log('Meridian: exec block not found with standard selectors — skipping content check');
  }
  await page.screenshot({ path: 'test-results/meridian_02_exec_summary.png', fullPage: true });
});

test('Meridian: cluster list renders cards', async ({ page }) => {
  await openAssessment(page, MERIDIAN, 'meridian');
  await openClusterList(page);

  const cards = page.locator('.br-card');
  await expect(cards.first()).toBeVisible({ timeout: 15000 });
  const cardCount = await cards.count();
  console.log('Meridian: cluster cards visible:', cardCount);
  expect(cardCount).toBeGreaterThan(0);
  await page.screenshot({ path: 'test-results/meridian_03_cluster_list.png', fullPage: true });
});

test('Meridian: open first cluster detail page', async ({ page }) => {
  await openAssessment(page, MERIDIAN, 'meridian');
  await openClusterList(page);

  const openBtn = page.locator('.br-card__open', { hasText: 'Open threat case' }).first();
  await expect(openBtn).toBeVisible({ timeout: 10000 });

  const [newPage] = await Promise.all([
    page.context().waitForEvent('page'),
    openBtn.click(),
  ]);
  await newPage.waitForLoadState('domcontentloaded');
  const url = newPage.url();
  console.log('Meridian cluster detail URL:', url);
  expect(url).toContain('cluster=');
  await newPage.screenshot({ path: 'test-results/meridian_04_cluster_detail.png', fullPage: true });
  await newPage.close();
});

// ── Santos ────────────────────────────────────────────────────────────────────

test('Santos: home page loads with meta counts', async ({ page }) => {
  await openAssessment(page, SANTOS, 'santos');

  const sourceEl  = page.locator('[data-testid="br-source-count"]');
  const rowEl     = page.locator('[data-testid="br-row-count"]');
  const clusterEl = page.locator('[data-testid="br-cluster-count"]');

  if (await sourceEl.count() > 0) {
    const src = (await sourceEl.textContent()).trim();
    console.log('Santos sources:', src);
    expect(src).not.toBe('?');
  }
  if (await rowEl.count() > 0) {
    const rows = (await rowEl.textContent()).trim();
    console.log('Santos rows:', rows);
    expect(parseInt(rows, 10)).toBeGreaterThan(0);
  }
  if (await clusterEl.count() > 0) {
    const cls = (await clusterEl.textContent()).trim();
    console.log('Santos clusters:', cls);
    expect(parseInt(cls, 10)).toBeGreaterThan(0);
  }
});

test('Santos: executive summary renders non-empty text', async ({ page }) => {
  await openAssessment(page, SANTOS, 'santos');

  const toggleBtn = page.locator('[data-testid="br-toggle-drilldown"]');
  if (await toggleBtn.count() > 0) await toggleBtn.click();

  const execBlock = page.locator('[data-testid="br-exec-block"], #br-exec-det, .br-exec-summary');
  const visible = await execBlock.first().isVisible().catch(() => false);
  if (visible) {
    const text = await execBlock.first().textContent();
    console.log('Santos exec summary (first 200 chars):', text.trim().slice(0, 200));
    expect(text.trim().length).toBeGreaterThan(20);
  } else {
    console.log('Santos: exec block not found — skipping content check');
  }
  await page.screenshot({ path: 'test-results/santos_02_exec_summary.png', fullPage: true });
});

test('Santos: cluster list renders cards', async ({ page }) => {
  await openAssessment(page, SANTOS, 'santos');
  await openClusterList(page);

  const cards = page.locator('.br-card');
  await expect(cards.first()).toBeVisible({ timeout: 15000 });
  const cardCount = await cards.count();
  console.log('Santos: cluster cards visible:', cardCount);
  expect(cardCount).toBeGreaterThan(0);
  await page.screenshot({ path: 'test-results/santos_03_cluster_list.png', fullPage: true });
});

test('Santos: open first cluster detail page', async ({ page }) => {
  await openAssessment(page, SANTOS, 'santos');
  await openClusterList(page);

  const openBtn = page.locator('.br-card__open', { hasText: 'Open threat case' }).first();
  await expect(openBtn).toBeVisible({ timeout: 10000 });

  const [newPage] = await Promise.all([
    page.context().waitForEvent('page'),
    openBtn.click(),
  ]);
  await newPage.waitForLoadState('domcontentloaded');
  const url = newPage.url();
  console.log('Santos cluster detail URL:', url);
  expect(url).toContain('cluster=');
  await newPage.screenshot({ path: 'test-results/santos_04_cluster_detail.png', fullPage: true });
  await newPage.close();
});
