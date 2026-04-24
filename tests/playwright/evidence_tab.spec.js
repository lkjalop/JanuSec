const { test, expect } = require('@playwright/test');

const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:8000';
const AID  = process.env.EVIDENCE_AID || 'assessment-1776718576-92842bbb';

test('Evidence tab: table renders with rows, filters, expand', async ({ page }) => {
  await page.goto(BASE + '/static/breach.html?assessment=' + AID + '&tab=evidence');
  await expect(page.locator('.br-ev')).toBeVisible({ timeout: 15000 });

  // Controls present
  await expect(page.locator('#br-ev-cluster')).toBeVisible();
  await expect(page.locator('#br-ev-sev')).toBeVisible();
  await expect(page.locator('#br-ev-search')).toBeVisible();

  // Row count shows real numbers
  const count = await page.locator('.br-ev__count').textContent();
  console.log('  Row count:', count.trim());
  expect(count.trim()).toMatch(/\d+ \/ \d+ rows/);
  const total = parseInt(count.split('/')[1]);
  expect(total).toBeGreaterThan(50);

  // Source platform column populated
  const srcs = await page.locator('.br-ev__td--src').allTextContents();
  console.log('  Sample sources:', srcs.slice(0,4).map(s => s.trim()));
  expect(srcs.filter(s => s.trim()).length).toBeGreaterThan(0);

  // Cluster badges present for correlated rows
  const badges = await page.locator('.br-ev__cluster:not(.br-ev__cluster--none)').count();
  console.log('  Cluster badges visible:', badges);
  expect(badges).toBeGreaterThan(10);

  // MITRE badges present
  const mitreBadges = await page.locator('.br-ev__mitre').count();
  console.log('  MITRE badges:', mitreBadges);
  expect(mitreBadges).toBeGreaterThan(0);

  // Expand first toggle to show analyst notes
  const toggle = page.locator('.br-ev__toggle').first();
  await toggle.click();
  await expect(page.locator('.br-ev__notes').first()).toBeVisible();
  const notes = await page.locator('.br-ev__notes').first().textContent();
  console.log('  Notes preview:', notes.slice(0, 120).trim());
  expect(notes.trim().length).toBeGreaterThan(20);

  // Severity sort: click Sev header
  await page.locator('[data-evsort="severity"]').click();
  const countAfterSort = await page.locator('.br-ev__count').textContent();
  expect(countAfterSort.trim()).toMatch(/\d+ \/ \d+ rows/);

  // Cluster filter reduces rows
  const clusterSel = page.locator('#br-ev-cluster');
  const opts = await clusterSel.locator('option').allTextContents();
  console.log('  Cluster options:', opts.slice(0,5));
  if (opts.length > 1) {
    await clusterSel.selectOption({ index: 1 });
    const filtered = await page.locator('.br-ev__count').textContent();
    console.log('  After cluster filter:', filtered.trim());
    expect(parseInt(filtered.split('/')[0])).toBeLessThan(total);
  }

  // Text search
  await page.locator('#br-ev-cluster').selectOption({ index: 0 }); // reset
  await page.locator('#br-ev-search').fill('Okta');
  await page.waitForTimeout(300);
  const searchCount = await page.locator('.br-ev__count').textContent();
  console.log('  After "Okta" search:', searchCount.trim());
  expect(parseInt(searchCount.split('/')[0])).toBeLessThan(total);
  expect(parseInt(searchCount.split('/')[0])).toBeGreaterThan(0);
});
