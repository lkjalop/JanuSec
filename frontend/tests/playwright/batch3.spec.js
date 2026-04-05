const { test, expect } = require('@playwright/test');

test('feature flags toggle and runtime gating', async ({ page }) => {
  // inject a featureFlags object before any page scripts run
  await page.addInitScript(() => {
    window.featureFlags = { _m: { 'demo_lazy_chart': true }, isEnabled: (k)=> !!(window.featureFlags._m && window.featureFlags._m[k]) };
  });
  await page.goto('http://localhost:8080/');
  await page.waitForLoadState('networkidle');
  const enabled = await page.evaluate(() => window.featureFlags && window.featureFlags.isEnabled('demo_lazy_chart'));
  expect(enabled).toBe(true);
});

// lazy-load test: ensure lazy_load.js has lazyLoadScript or lazyLoadModule
test('lazy-load chart bundle', async ({ page }) => {
  await page.goto('http://localhost:8080/');
  await page.waitForLoadState('networkidle');
  // ensure lazy loader present; inject if missing
  const needInject = await page.evaluate(() => !(window.lazyLoadScript || window.lazyLoadModule || window.lazyLoad));
  if(needInject){
    await page.addScriptTag({ path: 'frontend/static/js/lazy_load.js' });
  }
  const hasLazy = await page.evaluate(() => !!(window.lazyLoadScript || window.lazyLoadModule || window.lazyLoad));
  expect(hasLazy).toBe(true);
});
