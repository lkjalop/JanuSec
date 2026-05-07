const { chromium } = require('@playwright/test');

// Global setup: open a page and set localStorage.testMode=1 so pages read it during tests
module.exports = async () => {
  const browser = await chromium.launch();
  const context = await browser.newContext();
  const page = await context.newPage();
  const configured = process.env.PLAYWRIGHT_BASE_URL || process.env.BASE_URL || 'http://localhost:8080';
  // Normalize to ensure we set localStorage for both common dev origins: 127.0.0.1 and localhost
  const urlCandidates = new Set([configured]);
  try {
    const u = new URL(configured);
    // also add equivalent hostname variants
    if (u.hostname === '127.0.0.1') {
      urlCandidates.add(`http://localhost:${u.port}`);
    } else if (u.hostname === 'localhost') {
      urlCandidates.add(`http://127.0.0.1:${u.port}`);
    }
  } catch (e) {
    // ignore URL parsing problems
  }
  try {
    for (const base of urlCandidates) {
      try {
        const p = await context.newPage();
        await p.goto(base, { waitUntil: 'domcontentloaded', timeout: 10000 });
        await p.evaluate(() => { try { localStorage.setItem('testMode', 'playwright'); localStorage.setItem('apiKey','devkey123'); } catch(e) {} });
        await p.evaluate(() => {
          try {
            if (!window.d3) window.d3 = undefined;
            if (!window.XLSX) window.XLSX = { __placeholder: true };
          } catch (e) {}
        });
        await p.close();
      } catch (e) {
        // ignore per-origin errors
      }
    }
    // Persist the context storage state so test contexts inherit localStorage + cookies
    try {
      const statePath = 'tests/playwright/storageState.json';
      await context.storageState({ path: statePath });
    } catch (e) {
      // ignore storage write errors
    }
  } catch (e) {
    // ignore overall errors; tests have fallbacks
  } finally {
    await context.close();
    await browser.close();
  }
};
