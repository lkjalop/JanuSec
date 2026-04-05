const { test, expect } = require('@playwright/test');

test('Tier summaries surface queued/replayed factor cues', async ({ page }) => {
  await page.addInitScript(() => { try { localStorage.setItem('apiKey', 'devkey123'); } catch (e) {} });
  await page.goto('http://localhost:8080/static/csv_analyzer.html', { waitUntil: 'domcontentloaded' });
  const html = await page.evaluate(() => {
    if (typeof window.renderCorrelationHighlights !== 'function') {
      return '';
    }
    const now = Date.now() / 1000;
    return window.renderCorrelationHighlights({
      mappingScore: 0.42,
      domainScore: 0.58,
      pathScore: null,
      insights: [],
      dependency: {
        hopgraph: { available: true, seconds_since_ok: 12 },
        redis: { available: true, seconds_since_ok: 18 },
        queued_factor_batches: 3,
        replay_history: [{ timestamp: now, batch_count: 2 }],
      },
      replayCount: 2,
      replayHistory: [{ timestamp: now }],
    });
  });
  expect(html).toContain('Queued factor batches awaiting replay');
  expect(html).toContain('Recovered 2 queued factor batches');
});
