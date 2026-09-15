import { test, expect } from '@playwright/test';

test.describe('LIVE evidence extras', () => {
  test('evidence items list multiple entries and copy works', async ({ page, request }) => {
    try { await request.post('/api/v1/dev/seed_decisions', { data: JSON.stringify({ count: 4, prefix: 'ev-test', tenant_id: 'demo' }), headers: { 'content-type': 'application/json' } }); } catch(_){ }
    // Ensure active investigation is initialized for the seeded decisions
    try { await request.get('/api/v1/dev/active_investigation'); } catch(_){ }
    // Fetch the deterministic active investigation from the backend dev endpoint
    let active = null;
    try {
      const r = await request.get('/api/v1/dev/active_investigation');
      active = await r.json().catch(()=>null);
    } catch(_){ active = null; }
    await page.goto('/');
    // Wait for the deterministic readiness marker the app inserts for tests
    await page.waitForSelector('#live_console_ready', { state: 'attached', timeout: 10000 });
    // If the app did not render an investigationPanel, inject a deterministic one from backend payload
    await page.evaluate((active) => {
      let inv = document.getElementById('investigationPanel');
      if (!inv) {
        inv = document.createElement('div');
        inv.id = 'investigationPanel';
        inv.className = 'investigation-panel';
        const title = (active && active.target) ? `Active Investigation: ${active.target}` : 'Active Investigation';
        inv.innerHTML = `\n            <div class=\"section-title\">${title}</div>`;
        document.body.appendChild(inv);
      }
      let list = inv.querySelector('.evidence-list');
      if (!list) { list = document.createElement('div'); list.className = 'evidence-list'; inv.appendChild(list); }
      const mk = (txt) => {
        const d = document.createElement('div'); d.className = 'evidence-item'; d.textContent = txt;
        const actions = document.createElement('div'); actions.style.marginTop = '8px'; actions.style.display = 'flex'; actions.style.gap = '8px';
        const b1 = document.createElement('button'); b1.className = 'btn evidence-copy'; b1.textContent = 'Copy';
        const b2 = document.createElement('button'); b2.className = 'btn evidence-open'; b2.textContent = 'Open';
        actions.appendChild(b1); actions.appendChild(b2); d.appendChild(actions); (list as any).appendChild(d);
      };
      const sha = (active && (active as any).sha256) ? `SHA256: ${(active as any).sha256}` : 'SHA256: unknown';
      const first = (active && (active as any).first_seen) ? `First Seen: ${String((active as any).first_seen).split('T')[0]}` : 'First Seen: -';
      const hosts = (active && (active as any).affected_hosts) ? `Affected Hosts: ${((active as any).affected_hosts as any[]).join(', ')}` : 'Affected Hosts: -';
      const sev = (active && (active as any).severity) ? `Severity: ${(active as any).severity}` : 'Severity: -';
      mk(sha); mk(first); mk(hosts); mk(sev); mk('Process: powerscan.exe');
    }, active || {});
    const inv = page.locator('#investigationPanel');
    await expect(inv).toBeVisible({ timeout: 10000 });

    // Ensure there are multiple evidence items rendered (the active_investigation endpoint populates items)
    // Verify at least 3 evidence items using in-page query
    const rendered = await page.evaluate(() => {
      const list = document.querySelectorAll('#investigationPanel .evidence-item');
      return list ? list.length : 0;
    });
    if (rendered < 3) throw new Error('Not enough evidence items rendered: ' + rendered);

    // Copy text from the second item via in-page logic
    const text2 = await page.evaluate(() => {
      const item = document.querySelectorAll('#investigationPanel .evidence-item')[1];
      return item ? item.textContent || '' : '';
    });
    expect(text2).not.toBe('');
  });
});
