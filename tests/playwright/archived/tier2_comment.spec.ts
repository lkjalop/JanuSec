import { test, expect } from '@playwright/test';

// Minimal E2E for Tier 2 review panel comment submission
// Seeds an incident, opens LIVE console, submits a comment with optional delta, and verifies UI feedback.

test.describe('LIVE console Tier 2 review', () => {
  test('submits Tier 2 comment with evidence-only delta', async ({ page, request }) => {
    // Seed an incident (lite mode routes will accept this)
    const seedResp = await request.post('/api/v1/incidents', {
      data: JSON.stringify({ artifact_id: 'playwright-eid-1', title: 'PW Seed Incident', severity: 'medium' }),
      headers: { 'content-type': 'application/json', 'x-api-key': 'devkey123' },
    });
    expect(seedResp.ok()).toBeTruthy();
    const seedJson = await seedResp.json();
    const iid: string = (seedJson && seedJson.incident && seedJson.incident.id) || '';
    expect(iid).not.toEqual('');

    // Ensure API key is available in console
    await page.addInitScript(() => {
      try{ localStorage.setItem('apiKey','devkey123'); localStorage.setItem('role','tier2'); }catch(_){ }
    });
    await page.goto('/console');

    // Panel visible
    const panel = page.locator('#tier2ReviewPanel');
    await expect(panel).toBeVisible({ timeout: 15000 });

    // Fill form
    await page.locator('#tier2IncidentId').fill(iid);
    await page.locator('#tier2Status').selectOption('endorse');
    await page.locator('#tier2CommentText').fill('Tier 2 endorsement: corroborated by network timeline.');
    await page.locator('#tier2Delta').fill('0.05');
    await page.locator('#tier2ApplyDelta').check();

    // Intercept notification or rely on output area
    const out = page.locator('#tier2SubmitOut');
    await page.locator('#btnTier2Submit').click();

    // Verify the output shows last comment or notification appears
    await expect(out).toContainText(/Last:/, { timeout: 5000 });
  });
});
