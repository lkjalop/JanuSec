import { test, expect } from '@playwright/test';

// This spec requires the server to be running with ADMIN_API_KEY=devkey123 (or set in env)
const ADMIN_KEY = process.env.ADMIN_API_KEY || process.env.API_KEY || 'devkey123';

test('admin factors end-to-end propose & approve flow', async ({ request }) => {
  const headers = { 'x-admin-key': ADMIN_KEY };
  // Post feedback
  const fb = await request.post('/api/v1/admin/factors/feedback', {
    headers,
    data: { event_id: 'test-evt-1', factors: ['supply_chain:script_abuse'], vote: 1 }
  });
  expect(fb.ok()).toBeTruthy();
  const fbj = await fb.json();
  expect(fbj.status).toBe('ok');

  // List candidates (may be empty initially)
  const c = await request.get('/api/v1/admin/factors/candidates', { headers });
  expect(c.ok()).toBeTruthy();
  const cj = await c.json();
  // Approve first candidate if present (best-effort)
  if (cj.candidates && cj.candidates.length > 0) {
    const candidate = cj.candidates[0];
    const ap = await request.post(`/api/v1/admin/factors/candidates/${candidate.id}/approve`, { headers, data: { actor: 'playwright-test', current_weights: {} } });
    expect(ap.ok()).toBeTruthy();
    const apj = await ap.json();
    expect(apj.status).toBe('approved');
  }
});
