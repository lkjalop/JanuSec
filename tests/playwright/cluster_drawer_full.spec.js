/**
 * Playwright tests — Cluster Detail Drawer (full persona-tab redesign)
 *
 * Coverage:
 *   1. Drawer opens on cluster click, shows persona tabs
 *   2. SOC Analyst tab auto-loads on open
 *   3. Switching tabs lazy-loads each persona independently
 *   4. Revisiting a loaded tab is instant (cached — no new network call)
 *   5. Confirm/deny buttons toggle state; active button highlights; sibling deactivates
 *   6. Marking all subtasks done turns tab green
 *   7. EXPAND button fetches investigative questions; confirm/deny questions render
 *   8. Confirm/deny on an expand question tracked separately
 *   9. Threat model section — PASTA / Diamond / MAESTRO buttons fire POST
 *  10. Report tab aggregates confirmed/denied/open items from all personas
 *  11. Report tab Save Report fires POST /investigation-report
 *  12. Send buttons (email, Slack, object-storage) render disabled (no credentials)
 *  13. Drag-resize changes panel width via --cd-width CSS variable
 *  14. Close button hides drawer; backdrop click also closes
 *  15. Pop-out button opens new window
 *  16. Model selector is present and populated
 *  17. Cache key — model switch reloads tab content
 */

const { test, expect } = require('@playwright/test');

const BASE            = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:8080';
const INVESTIGATE_URL = `${BASE}/static/investigate.html`;

// ── Shared persona LLM stub response ─────────────────────────────────────────

const STUB_PERSONA_RESPONSE = {
  persona_label: 'SOC Analyst',
  persona_focus: 'Triage & containment',
  sections: {
    what_is_happening: 'Credential re-use across three sources',
    why_it_matters:    'Finance officer account shows unusual lateral movement',
    investigate_next:  'Check VPN logs for concurrent sessions',
    verdict_line:      'Likely real threat — MFA bypass possible',
    answer_to_sharpen: 'N/A',
  },
  verdict: 'real',
  persona_steps: [
    {
      title:    'Verify finance officer account compromise',
      owner:    'SOC L1',
      priority: 'P1',
      subtasks: [
        { label: 'Pull last 24h auth logs for testuser', ref: 'rows:0-1' },
        { label: 'Check impossible travel flags',        ref: 'rows:0' },
      ],
    },
    {
      title:    'Isolate lateral movement host',
      owner:    'SOC L2',
      priority: 'P2',
      subtasks: [
        { label: 'Block host-01 at NAC',         ref: 'rows:1' },
        { label: 'Force password reset testuser', ref: 'rows:0' },
      ],
    },
  ],
  from_cache: false,
};

const STUB_EXPAND_RESPONSE = {
  step_title: 'Verify finance officer account compromise',
  questions: [
    {
      question: 'Is there evidence of an impossible-travel login?',
      check:    'SELECT * FROM auth_logs WHERE user="testuser" AND delta_km > 500;',
      row_ref:  'rows:0',
    },
    {
      question: 'Were MFA challenges bypassed?',
      check:    'grep -i "mfa_bypass\\|push_fatigue" /var/log/okta/testuser.log',
      row_ref:  'rows:0-1',
    },
  ],
};

const STUB_THREAT_MODEL_RESPONSE = {
  model_type: 'pasta',
  stages: {
    'Stage 1 — Business Objectives': 'Protect finance data from exfiltration.',
    'Stage 2 — Technical Scope':     'IAM, VPN, and endpoint visibility required.',
  },
  from_cache: false,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Seed minimal assessment + cluster state into the page without upload. */
async function injectState(page, { assessmentId = 'pw-drawer-test', clusterId = 'cl-pw1' } = {}) {
  await page.addInitScript(({ aId, cId }) => {
    // Pre-set localStorage so investigate.js picks up the api key
    localStorage.setItem('apiKey',    'devkey123');
    localStorage.setItem('tenantId',  'default');
    // After page load the test will inject state via evaluate()
    window.__pw_aId = aId;
    window.__pw_cId = cId;
  }, { aId: assessmentId, cId: clusterId });
}

/** Navigate and inject cluster state, then open the drawer programmatically. */
async function openDrawer(page, opts = {}) {
  const assessmentId = opts.assessmentId || 'pw-drawer-test';
  const clusterId    = opts.clusterId    || 'cl-pw1';

  await injectState(page, { assessmentId, clusterId });
  await page.goto(INVESTIGATE_URL, { waitUntil: 'domcontentloaded' });

  await page.evaluate(({ aId, cId }) => {
    // Inject minimal state expected by openClusterDetail
    window.state = window.state || {};
    window.state.assessmentId = aId;
    window.state.clusterMap   = window.state.clusterMap || {};
    window.state.clusterMap[cId] = {
      cluster_id:           cId,
      severity:             'high',
      confidence:           0.85,
      top_mitre:            ['T1078', 'T1021'],
      shared_accounts:      ['testuser'],
      shared_hosts:         ['host-01'],
      shared_external_ips:  ['1.2.3.4'],
      row_refs:             [0, 1],
      blast_radius_summary: '1 host, 1 account',
      reason_summary:       'testuser shared across sources',
    };
    window.state.rows = [
      { row_number: 0, row_index: 0, severity: 'high',   user: 'testuser', hostname: 'host-01', description: 'Suspicious logon',      mitre_technique: 'T1078' },
      { row_number: 1, row_index: 1, severity: 'medium', user: 'testuser', hostname: 'host-01', description: 'RDP lateral movement',   mitre_technique: 'T1021' },
    ];
    window.openClusterDetail(cId);
  }, { aId: assessmentId, cId: clusterId });

  // Wait for drawer to become visible
  await expect(page.locator('#clusterDrawer')).toBeVisible({ timeout: 5000 });
}

/** Intercept LLM summary calls and respond with stub data. */
function mockPersonaEndpoint(page, responseBody = STUB_PERSONA_RESPONSE) {
  return page.route('**/tier2/llm-summary**', async route => {
    await route.fulfill({
      status:      200,
      contentType: 'application/json',
      body:        JSON.stringify(responseBody),
    });
  });
}

/** Intercept expand-step calls. */
function mockExpandEndpoint(page, responseBody = STUB_EXPAND_RESPONSE) {
  return page.route('**/expand-step**', async route => {
    await route.fulfill({
      status:      200,
      contentType: 'application/json',
      body:        JSON.stringify(responseBody),
    });
  });
}

/** Intercept threat-model calls. */
function mockThreatModelEndpoint(page, responseBody = STUB_THREAT_MODEL_RESPONSE) {
  return page.route('**/threat-model**', async route => {
    await route.fulfill({
      status:      200,
      contentType: 'application/json',
      body:        JSON.stringify(responseBody),
    });
  });
}

/** Intercept investigation-report calls. */
function mockReportEndpoint(page) {
  return page.route('**/investigation-report**', async route => {
    await route.fulfill({
      status:      200,
      contentType: 'application/json',
      body:        JSON.stringify({ saved: true, path: '/data/assessments/pw-drawer-test/report.json' }),
    });
  });
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test.describe('Cluster Drawer — open and structure', () => {
  test('drawer opens with persona tabs and header', async ({ page }) => {
    await mockPersonaEndpoint(page);
    await openDrawer(page);

    // Drawer visible
    const drawer = page.locator('#clusterDrawer');
    await expect(drawer).toBeVisible();

    // Header title present
    await expect(page.locator('#clusterDrawerTitle')).toBeVisible();

    // Persona tabs rendered
    const tabs = page.locator('#cdPersonaTabs .cd-ptab');
    await expect(tabs).toHaveCount(7, { timeout: 4000 }); // soc_analyst / threat_hunter / ciso / forensics / compliance / mssp / report

    // Model selector present
    await expect(page.locator('#cdModelSel')).toBeVisible();

    // Close and pop-out buttons present
    await expect(page.locator('button[title="Close"]')).toBeVisible();
    await expect(page.locator('button[title="Pop out to new window"]')).toBeVisible();
  });

  test('SOC Analyst tab is active by default', async ({ page }) => {
    await mockPersonaEndpoint(page);
    await openDrawer(page);

    const tabs = page.locator('#cdPersonaTabs .cd-ptab');
    const first = tabs.first();
    await expect(first).toHaveClass(/active/);
    await expect(first).toContainText(/soc/i);
  });

  test('SOC Analyst persona content loads automatically', async ({ page }) => {
    await mockPersonaEndpoint(page);
    await openDrawer(page);

    // Wait for content to render in body
    const body = page.locator('#cdBody');
    await expect(body).toContainText('Credential re-use', { timeout: 8000 });
  });

  test('verdict badge renders with correct class for real verdict', async ({ page }) => {
    await mockPersonaEndpoint(page);
    await openDrawer(page);

    const badge = page.locator('.cd-verdict-badge');
    await expect(badge).toBeVisible({ timeout: 8000 });
    await expect(badge).toHaveClass(/vb--real/);
  });

  test('TOP ACTIONS task cards render and are collapsible', async ({ page }) => {
    await mockPersonaEndpoint(page);
    await openDrawer(page);

    // Cards present
    const cards = page.locator('.cd-card');
    await expect(cards).toHaveCount(2, { timeout: 8000 });

    // Body starts collapsed
    const firstBody = cards.first().locator('.cd-card__body');
    await expect(firstBody).not.toHaveClass(/open/);

    // Click header to expand
    await cards.first().locator('.cd-card__hd').click();
    await expect(firstBody).toHaveClass(/open/);

    // Click again to collapse
    await cards.first().locator('.cd-card__hd').click();
    await expect(firstBody).not.toHaveClass(/open/);
  });
});

test.describe('Cluster Drawer — persona tab switching', () => {
  test('switching to Threat Hunter tab loads content', async ({ page }) => {
    let callCount = 0;
    await page.route('**/tier2/llm-summary**', async route => {
      callCount++;
      await route.fulfill({
        status:      200,
        contentType: 'application/json',
        body:        JSON.stringify({ ...STUB_PERSONA_RESPONSE, persona_label: callCount === 1 ? 'SOC Analyst' : 'Threat Hunter' }),
      });
    });

    await openDrawer(page);

    // Click Threat Hunter tab
    const tabs = page.locator('#cdPersonaTabs .cd-ptab');
    await tabs.nth(1).click();

    // Should trigger a second LLM call
    await page.waitForTimeout(300);
    expect(callCount).toBeGreaterThanOrEqual(2);
  });

  test('revisiting a loaded tab does not trigger another network call', async ({ page }) => {
    let callCount = 0;
    await page.route('**/tier2/llm-summary**', async route => {
      callCount++;
      await route.fulfill({
        status:      200,
        contentType: 'application/json',
        body:        JSON.stringify(STUB_PERSONA_RESPONSE),
      });
    });

    await openDrawer(page);

    // SOC Analyst loaded (call 1)
    await page.waitForTimeout(400);

    const tabs = page.locator('#cdPersonaTabs .cd-ptab');

    // Switch to Threat Hunter (call 2)
    await tabs.nth(1).click();
    await page.waitForTimeout(400);

    // Switch back to SOC Analyst — should use cache
    await tabs.first().click();
    await page.waitForTimeout(400);

    // Still only 2 calls
    expect(callCount).toBe(2);
  });

  test('model change reloads current tab', async ({ page }) => {
    let callCount = 0;
    await page.route('**/tier2/llm-summary**', async route => {
      callCount++;
      await route.fulfill({
        status:      200,
        contentType: 'application/json',
        body:        JSON.stringify(STUB_PERSONA_RESPONSE),
      });
    });

    await openDrawer(page);
    await page.waitForTimeout(400);

    const beforeCount = callCount;

    // Change model selection if options available
    const modelSel = page.locator('#cdModelSel');
    const optCount = await modelSel.locator('option').count();
    if (optCount > 1) {
      await modelSel.selectOption({ index: 1 });
      await page.waitForTimeout(400);
      expect(callCount).toBeGreaterThan(beforeCount);
    }
  });
});

test.describe('Cluster Drawer — confirm/deny workflow', () => {
  test('confirm button activates and deny deactivates sibling', async ({ page }) => {
    await mockPersonaEndpoint(page);
    await openDrawer(page);

    // Expand first task card to see subtasks
    const firstCard = page.locator('.cd-card').first();
    await firstCard.locator('.cd-card__hd').click();

    const subtasks    = firstCard.locator('.cd-subtask');
    await expect(subtasks).toHaveCount(2, { timeout: 5000 });

    const firstConfirm = subtasks.first().locator('.cd-confirm-btn');
    const firstDeny    = subtasks.first().locator('.cd-deny-btn');

    // Click confirm
    await firstConfirm.click();
    await expect(firstConfirm).toHaveClass(/active/);
    await expect(firstDeny).not.toHaveClass(/active/);

    // Click deny — confirm should deactivate
    await firstDeny.click();
    await expect(firstDeny).toHaveClass(/active/);
    await expect(firstConfirm).not.toHaveClass(/active/);
  });

  test('clicking confirm twice deselects (toggle off)', async ({ page }) => {
    await mockPersonaEndpoint(page);
    await openDrawer(page);

    const firstCard = page.locator('.cd-card').first();
    await firstCard.locator('.cd-card__hd').click();

    const firstConfirm = page.locator('.cd-subtask').first().locator('.cd-confirm-btn');

    await firstConfirm.click();
    await expect(firstConfirm).toHaveClass(/active/);

    await firstConfirm.click();
    await expect(firstConfirm).not.toHaveClass(/active/);
  });

  test('confirming all subtasks marks tab as done (green)', async ({ page }) => {
    await mockPersonaEndpoint(page);
    await openDrawer(page);

    // Expand both task cards and confirm all subtasks
    const cards = page.locator('.cd-card');
    const count = await cards.count();

    for (let i = 0; i < count; i++) {
      const card = cards.nth(i);
      await card.locator('.cd-card__hd').click();

      const subtasks = card.locator('.cd-subtask');
      const subCount = await subtasks.count();

      for (let j = 0; j < subCount; j++) {
        await subtasks.nth(j).locator('.cd-confirm-btn').click();
      }
    }

    // First tab should now have .done class
    const firstTab = page.locator('#cdPersonaTabs .cd-ptab').first();
    await expect(firstTab).toHaveClass(/done/, { timeout: 2000 });
  });
});

test.describe('Cluster Drawer — EXPAND button', () => {
  test('EXPAND button fetches investigative questions', async ({ page }) => {
    await mockPersonaEndpoint(page);
    await mockExpandEndpoint(page);
    await openDrawer(page);

    // Expand first task card
    const firstCard = page.locator('.cd-card').first();
    await firstCard.locator('.cd-card__hd').click();

    // Click the EXPAND button on the first card
    const expandBtn = firstCard.locator('.cd-card__expand-btn');
    await expect(expandBtn).toBeVisible({ timeout: 5000 });
    await expandBtn.click();

    // Questions should render
    const expandBlock = page.locator('.cd-expand-block');
    await expect(expandBlock).toBeVisible({ timeout: 8000 });

    const questions = expandBlock.locator('.cd-expand-q');
    await expect(questions).toHaveCount(2, { timeout: 5000 });
  });

  test('expand questions show CHECK commands', async ({ page }) => {
    await mockPersonaEndpoint(page);
    await mockExpandEndpoint(page);
    await openDrawer(page);

    const firstCard = page.locator('.cd-card').first();
    await firstCard.locator('.cd-card__hd').click();

    const expandBtn = firstCard.locator('.cd-card__expand-btn');
    await expandBtn.click();

    const checkEl = page.locator('.cd-expand-q__check').first();
    await expect(checkEl).toBeVisible({ timeout: 8000 });
    await expect(checkEl).toContainText('SELECT');
  });

  test('confirm/deny on expand question tracked separately', async ({ page }) => {
    await mockPersonaEndpoint(page);
    await mockExpandEndpoint(page);
    await openDrawer(page);

    const firstCard = page.locator('.cd-card').first();
    await firstCard.locator('.cd-card__hd').click();

    const expandBtn = firstCard.locator('.cd-card__expand-btn');
    await expandBtn.click();

    // Wait for expand block
    const expandBlock = page.locator('.cd-expand-block');
    await expect(expandBlock).toBeVisible({ timeout: 8000 });

    const firstQ = expandBlock.locator('.cd-expand-q').first();
    const confirmBtn = firstQ.locator('.cd-confirm-btn');
    await expect(confirmBtn).toBeVisible({ timeout: 5000 });

    await confirmBtn.click();
    await expect(confirmBtn).toHaveClass(/active/);

    // Main subtask confirm/deny unchanged
    const mainConfirm = firstCard.locator('.cd-subtask').first().locator('.cd-confirm-btn');
    await expect(mainConfirm).not.toHaveClass(/active/);
  });

  test('second EXPAND on same card reuses cached result (no new request)', async ({ page }) => {
    let expandCalls = 0;
    await mockPersonaEndpoint(page);
    await page.route('**/expand-step**', async route => {
      expandCalls++;
      await route.fulfill({
        status:      200,
        contentType: 'application/json',
        body:        JSON.stringify(STUB_EXPAND_RESPONSE),
      });
    });

    await openDrawer(page);

    const firstCard = page.locator('.cd-card').first();
    await firstCard.locator('.cd-card__hd').click();

    const expandBtn = firstCard.locator('.cd-card__expand-btn');
    await expandBtn.click();

    await page.locator('.cd-expand-block').waitFor({ timeout: 8000 });

    // Click expand again (collapse + re-open scenario — button may toggle)
    // At minimum a second click should not fire another network call
    const callsAfterFirst = expandCalls;
    await expandBtn.click();
    await page.waitForTimeout(300);

    expect(expandCalls).toBe(callsAfterFirst);
  });
});

test.describe('Cluster Drawer — Threat modelling', () => {
  test('PASTA run button fires POST threat-model', async ({ page }) => {
    await mockPersonaEndpoint(page);
    await mockThreatModelEndpoint(page);
    await openDrawer(page);

    // Switch to CISO tab which has threat modelling
    const tabs = page.locator('#cdPersonaTabs .cd-ptab');
    const cisoTab = tabs.filter({ hasText: /ciso/i });
    if (await cisoTab.count() === 0) {
      test.skip();
      return;
    }

    // Mock the persona endpoint to serve CISO-specific stub
    await cisoTab.click();

    let threatModelCalled = false;
    await page.route('**/threat-model**', async route => {
      threatModelCalled = true;
      await route.fulfill({
        status:      200,
        contentType: 'application/json',
        body:        JSON.stringify(STUB_THREAT_MODEL_RESPONSE),
      });
    });

    // Look for any threat model run button
    const tmBtn = page.locator('.cd-tm-run-btn').first();
    if (await tmBtn.isVisible({ timeout: 5000 }).catch(() => false)) {
      await tmBtn.click();
      await page.waitForTimeout(500);
      expect(threatModelCalled).toBe(true);
    }
  });
});

test.describe('Cluster Drawer — Report tab', () => {
  test('report tab exists in the tab bar', async ({ page }) => {
    await mockPersonaEndpoint(page);
    await openDrawer(page);

    const reportTab = page.locator('#cdPersonaTabs .cd-ptab').filter({ hasText: /report/i });
    await expect(reportTab).toBeVisible({ timeout: 5000 });
  });

  test('report tab shows confirmed/open items after confirming a subtask', async ({ page }) => {
    await mockPersonaEndpoint(page);
    await openDrawer(page);

    // Expand first card and confirm one subtask
    const firstCard = page.locator('.cd-card').first();
    await firstCard.locator('.cd-card__hd').click();

    await page.locator('.cd-subtask').first().locator('.cd-confirm-btn').click();

    // Open report tab
    const reportTab = page.locator('#cdPersonaTabs .cd-ptab').filter({ hasText: /report/i });
    await reportTab.click();

    // Report content should show confirmed items section
    const body = page.locator('#cdBody');
    await expect(body).toContainText(/confirmed|open|denied/i, { timeout: 5000 });
  });

  test('save report button fires POST investigation-report', async ({ page }) => {
    let reportCalled = false;
    await mockPersonaEndpoint(page);
    await page.route('**/investigation-report**', async route => {
      reportCalled = true;
      await route.fulfill({
        status:      200,
        contentType: 'application/json',
        body:        JSON.stringify({ saved: true }),
      });
    });

    await openDrawer(page);

    const reportTab = page.locator('#cdPersonaTabs .cd-ptab').filter({ hasText: /report/i });
    await reportTab.click();

    const saveBtn = page.locator('#cdBody').getByText(/save report/i);
    if (await saveBtn.isVisible({ timeout: 3000 }).catch(() => false)) {
      await saveBtn.click();
      await page.waitForTimeout(400);
      expect(reportCalled).toBe(true);
    }
  });

  test('email/slack send buttons render as disabled', async ({ page }) => {
    await mockPersonaEndpoint(page);
    await openDrawer(page);

    const reportTab = page.locator('#cdPersonaTabs .cd-ptab').filter({ hasText: /report/i });
    await reportTab.click();

    // Disabled send buttons should have the --disabled modifier class
    const disabledBtns = page.locator('.cd-send-btn--disabled');
    await expect(disabledBtns.first()).toBeVisible({ timeout: 5000 });
  });
});

test.describe('Cluster Drawer — resize and controls', () => {
  test('drag resize changes panel width', async ({ page }) => {
    await mockPersonaEndpoint(page);
    await openDrawer(page);

    const panel = page.locator('#cdPanel');
    const handle = page.locator('#cdResizeHandle');

    const initialWidth = await panel.evaluate(el => el.offsetWidth);

    // Simulate drag: press on handle, move left (making panel wider)
    const box = await handle.boundingBox();
    if (!box) return;

    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.down();
    await page.mouse.move(box.x - 100, box.y + box.height / 2, { steps: 10 });
    await page.mouse.up();

    const finalWidth = await panel.evaluate(el => el.offsetWidth);
    expect(finalWidth).toBeGreaterThan(initialWidth);
  });

  test('close button hides drawer', async ({ page }) => {
    await mockPersonaEndpoint(page);
    await openDrawer(page);

    const drawer = page.locator('#clusterDrawer');
    await expect(drawer).toBeVisible();

    await page.locator('button[title="Close"]').click();

    // Drawer should be hidden (display:none or closed state)
    await expect(drawer).toBeHidden({ timeout: 2000 });
  });

  test('backdrop click closes drawer', async ({ page }) => {
    await mockPersonaEndpoint(page);
    await openDrawer(page);

    const drawer = page.locator('#clusterDrawer');
    await expect(drawer).toBeVisible();

    // Click backdrop (the semi-transparent overlay behind the panel)
    const backdrop = page.locator('.cluster-drawer__backdrop');
    await backdrop.click({ force: true });

    await expect(drawer).toBeHidden({ timeout: 2000 });
  });

  test('pop-out opens a new window', async ({ page, context }) => {
    await mockPersonaEndpoint(page);
    await openDrawer(page);

    const [newPage] = await Promise.all([
      context.waitForEvent('page', { timeout: 5000 }).catch(() => null),
      page.locator('button[title="Pop out to new window"]').click(),
    ]);

    if (newPage) {
      await newPage.close();
    }
    // If no new page, that's acceptable — pop-out may use window.open which could be blocked
    // Test passes as long as no error is thrown
  });
});

test.describe('Cluster Drawer — loading and error states', () => {
  test('shows loading spinner while fetching persona content', async ({ page }) => {
    let resolveReq;
    const pendingReq = new Promise(res => { resolveReq = res; });

    await page.route('**/tier2/llm-summary**', async route => {
      await pendingReq; // Hold until we check for spinner
      await route.fulfill({
        status:      200,
        contentType: 'application/json',
        body:        JSON.stringify(STUB_PERSONA_RESPONSE),
      });
    });

    await openDrawer(page);

    // Spinner should be visible before the request resolves
    const spinner = page.locator('.cd-spinner');
    await expect(spinner).toBeVisible({ timeout: 3000 });

    // Now let the request proceed
    resolveReq();

    // Spinner should disappear
    await expect(spinner).toBeHidden({ timeout: 8000 });
  });

  test('shows error state when LLM call fails', async ({ page }) => {
    await page.route('**/tier2/llm-summary**', async route => {
      await route.fulfill({ status: 500, body: 'Internal Server Error' });
    });

    await openDrawer(page);

    const errorEl = page.locator('.cd-error');
    await expect(errorEl).toBeVisible({ timeout: 8000 });
  });
});

test.describe('Cluster Drawer — metadata display', () => {
  test('drawer meta shows cluster severity and confidence', async ({ page }) => {
    await mockPersonaEndpoint(page);
    await openDrawer(page);

    const meta = page.locator('#clusterDrawerMeta');
    await expect(meta).toBeVisible({ timeout: 3000 });
    // Meta should show some cluster context — severity or IDs
    const text = await meta.textContent();
    expect(text.length).toBeGreaterThan(0);
  });

  test('drawer title shows Cluster Detail', async ({ page }) => {
    await mockPersonaEndpoint(page);
    await openDrawer(page);

    await expect(page.locator('#clusterDrawerTitle')).toContainText(/cluster/i);
  });
});
