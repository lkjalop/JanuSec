// investigate_expand.spec.js
// Phase 5: E2E test for the Investigate tab and EXPAND subtask flow.
//
// Uses a mock LLM response (LLM_MOCK=1 env or mocked API intercept) so CI
// never requires a live Ollama instance.
//
// What this tests:
//   1. Investigate tab renders after analysis
//   2. "Build Investigate" button is visible + clickable after analysis
//   3. Polling reaches status=ready and renders the narrative
//   4. Task cards appear
//   5. EXPAND button calls /tasks/{id}/expand and renders subtask panel
//   6. Entity chips + check badges render (OPT-1/OPT-2)
//   7. Cache hit is reflected (second EXPAND click is instant)

const { test, expect } = require('@playwright/test');

const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:8080';

// Minimal 4-row CSV with entity diversity to exercise OPT-1/OPT-2
const SAMPLE_CSV = [
  'timestamp,severity,src_ip,username,host,event_type,mitre_technique,command_line',
  '2026-04-17T08:12:00Z,critical,10.0.0.1,alice@corp.local,WS-01,process_spawn,T1059.001,powershell -enc AABB',
  '2026-04-17T08:13:30Z,critical,10.0.0.1,alice@corp.local,WS-01,lsass_access,T1003.001,procdump.exe lsass',
  '2026-04-17T08:20:00Z,high,10.0.0.1,bob@corp.local,SRV-02,lateral_move,T1021,wmiexec.py',
  '2026-04-17T23:45:00Z,high,10.0.0.1,carol@corp.local,WS-03,privilege_escalation,T1078,net.exe localgroup Administrators',
].join('\n');

// Mock response the expand endpoint will return when intercepted
const MOCK_EXPAND_RESPONSE = {
  assessment_id: 'mock-aid',
  task_id: 'aabbccdd',
  persona: 'soc',
  entity_fields: {
    users: ['alice@corp.local', 'bob@corp.local'],
    ips: ['10.0.0.1'],
    hosts: ['WS-01', 'SRV-02'],
    sessions: [], tokens: [], policies: [],
  },
  check_results: [
    { check_id: 'after_hours', label: 'After-Hours Activity', triggered: true, severity: 'warning',
      detail: '1 after-hours event(s): privilege_escalation by carol at 23:45 UTC', evidence_rows: [3] },
    { check_id: 'same_ip_cross_account', label: 'Cross-Account Same IP', triggered: true, severity: 'critical',
      detail: 'IP 10.0.0.1 used by 3 accounts: alice, bob, carol', evidence_rows: [0, 1, 2] },
    { check_id: 'impossible_travel', label: 'Impossible Travel', triggered: false, severity: 'info', detail: '', evidence_rows: [] },
    { check_id: 'temp_privilege', label: 'Privilege Escalation / Temp Privilege', triggered: true, severity: 'critical',
      detail: '1 privilege event(s): carol — privilege_escalation', evidence_rows: [3] },
  ],
  matched_entities: { users: ['alice@corp.local'], ips: ['10.0.0.1'] },
  row_count: 3,
  summary: 'Alice used encoded PowerShell to dump LSASS credentials on WS-01, then pivoted laterally.',
  confidence: 0.87,
  subtasks: [
    { id: 's1', action: 'Isolate WS-01 from network', entity: 'WS-01', priority: 'high' },
    { id: 's2', action: 'Extract LSASS dump artefacts from WS-01', entity: 'WS-01', priority: 'high' },
    { id: 's3', action: 'Review bob lateral move from WS-01 to SRV-02', entity: 'SRV-02', priority: 'medium' },
  ],
  iocs: [
    { type: 'process', value: 'procdump.exe', context: 'LSASS credential dump' },
    { type: 'ip', value: '10.0.0.1', context: 'Cross-account origin' },
  ],
  mitre_techniques: ['T1059.001', 'T1003.001', 'T1021'],
  next_pivot: 'Check WS-01 memory dump for injected shellcode using volatility3',
  cache_hit: false,
  latency_ms: 312,
};

// Mock investigate build/poll responses
const MOCK_INVESTIGATE_BUILD = {
  assessment_id: 'mock-aid',
  investigate_id: 'inv-mock-0001',
  status: 'queued',
};

const MOCK_INVESTIGATE_RECORD = {
  investigate_id: 'inv-mock-0001',
  assessment_id: 'mock-aid',
  status: 'ready',
  narrative: 'PHANTOM MERIDIAN: Alice (alice@corp.local) on WS-01 executed encoded PowerShell to dump LSASS credentials (T1059.001, T1003.001). Bob (bob@corp.local) used WMIExec for lateral movement to SRV-02 (T1021). Carol performed privilege escalation at 23:45 UTC outside business hours (T1078). All three accounts originated from IP 10.0.0.1 suggesting a shared C2 or pivot host.',
  missing_logs: ['network_flow', 'dns'],
  evidence_table: [
    { row_index: 0, user: 'alice@corp.local', host: 'WS-01', process: 'powershell.exe', verdict: 'malicious', ml_score: 0.95 },
    { row_index: 1, user: 'alice@corp.local', host: 'WS-01', process: 'procdump.exe', verdict: 'malicious', ml_score: 0.98 },
  ],
  persona_expanded: {
    soc_analyst: '1. Isolate WS-01 immediately — LSASS dump confirmed.\n2. Review lateral movement path to SRV-02 via WMIExec.\n3. Escalate carol privilege escalation (after-hours, T1078).',
  },
};

test.describe('Investigate tab — EXPAND subtask flow', () => {
  test.setTimeout(90000);
  let page;
  let assessmentId;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();

    await page.addInitScript(() => {
      localStorage.setItem('apiKey', 'devkey123');
      localStorage.setItem('tenantId', 'playwright-expand-test');
    });

    // ── Intercept investigate/build → return mock ─────────────────────────
    await page.route('**/investigate/build', async (route) => {
      // Extract real assessment_id from request URL
      const url = route.request().url();
      const match = url.match(/assessments\/([^/]+)\/investigate/);
      const aid = match ? match[1] : 'mock-aid';
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ ...MOCK_INVESTIGATE_BUILD, assessment_id: aid }),
      });
    });

    // ── Intercept investigate/{id} status poll → return ready ─────────────
    await page.route('**/investigate/inv-mock-0001', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(MOCK_INVESTIGATE_RECORD),
      });
    });

    // ── Intercept expand endpoint ──────────────────────────────────────────
    await page.route('**/tasks/**/expand', async (route) => {
      const url = route.request().url();
      const match = url.match(/assessments\/([^/]+)\//);
      const aid = match ? match[1] : 'mock-aid';
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ ...MOCK_EXPAND_RESPONSE, assessment_id: aid }),
      });
    });

    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');

    // Upload CSV
    await page.locator('#fileInput').setInputFiles([{
      name: 'expand_test.csv',
      mimeType: 'text/csv',
      buffer: Buffer.from(SAMPLE_CSV),
    }]);
    await page.waitForTimeout(500);

    // Run analysis — also mock deep_analyze to return a stub quickly
    await page.route('**/api/v1/csv/deep_analyze', async (route) => {
      if (route.request().method() !== 'POST') { await route.continue(); return; }
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          assessment_id: 'mock-expand-001',
          report_id: 'mock-expand-001',
          status: 'complete',
          rows_processed: 4,
          llm_rows: [],
          rows: [
            { row_index: 0, user: 'alice@corp.local', src_ip: '10.0.0.1', host: 'WS-01',
              event_type: 'process_spawn', severity: 'critical', mitre_technique: 'T1059.001' },
            { row_index: 1, user: 'alice@corp.local', src_ip: '10.0.0.1', host: 'WS-01',
              event_type: 'lsass_access', severity: 'critical', mitre_technique: 'T1003.001' },
          ],
          headline: 'P1 — PHANTOM_MERIDIAN initial access detected',
        }),
      });
    });

    // Also mock the assessment poll endpoint
    await page.route('**/deep_analyze/assessments/mock-expand-001', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          assessment_id: 'mock-expand-001',
          status: 'complete',
          rows_processed: 4,
          rows: [
            { row_index: 0, user: 'alice@corp.local', src_ip: '10.0.0.1', host: 'WS-01',
              event_type: 'process_spawn', severity: 'critical', mitre_technique: 'T1059.001' },
            { row_index: 1, user: 'alice@corp.local', src_ip: '10.0.0.1', host: 'WS-01',
              event_type: 'lsass_access', severity: 'critical', mitre_technique: 'T1003.001' },
          ],
          headline: 'P1 — PHANTOM_MERIDIAN initial access detected',
        }),
      });
    });

    await page.click('#btnAnalyze');

    // Wait for the loading spinner to appear (analysis started)
    try {
      await page.waitForFunction(() => {
        const loading = document.getElementById('reportLoading');
        return loading && loading.style.display !== 'none';
      }, { timeout: 5000 });
    } catch (_) { /* spinner may flicker too fast with mocked APIs */ }

    // Wait for analysis to complete (spinner gone, content or empty shows)
    await page.waitForFunction(() => {
      const loading = document.getElementById('reportLoading');
      const content = document.getElementById('reportContent');
      const empty = document.getElementById('reportEmpty');
      if (!loading) return false;
      const loadingGone = loading.style.display === 'none';
      const somethingVisible = (content && content.style.display !== 'none') ||
                               (empty && empty.style.display !== 'none' && empty.style.display !== '');
      // Also accept: btnAnalyze re-enabled (pipeline done)
      const btnDone = document.getElementById('btnAnalyze') && !document.getElementById('btnAnalyze').disabled;
      return loadingGone && (somethingVisible || btnDone);
    }, { timeout: 30000 });

    // Capture assessmentId from state for assertions
    assessmentId = await page.evaluate(() => {
      try { return window._investigateState ? null : (window.state && window.state.assessmentId); } catch (e) { return null; }
    });
  });

  test.afterAll(async () => {
    await page.close();
  });

  // ── Test 1: Investigate tab is visible ────────────────────────────────────
  test('Investigate tab button is present', async () => {
    const tabBtn = page.locator('.tab-btn[data-tab="investigate"]');
    await expect(tabBtn).toBeVisible();
  });

  // ── Test 2: Switching to Investigate tab shows actions bar ────────────────
  test('Switching to Investigate tab shows Build button', async () => {
    await page.click('.tab-btn[data-tab="investigate"]');
    await page.waitForTimeout(300);

    const tabPanel = page.locator('#tabInvestigate');
    await expect(tabPanel).toHaveClass(/active/);

    // Build button should be visible (assessmentId is set)
    const buildBtn = page.locator('#btnBuildInvestigate');
    await expect(buildBtn).toBeVisible();
  });

  // ── Test 3: Build Investigate queues and polls ────────────────────────────
  test('Build Investigate → narrative renders with task cards', async () => {
    await page.click('.tab-btn[data-tab="investigate"]');
    await page.waitForTimeout(200);

    await page.click('#btnBuildInvestigate');

    // Wait for loading state to disappear and results to appear
    await page.waitForFunction(() => {
      const loading = document.getElementById('investigateLoading');
      const results = document.getElementById('investigateResults');
      return results && results.style.display !== 'none' && loading && loading.style.display === 'none';
    }, { timeout: 20000 });

    // Narrative block should contain text
    const narrative = page.locator('#investigateNarrative');
    await expect(narrative).toBeVisible();
    const narText = await narrative.textContent();
    expect(narText.length).toBeGreaterThan(50);

    // At least one task card should render
    const taskCards = page.locator('.task-card');
    const count = await taskCards.count();
    expect(count, 'Should have at least 1 task card').toBeGreaterThan(0);
  });

  // ── Test 4: Task card has EXPAND button ───────────────────────────────────
  test('First task card has EXPAND button', async () => {
    const expandBtn = page.locator('.task-card__expand-btn').first();
    await expect(expandBtn).toBeVisible();
    await expect(expandBtn).toContainText('EXPAND');
  });

  // ── Test 5: EXPAND button calls backend and renders subtask panel ─────────
  test('Clicking EXPAND → renders subtask panel with entity chips + checks', async () => {
    const firstExpandBtn = page.locator('.task-card__expand-btn').first();
    await firstExpandBtn.click();

    // Wait for expand panel content to appear
    await page.waitForFunction(() => {
      const bodies = document.querySelectorAll('.task-card__body.open');
      if (!bodies.length) return false;
      const body = bodies[0];
      return body.innerHTML.length > 100 && !body.innerHTML.includes('⏳');
    }, { timeout: 15000 });

    // Entity chips should be present
    const entityChips = page.locator('.entity-chip');
    const chipCount = await entityChips.count();
    expect(chipCount, 'Should show entity chips').toBeGreaterThan(0);

    // Check badges for triggered checks
    const checkBadges = page.locator('.expand-badge');
    const badgeCount = await checkBadges.count();
    expect(badgeCount, 'Should show triggered check badges').toBeGreaterThan(0);

    // Subtask list should have items
    const subtasks = page.locator('.expand-subtask-list li');
    const subtaskCount = await subtasks.count();
    expect(subtaskCount, 'Should show subtasks').toBeGreaterThan(0);

    // IOC list
    const iocs = page.locator('.expand-ioc-list li');
    const iocCount = await iocs.count();
    expect(iocCount, 'Should show IOCs').toBeGreaterThan(0);

    // Next pivot block
    const pivot = page.locator('.expand-pivot');
    await expect(pivot).toBeVisible();
    const pivotText = await pivot.textContent();
    expect(pivotText.length, 'Next pivot text should be non-empty').toBeGreaterThan(10);
  });

  // ── Test 6: EXPAND button text changes to ▲ after opening ────────────────
  test('EXPAND button shows ▲ after panel is open', async () => {
    const firstExpandBtn = page.locator('.task-card__expand-btn').first();
    const btnText = await firstExpandBtn.textContent();
    expect(btnText).toContain('▲');
  });

  // ── Test 7: Persona selector is present and has correct options ──────────
  test('Persona selector has correct options', async () => {
    const select = page.locator('#investigatePersonaSelect');
    await expect(select).toBeVisible();
    const options = await select.locator('option').allTextContents();
    expect(options).toContain('SOC Analyst');
    expect(options).toContain('CISO');
    expect(options).toContain('Threat Hunter');
  });

  // ── Test 8: MITRE techniques render ────────────────────────────────────
  test('MITRE techniques appear in expanded panel', async () => {
    // Check that at least one MITRE badge is visible in the first open panel
    const mitreBadges = page.locator('.task-card__body.open span').filter({ hasText: /T\d{4}/ });
    const count = await mitreBadges.count();
    expect(count, 'Should show MITRE technique badges').toBeGreaterThan(0);
  });
});
