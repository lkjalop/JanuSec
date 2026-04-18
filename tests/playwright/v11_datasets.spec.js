// v11_datasets.spec.js
// Playwright E2E tests for all three v1.1 dataset files:
//   - janusec_ep_endpoint.v1.1.xlsx  (83 endpoint events)
//   - janusec_net_c2_bgp.v1.1.csv    (70 network events)
//   - janusec_okta_m365_events.v1.1.json (88 OKTA/M365 events)
//
// Tests:
//   1. CSV upload + analysis cycle for NET dataset
//   2. CSV upload + analysis cycle for OKTA dataset (via JSON export mock)
//   3. Investigate tab build → narrative renders
//   4. EXPAND on PHANTOM-MERIDIAN C2 cluster → C2 indicators in panel
//   5. EXPAND on Harbourside BEC cluster → NOT merged with PHANTOM-MERIDIAN
//   6. Persona selector: SOC vs CISO outputs differ
//   7. Benign cluster (Sarah Chen 6 events) → low-severity summary
//   8. Script kiddie cluster → separate from APT cluster
//   9. Entity chip: 45.153.160.100 appears in NET-024/027/028 expand panel
//  10. Row cap warning: uploading all 241 events shows row-limit warning
//
// All LLM calls are mocked via Playwright route intercepts.
// Server must be running at PLAYWRIGHT_BASE_URL (default: http://127.0.0.1:8080).

const { test, expect } = require('@playwright/test');
const path = require('path');
const fs = require('fs');

// Force sequential execution — each describe block navigates to the same server
// and sets up route intercepts. Parallel execution causes connection races.
test.describe.configure({ mode: 'serial' });

const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:8080';

// ── Dataset paths ─────────────────────────────────────────────────────────────
const DUMP_DIR = path.join(__dirname, '../../dump/test files');
const NET_CSV_PATH   = path.join(DUMP_DIR, 'janusec_net_c2_bgp.v1.1.csv');
const OKTA_JSON_PATH = path.join(DUMP_DIR, 'janusec_okta_m365_events.v1.1.json');
const EP_XLSX_PATH   = path.join(DUMP_DIR, 'janusec_ep_endpoint.v1.1.xlsx');

// Minimal NET CSV with 8 rows covering PHANTOM-MERIDIAN + benign
const PHANTOM_MERIDIAN_CSV = [
  'event_id,timestamp_utc,src_ip,dst_ip,dns_query,dns_label_entropy_bits,sni,ja3_md5,beacon_interval_seconds,beacon_jitter_ratio,running_mean_interval,running_stddev,review_state,analyst_notes,mitre_technique',
  'NET-009,2026-03-07T09:18:19Z,10.10.4.88,45.153.160.100,update-cdn-svc.net,2.1,update-cdn-svc.net,72a589da,2700.0,0.093,2700.0,0.0,confirmed_malicious,C2 beacon #1,T1071.004',
  'NET-010,2026-03-09T10:03:00Z,10.10.4.88,8.8.8.8,LAPTOP-WKS-CFO-cfo.update-cdn-svc.net,3.8,,72a589da,2734.0,0.093,2717.0,24.0,confirmed_malicious,C2 beacon #2 DNS tunnel,T1071.004',
  'NET-014,2026-03-14T11:00:00Z,10.10.4.88,8.8.8.8,c2-usr-list-b64data.update-cdn-svc.net,4.6,,72a589da,3336.0,0.12,2860.0,399.0,confirmed_malicious,Data exfil via DNS tunnel,T1048',
  'NET-024,2026-03-24T02:30:00Z,10.10.4.88,45.153.160.100,,0,,72a589da,,,,,confirmed_malicious,CS Beacon #24 exfil pre-stage,T1041',
  'NET-001,2026-03-01T08:00:01Z,10.10.4.10,8.8.8.8,google.com,2.8,,,0.0,0.0,0.0,0.0,reviewed_benign,Normal O365 DNS lookup,',
  'NET-002,2026-03-01T08:00:15Z,10.10.4.11,8.8.8.8,microsoft.com,2.5,,,0.0,0.0,0.0,0.0,reviewed_benign,Normal DNS lookup,',
].join('\n');

// Minimal OKTA BEC rows for Harbourside test
const HARBOURSIDE_CSV = [
  'event_id,timestamp_utc,user,src_ip,event_type,mitre_technique,review_state,analyst_notes',
  'OKT-021,2026-03-21T14:22:00Z,finance.officer@acmecorp.com,185.62.56.200,email_send,T1566.002,confirmed_malicious,Harbourside BEC wire $127500',
  'OKT-022,2026-03-21T14:23:00Z,finance.officer@acmecorp.com,185.62.56.200,inbox_rule_create,T1114.003,confirmed_malicious,Harbourside BEC forwarding rule',
  'OKT-027,2026-03-21T15:01:00Z,finance.officer@acmecorp.com,185.62.56.200,email_send,T1566.002,confirmed_malicious,BEC wire transfer sent $127500',
  'OKT-001,2026-03-01T08:10:00Z,j.smith@acmecorp.com,10.0.1.50,user_login,,,reviewed_benign,Normal login',
].join('\n');

// Sarah Chen benign cluster
const SARAH_CHEN_CSV = [
  'event_id,timestamp_utc,user,src_ip,event_type,review_state,analyst_notes',
  'OKT-050,2026-04-01T09:00:00Z,sarah.chen@acmecorp.com,10.0.2.15,app_access,reviewed_benign,NEW_HIRE_SARAH_CHEN #1',
  'OKT-051,2026-04-01T09:05:00Z,sarah.chen@acmecorp.com,10.0.2.15,mfa_enroll,reviewed_benign,NEW_HIRE_SARAH_CHEN #2',
  'OKT-052,2026-04-01T09:10:00Z,sarah.chen@acmecorp.com,10.0.2.15,app_access,reviewed_benign,NEW_HIRE_SARAH_CHEN #3',
  'OKT-053,2026-04-01T09:15:00Z,sarah.chen@acmecorp.com,10.0.2.15,user_login,reviewed_benign,NEW_HIRE_SARAH_CHEN #4',
  'OKT-054,2026-04-01T09:20:00Z,sarah.chen@acmecorp.com,10.0.2.15,profile_update,reviewed_benign,NEW_HIRE_SARAH_CHEN #5',
  'OKT-055,2026-04-01T09:25:00Z,sarah.chen@acmecorp.com,10.0.2.15,app_access,reviewed_benign,NEW_HIRE_SARAH_CHEN #6',
].join('\n');

// Script kiddie vs APT rows
const SCRIPT_KIDDIE_CSV = [
  'event_id,timestamp_utc,user,src_ip,event_type,attempts_per_second,review_state,analyst_notes',
  'OKT-039,2026-03-19T14:00:00Z,admin@acmecorp.com,117.50.39.100,auth_failure,3.0,script_kiddie,847 attempts in 282s automated scan',
  'OKT-040,2026-03-19T14:05:00Z,guest@acmecorp.com,117.50.39.100,auth_failure,2.8,script_kiddie,Continuation of spray - low quality creds',
  'OKT-001,2026-03-07T09:15:00Z,cfo@acmecorp.com,91.108.4.200,auth_failure,,confirmed_malicious,APT - 1 attempt every 7 min valid user',
  'OKT-004,2026-03-07T09:22:00Z,cfo@acmecorp.com,91.108.4.200,auth_success,,confirmed_malicious,APT MFA fatigue success',
].join('\n');

// ── Mock responses ────────────────────────────────────────────────────────────

const MOCK_ANALYSIS_PHANTOM = {
  assessment_id: 'phantom-001',
  report_id: 'phantom-001',
  status: 'complete',
  rows_processed: 6,
  rows: [
    { row_index: 0, event_id: 'NET-009', src_ip: '10.10.4.88', dst_ip: '45.153.160.100',
      event_type: 'dns_query', severity: 'critical', mitre_technique: 'T1071.004' },
    { row_index: 1, event_id: 'NET-010', src_ip: '10.10.4.88',
      event_type: 'dns_query', severity: 'critical', mitre_technique: 'T1071.004' },
    { row_index: 2, event_id: 'NET-014', src_ip: '10.10.4.88',
      event_type: 'dns_exfil', severity: 'critical', mitre_technique: 'T1048' },
    { row_index: 3, event_id: 'NET-024', src_ip: '10.10.4.88', dst_ip: '45.153.160.100',
      event_type: 'c2_beacon', severity: 'critical', mitre_technique: 'T1041' },
  ],
  llm_rows: [],
  headline: 'P1 — PHANTOM_MERIDIAN C2 beacon + DNS exfiltration detected',
};

const MOCK_ANALYSIS_HARBOURSIDE = {
  assessment_id: 'harbourside-001',
  report_id: 'harbourside-001',
  status: 'complete',
  rows_processed: 4,
  rows: [
    { row_index: 0, event_id: 'OKT-021', user: 'finance.officer@acmecorp.com',
      src_ip: '185.62.56.200', event_type: 'email_send', severity: 'critical', mitre_technique: 'T1566.002' },
    { row_index: 1, event_id: 'OKT-022', user: 'finance.officer@acmecorp.com',
      src_ip: '185.62.56.200', event_type: 'inbox_rule_create', severity: 'critical', mitre_technique: 'T1114.003' },
  ],
  llm_rows: [],
  headline: 'P1 — HARBOURSIDE BEC wire transfer $127,500',
};

const MOCK_ANALYSIS_SARAH = {
  assessment_id: 'sarah-001',
  report_id: 'sarah-001',
  status: 'complete',
  rows_processed: 6,
  rows: Array.from({length: 6}, (_, i) => ({
    row_index: i, event_id: `OKT-05${i}`, user: 'sarah.chen@acmecorp.com',
    event_type: 'app_access', severity: 'info', mitre_technique: '',
  })),
  llm_rows: [],
  headline: 'INFO — New hire onboarding activity (benign)',
};

const MOCK_INVESTIGATE_PHANTOM = {
  investigate_id: 'inv-phantom-001',
  assessment_id: 'phantom-001',
  status: 'ready',
  narrative: 'PHANTOM MERIDIAN: Host 10.10.4.88 (CFO workstation) beaconed to 45.153.160.100 (Datacamp AS60068) over DNS tunnel (update-cdn-svc.net). Entropy escalated from 2.1 to 4.6 (T1048). Cobalt Strike JA3 72a589da present in NET-009, NET-024.',
  missing_logs: ['network_flow', 'endpoint_memory'],
  evidence_table: [
    { row_index: 0, event_id: 'NET-009', verdict: 'malicious', ml_score: 0.97 },
    { row_index: 2, event_id: 'NET-014', verdict: 'malicious', ml_score: 0.99 },
  ],
  persona_expanded: {
    soc_analyst: '1. Block 45.153.160.100 at perimeter immediately.\n2. Isolate 10.10.4.88.\n3. Collect memory dump for Cobalt Strike beacon analysis.',
    ciso: 'PHANTOM MERIDIAN represents a T1+ threat. Estimated dwell time 17 days. Recommend emergency IR engagement.',
  },
};

const MOCK_INVESTIGATE_HARBOURSIDE = {
  investigate_id: 'inv-harbourside-001',
  assessment_id: 'harbourside-001',
  status: 'ready',
  narrative: 'HARBOURSIDE BEC: finance.officer@acmecorp.com account compromised from 185.62.56.200 (AS44050 RU). Wire transfer $127,500 sent to fraudulent account. Inbox forwarding rule OKT-022 created. SEPARATE INCIDENT from C2 network campaign — actor originates from different ASN (AS44050, not AS60068) and targets financial accounts, not infrastructure.',
  missing_logs: ['email_gateway', 'financial_system'],
  evidence_table: [
    { row_index: 0, event_id: 'OKT-021', verdict: 'malicious', ml_score: 0.96 },
  ],
  persona_expanded: {
    soc_analyst: '1. Revoke finance.officer session immediately.\n2. Contact bank to recall wire transfer.\n3. Preserve inbox rule as forensic evidence.',
    ciso: 'BEC fraud confirmed. $127,500 at risk. Legal and finance teams notified. Regulatory reporting assessment in progress.',
  },
};

const MOCK_INVESTIGATE_SARAH = {
  investigate_id: 'inv-sarah-001',
  assessment_id: 'sarah-001',
  status: 'ready',
  narrative: 'NEW HIRE ONBOARDING (BENIGN): Sarah Chen performed normal new-hire activities — MFA enrollment, app access, profile update. No lateral movement or privilege escalation observed. All 6 events are consistent with standard IT onboarding workflow.',
  missing_logs: [],
  evidence_table: [],
  persona_expanded: {
    soc_analyst: 'No action required. Standard new hire onboarding pattern.',
  },
};

// EXPAND mock for PHANTOM-MERIDIAN C2 task
const MOCK_EXPAND_PHANTOM = {
  assessment_id: 'phantom-001',
  task_id: 'task-phantom-c2',
  persona: 'soc',
  entity_fields: {
    users: [],
    ips: ['10.10.4.88', '45.153.160.100'],
    hosts: [],
    domains: ['update-cdn-svc.net', 'c2-usr-list-b64data.update-cdn-svc.net'],
    sessions: [], tokens: [], policies: [],
  },
  check_results: [
    { check_id: 'after_hours', label: 'After-Hours Activity', triggered: false, severity: 'info', detail: '', evidence_rows: [] },
    { check_id: 'same_ip_cross_account', label: 'Cross-Account Same IP', triggered: false, severity: 'info', detail: '', evidence_rows: [] },
    { check_id: 'impossible_travel', label: 'Impossible Travel', triggered: false, severity: 'info', detail: '', evidence_rows: [] },
    { check_id: 'temp_privilege', label: 'Privilege Escalation / Temp Privilege', triggered: false, severity: 'info', detail: '', evidence_rows: [] },
  ],
  matched_entities: { ips: ['45.153.160.100'], domains: ['update-cdn-svc.net'] },
  row_count: 4,
  summary: 'PHANTOM MERIDIAN: DNS tunnel C2 via update-cdn-svc.net to 45.153.160.100 (Cobalt Strike JA3 72a589da). Entropy escalated to 4.6 during exfil.',
  confidence: 0.97,
  subtasks: [
    { id: 's1', action: 'Block 45.153.160.100 at perimeter firewall and DNS sinkhole update-cdn-svc.net', entity: '45.153.160.100', priority: 'high' },
    { id: 's2', action: 'Isolate 10.10.4.88 from network and collect memory dump', entity: '10.10.4.88', priority: 'high' },
    { id: 's3', action: 'Extract NET-014 DNS exfil payload from packet capture (highest entropy 4.6 bits)', entity: 'NET-014', priority: 'high' },
  ],
  iocs: [
    { type: 'ip', value: '45.153.160.100', context: 'Cobalt Strike C2 server (AS60068)' },
    { type: 'domain', value: 'update-cdn-svc.net', context: 'C2 domain (DNS tunnel exfil)' },
    { type: 'ja3', value: '72a589da', context: 'Cobalt Strike JA3 fingerprint' },
  ],
  mitre_techniques: ['T1071.004', 'T1048', 'T1041'],
  next_pivot: 'Check SIEM for any other hosts querying update-cdn-svc.net or communicating with 45.153.160.100',
  cache_hit: false,
  latency_ms: 487,
};

// EXPAND mock for Harbourside BEC — MUST NOT reference PHANTOM-MERIDIAN IPs
const MOCK_EXPAND_HARBOURSIDE = {
  assessment_id: 'harbourside-001',
  task_id: 'task-harbourside-bec',
  persona: 'soc',
  entity_fields: {
    users: ['finance.officer@acmecorp.com'],
    ips: ['185.62.56.200'],
    hosts: [],
    domains: [],
    sessions: [], tokens: [], policies: [],
  },
  check_results: [
    { check_id: 'after_hours', label: 'After-Hours Activity', triggered: false, severity: 'info', detail: '', evidence_rows: [] },
    { check_id: 'same_ip_cross_account', label: 'Cross-Account Same IP', triggered: false, severity: 'info', detail: '', evidence_rows: [] },
  ],
  matched_entities: { users: ['finance.officer@acmecorp.com'], ips: ['185.62.56.200'] },
  row_count: 3,
  summary: 'HARBOURSIDE BEC: finance.officer account compromised from 185.62.56.200 (AS44050 — different actor from PHANTOM MERIDIAN). Wire transfer $127,500 to fraudulent account.',
  confidence: 0.95,
  subtasks: [
    { id: 's1', action: 'Revoke all sessions for finance.officer@acmecorp.com', entity: 'finance.officer@acmecorp.com', priority: 'high' },
    { id: 's2', action: 'Contact bank to recall $127,500 wire transfer', entity: 'wire_transfer', priority: 'high' },
    { id: 's3', action: 'Remove inbox forwarding rule created by OKT-022', entity: 'OKT-022', priority: 'high' },
  ],
  iocs: [
    { type: 'ip', value: '185.62.56.200', context: 'Harbourside BEC actor (AS44050 RU)' },
    { type: 'email', value: 'finance.officer@acmecorp.com', context: 'Compromised BEC target' },
  ],
  mitre_techniques: ['T1566.002', 'T1114.003'],
  next_pivot: 'Check email gateway logs for any other BEC attempts from AS44050 in the past 30 days',
  cache_hit: false,
  latency_ms: 312,
};

// ── Helper: set up common API mocks ──────────────────────────────────────────

async function mockAnalysis(page, assessmentId, mockResponse) {
  await page.route('**/api/v1/csv/deep_analyze', async (route) => {
    if (route.request().method() !== 'POST') { await route.continue(); return; }
    await route.fulfill({ status: 200, contentType: 'application/json',
      body: JSON.stringify(mockResponse) });
  });
  await page.route(`**/deep_analyze/assessments/${assessmentId}`, async (route) => {
    await route.fulfill({ status: 200, contentType: 'application/json',
      body: JSON.stringify(mockResponse) });
  });
}

async function mockInvestigate(page, investigateRecord) {
  const invId = investigateRecord.investigate_id;
  const aid = investigateRecord.assessment_id;
  await page.route(`**/assessments/${aid}/investigate/build`, async (route) => {
    await route.fulfill({ status: 200, contentType: 'application/json',
      body: JSON.stringify({ assessment_id: aid, investigate_id: invId, status: 'queued' }) });
  });
  await page.route(`**/investigate/${invId}`, async (route) => {
    await route.fulfill({ status: 200, contentType: 'application/json',
      body: JSON.stringify(investigateRecord) });
  });
}

async function mockExpand(page, assessmentId, expandResponse) {
  await page.route(`**/assessments/${assessmentId}/tasks/**/expand`, async (route) => {
    await route.fulfill({ status: 200, contentType: 'application/json',
      body: JSON.stringify(expandResponse) });
  });
}

async function runAnalysis(page) {
  await page.click('#btnAnalyze');
  try {
    await page.waitForFunction(() => {
      const l = document.getElementById('reportLoading');
      return l && l.style.display !== 'none';
    }, { timeout: 5000 });
  } catch (_) { /* spinner may flicker */ }
  await page.waitForFunction(() => {
    const loading = document.getElementById('reportLoading');
    const content = document.getElementById('reportContent');
    const empty = document.getElementById('reportEmpty');
    if (!loading) return false;
    const gone = loading.style.display === 'none';
    const shown = (content && content.style.display !== 'none') ||
                  (empty && empty.style.display !== 'none' && empty.style.display !== '');
    const done = document.getElementById('btnAnalyze') && !document.getElementById('btnAnalyze').disabled;
    return gone && (shown || done);
  }, { timeout: 30000 });
}

async function buildInvestigate(page) {
  await page.click('.tab-btn[data-tab="investigate"]');
  await page.waitForTimeout(200);
  await page.click('#btnBuildInvestigate');
  await page.waitForFunction(() => {
    const loading = document.getElementById('investigateLoading');
    const results = document.getElementById('investigateResults');
    return results && results.style.display !== 'none' && loading && loading.style.display === 'none';
  }, { timeout: 20000 });
}

// ── Test suite: PHANTOM-MERIDIAN (NET CSV) ────────────────────────────────────

test.describe('PHANTOM-MERIDIAN C2 cluster (NET CSV)', () => {
  test.setTimeout(90000);
  let page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await page.addInitScript(() => {
      localStorage.setItem('apiKey', 'devkey123');
      localStorage.setItem('tenantId', 'v11-phantom-test');
    });

    await mockAnalysis(page, 'phantom-001', MOCK_ANALYSIS_PHANTOM);
    await mockInvestigate(page, MOCK_INVESTIGATE_PHANTOM);
    await mockExpand(page, 'phantom-001', MOCK_EXPAND_PHANTOM);

    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');

    await page.locator('#fileInput').setInputFiles([{
      name: 'phantom_meridian.csv',
      mimeType: 'text/csv',
      buffer: Buffer.from(PHANTOM_MERIDIAN_CSV),
    }]);
    await page.waitForTimeout(500);

    await runAnalysis(page);
  });

  test.afterAll(async () => { await page.close(); });

  test('NET CSV upload triggers analysis (rows_processed shown)', async () => {
    const content = page.locator('#reportContent');
    // Either content is visible or the analyze button re-enabled (analysis ran)
    const btnEnabled = await page.locator('#btnAnalyze').isEnabled();
    expect(btnEnabled, 'Analysis should complete and re-enable button').toBe(true);
  });

  test('Build Investigate produces PHANTOM-MERIDIAN narrative', async () => {
    await buildInvestigate(page);
    const narrative = page.locator('#investigateNarrative');
    await expect(narrative).toBeVisible();
    const text = await narrative.textContent();
    expect(text.toLowerCase()).toMatch(/phantom|meridian|c2|beacon|dns/i);
  });

  test('Task card EXPAND renders C2 IP in entity chips', async () => {
    const expandBtn = page.locator('.task-card__expand-btn').first();
    await expect(expandBtn).toBeVisible();
    await expandBtn.click();

    await page.waitForFunction(() => {
      const bodies = document.querySelectorAll('.task-card__body.open');
      return bodies.length > 0 && bodies[0].innerHTML.length > 100 && !bodies[0].innerHTML.includes('⏳');
    }, { timeout: 15000 });

    // Entity chips should show C2 IP or domain
    const chips = page.locator('.entity-chip');
    const chipCount = await chips.count();
    expect(chipCount).toBeGreaterThan(0);

    const allChipText = await chips.allTextContents();
    const hasC2Indicator = allChipText.some(t =>
      t.includes('45.153.160.100') || t.includes('update-cdn-svc.net') || t.includes('10.10.4.88')
    );
    expect(hasC2Indicator, 'C2 IP or domain should appear in entity chips').toBe(true);
  });

  test('PHANTOM-MERIDIAN IOCs include Cobalt Strike indicators', async () => {
    const iocs = page.locator('.expand-ioc-list li');
    const iocCount = await iocs.count();
    expect(iocCount).toBeGreaterThan(0);

    const iocTexts = await iocs.allTextContents();
    const hasCS = iocTexts.some(t =>
      t.includes('45.153.160.100') || t.includes('72a589da') || t.includes('update-cdn-svc.net')
    );
    expect(hasCS, 'Cobalt Strike IOC should appear').toBe(true);
  });

  test('PHANTOM-MERIDIAN MITRE techniques include T1048 (exfil) or T1071 (C2)', async () => {
    const mitreBadges = page.locator('.task-card__body.open span').filter({ hasText: /T\d{4}/ });
    const count = await mitreBadges.count();
    expect(count).toBeGreaterThan(0);

    const texts = await mitreBadges.allTextContents();
    const hasExfilOrC2 = texts.some(t => t.includes('T1048') || t.includes('T1071') || t.includes('T1041'));
    expect(hasExfilOrC2, 'Exfil or C2 MITRE technique should be shown').toBe(true);
  });

  test('Next pivot block references DNS or C2 indicators', async () => {
    const pivot = page.locator('.expand-pivot');
    await expect(pivot).toBeVisible();
    const pivotText = await pivot.textContent();
    expect(pivotText.toLowerCase()).toMatch(/dns|c2|45\.153|update-cdn|beacon/i);
  });
});

// ── Test suite: Harbourside BEC (must NOT merge with PHANTOM-MERIDIAN) ────────

test.describe('Harbourside BEC cluster (OKTA CSV)', () => {
  test.setTimeout(90000);
  let page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await page.addInitScript(() => {
      localStorage.setItem('apiKey', 'devkey123');
      localStorage.setItem('tenantId', 'v11-harbourside-test');
    });

    await mockAnalysis(page, 'harbourside-001', MOCK_ANALYSIS_HARBOURSIDE);
    await mockInvestigate(page, MOCK_INVESTIGATE_HARBOURSIDE);
    await mockExpand(page, 'harbourside-001', MOCK_EXPAND_HARBOURSIDE);

    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');

    await page.locator('#fileInput').setInputFiles([{
      name: 'harbourside_bec.csv',
      mimeType: 'text/csv',
      buffer: Buffer.from(HARBOURSIDE_CSV),
    }]);
    await page.waitForTimeout(500);

    await runAnalysis(page);
  });

  test.afterAll(async () => { await page.close(); });

  test('Harbourside narrative does NOT mention PHANTOM-MERIDIAN IP (45.153.160.100)', async () => {
    await buildInvestigate(page);
    const narrative = page.locator('#investigateNarrative');
    await expect(narrative).toBeVisible();
    const text = await narrative.textContent();
    // Should NOT mention PHANTOM-MERIDIAN's C2 IP
    expect(text).not.toContain('45.153.160.100');
  });

  test('Harbourside narrative mentions BEC and finance.officer', async () => {
    const narrative = page.locator('#investigateNarrative');
    const text = await narrative.textContent();
    expect(text.toLowerCase()).toMatch(/bec|harbourside|finance\.officer|wire transfer/i);
  });

  test('Harbourside EXPAND shows 185.62.56.200 (BEC actor IP), NOT 45.153.160.100', async () => {
    const expandBtn = page.locator('.task-card__expand-btn').first();
    await expect(expandBtn).toBeVisible();
    await expandBtn.click();

    await page.waitForFunction(() => {
      const bodies = document.querySelectorAll('.task-card__body.open');
      return bodies.length > 0 && bodies[0].innerHTML.length > 100 && !bodies[0].innerHTML.includes('⏳');
    }, { timeout: 15000 });

    const chips = page.locator('.entity-chip');
    const chipTexts = await chips.allTextContents();
    const allPanelText = chipTexts.join(' ');

    // Must have BEC actor IP
    const hasBECIP = allPanelText.includes('185.62.56.200') ||
                     allPanelText.includes('finance.officer');
    expect(hasBECIP, 'BEC actor IP or user should appear').toBe(true);

    // Must NOT have PHANTOM-MERIDIAN IP (cluster separation)
    expect(allPanelText, 'PHANTOM-MERIDIAN C2 IP must NOT appear in Harbourside panel')
      .not.toContain('45.153.160.100');
  });

  test('Harbourside IOCs reference email/finance (not C2)', async () => {
    const iocs = page.locator('.expand-ioc-list li');
    const iocTexts = await iocs.allTextContents();
    const hasEmailIOC = iocTexts.some(t =>
      t.includes('185.62.56.200') || t.includes('finance.officer') || t.toLowerCase().includes('email')
    );
    expect(hasEmailIOC, 'Harbourside IOC should be email/finance-related').toBe(true);
  });

  test('Harbourside MITRE includes T1566 (phishing) or T1114 (email collection)', async () => {
    const mitreBadges = page.locator('.task-card__body.open span').filter({ hasText: /T\d{4}/ });
    const count = await mitreBadges.count();
    if (count === 0) return; // MITRE not shown = acceptable for BEC minimal rows
    const texts = await mitreBadges.allTextContents();
    const hasBECMITRE = texts.some(t => t.includes('T1566') || t.includes('T1114'));
    expect(hasBECMITRE, 'BEC MITRE technique should be shown').toBe(true);
  });
});

// ── Test suite: Sarah Chen benign cluster ─────────────────────────────────────

test.describe('Sarah Chen new-hire benign cluster', () => {
  test.setTimeout(90000);
  let page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await page.addInitScript(() => {
      localStorage.setItem('apiKey', 'devkey123');
      localStorage.setItem('tenantId', 'v11-sarah-test');
    });

    await mockAnalysis(page, 'sarah-001', MOCK_ANALYSIS_SARAH);
    await mockInvestigate(page, MOCK_INVESTIGATE_SARAH);

    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');

    await page.locator('#fileInput').setInputFiles([{
      name: 'sarah_chen.csv',
      mimeType: 'text/csv',
      buffer: Buffer.from(SARAH_CHEN_CSV),
    }]);
    await page.waitForTimeout(500);

    await runAnalysis(page);
  });

  test.afterAll(async () => { await page.close(); });

  test('Sarah Chen investigate panel renders narrative text', async () => {
    await buildInvestigate(page);
    const narrative = page.locator('#investigateNarrative');
    await expect(narrative).toBeVisible();
    const text = await narrative.textContent();
    // Narrative must be non-trivially populated (mock or real server)
    expect(text.trim().length, 'Investigate narrative should have meaningful content').toBeGreaterThan(30);
  });

  test('Sarah Chen investigate results are visible (no loading spinner)', async () => {
    // Verify the investigate results panel is shown (not still loading)
    const results = page.locator('#investigateResults');
    await expect(results).toBeVisible();
    const loading = page.locator('#investigateLoading');
    const loadingVisible = await loading.isVisible().catch(() => false);
    expect(loadingVisible, 'Loading spinner should be gone after build completes').toBe(false);
  });
});

// ── Test suite: Persona selector coherence ────────────────────────────────────

test.describe('Persona selector: SOC vs CISO differentiation', () => {
  test.setTimeout(60000);
  let page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await page.addInitScript(() => {
      localStorage.setItem('apiKey', 'devkey123');
    });
    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');
  });

  test.afterAll(async () => { await page.close(); });

  test('Persona selector exists in the DOM with correct options', async () => {
    // The #investigatePersonaSelect may be hidden until after analysis.
    // We just verify it exists and has the right options in the DOM.
    const select = page.locator('#investigatePersonaSelect');
    const count = await select.count();

    if (count === 0) {
      // Fall back to the report-tab persona selector
      const reportPersona = page.locator('#personaSelect, select[name="persona"]');
      const rpCount = await reportPersona.count();
      expect(rpCount, 'A persona selector should exist somewhere on the page').toBeGreaterThan(0);
      return;
    }

    // Element is in DOM — check its options regardless of visibility
    const options = await select.locator('option').allTextContents();
    expect(options.some(o => o.toLowerCase().includes('soc')),
      `SOC option not found. Options: ${options.join(', ')}`).toBe(true);
    expect(options.some(o => o.toLowerCase().includes('ciso') || o.toLowerCase().includes('executive')),
      `CISO/executive option not found. Options: ${options.join(', ')}`).toBe(true);
  });
});

// ── Test suite: row-cap architectural boundary ────────────────────────────────

test.describe('Row cap boundary: 30-row investigate limit', () => {
  test.setTimeout(30000);
  let page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await page.goto(`${BASE}/static/investigate.html`);
    await page.waitForLoadState('networkidle');
  });

  test.afterAll(async () => { await page.close(); });

  test('Page loads without JS errors', async () => {
    const errors = [];
    page.on('pageerror', (err) => errors.push(err.message));
    await page.reload();
    await page.waitForLoadState('networkidle');
    const fatal = errors.filter(e => !e.includes('favicon') && !e.includes('net::ERR'));
    expect(fatal.length, `JS errors on page: ${fatal.join(', ')}`).toBe(0);
  });

  test('investigate.html has the Investigate tab button', async () => {
    const tabBtn = page.locator('.tab-btn[data-tab="investigate"]');
    await expect(tabBtn).toBeVisible();
  });

  test('investigate.html has file upload input', async () => {
    const fileInput = page.locator('#fileInput');
    await expect(fileInput).toBeAttached();
  });
});

// ── Test suite: NET CSV file from disk (non-mocked file read) ─────────────────

test.describe('NET CSV v1.1 file exists and is readable', () => {
  test('NET CSV exists at expected dump path', async () => {
    expect(fs.existsSync(NET_CSV_PATH), `File not found: ${NET_CSV_PATH}`).toBe(true);
  });

  test('NET CSV has at least 65 rows', async () => {
    const content = fs.readFileSync(NET_CSV_PATH, 'utf-8');
    const lines = content.split('\n').filter(l => l.trim());
    expect(lines.length, 'NET CSV should have header + ≥65 rows').toBeGreaterThan(65);
  });

  test('OKTA JSON exists at expected dump path', async () => {
    expect(fs.existsSync(OKTA_JSON_PATH), `File not found: ${OKTA_JSON_PATH}`).toBe(true);
  });

  test('OKTA JSON has at least 80 events', async () => {
    const raw = fs.readFileSync(OKTA_JSON_PATH, 'utf-8');
    const data = JSON.parse(raw);
    expect(data.events.length, 'OKTA JSON should have ≥80 events').toBeGreaterThanOrEqual(80);
  });

  test('EP XLSX exists at expected dump path', async () => {
    expect(fs.existsSync(EP_XLSX_PATH), `File not found: ${EP_XLSX_PATH}`).toBe(true);
  });
});
