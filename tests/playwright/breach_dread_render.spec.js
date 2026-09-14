const { test, expect } = require('@playwright/test');

const BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:8000';
const AID = 'assessment-1777008559-81de74d8';

const dreadFragments = {
  damage: 'On 2026-02-03, an actor transferred SFL_DATA and FINANCE_WH data to Backblaze B2 (rows 4548, 5711, 5713).',
  reproducibility: 'The same command signature recurred across 7 distinct days (rows 12832, 15865).',
  exploitability: 'No DLP inspection on cloud-sync egress and no PAM gate were observed.',
  affected_users: '4 accounts affected: SVC_SFL_ANALYTICS_FED, marcus.delacroix, rachel.nakamura, aaron.blackwood.',
  discoverability: 'Cross-source correlation across endpoint, network, cloud, and identity sources.'
};

function assessmentBody() {
  return {
    assessment_id: AID,
    rows_processed: 43834,
    evidence_store: { row_count: 43834, source_counts: { endpoint: 1, network: 1, cloud: 1, identity: 1 } },
    correlation_clusters: [
      {
        cluster_id: 'case-primary-breach',
        severity: 'critical',
        verdict: 'VALIDATED_BREACH',
        row_refs: [4548, 5711, 5713, 5720, 12832, 15865],
        tier1_prefill: {
          incident_name: 'PRIMARY BREACH',
          headline_subtitle: 'Multiple attack phases observed across identity, endpoint, and network telemetry.',
          observed_impact: {
            identity: 'SVC_SFL_ANALYTICS_FED, marcus.delacroix, rachel.nakamura, aaron.blackwood',
            data: 'SFL_DATA and FINANCE_WH exports to temporary unload stages',
            operational: 'No DLP inspection on cloud-sync egress and no PAM gate'
          },
          dread_narrative: {
            fragments: dreadFragments,
            sabsa_coda_draft: 'Business consequence: Confidential, Reputable, and Authorised attributes degraded.',
            sabsa_attributes: ['Confidential', 'Reputable', 'Authorised']
          },
          confidence_meter: { total: 85 }
        },
        confidence_meter: { total: 85 }
      },
      {
        cluster_id: 'authorized-security-test',
        severity: 'low',
        verdict: 'BENIGN_EXPECTED',
        row_refs: Array.from({ length: 10 }, (_, i) => i),
        tier1_prefill: { incident_name: 'AUTHORIZED SECURITY TEST', headline_subtitle: 'Pentest tooling is expected within scope.' }
      }
    ],
    normalized_rows: [
      { row_index: 4548, _source: 'network', severity: 'critical', description: '100MB outbound to attacker C2', geo_dst_country: 'AU', geo_dst_asn: 'AS12345' },
      { row_index: 5711, _source: 'snowflake', severity: 'critical', database_name: 'SFL_DATA', warehouse_name: 'FINANCE_WH', description: 'COPY INTO temp unload stage' },
      { row_index: 5713, _source: 'snowflake', severity: 'critical', database_name: 'SFL_DATA', warehouse_name: 'FINANCE_WH', description: 'COPY INTO temp unload stage' },
      { row_index: 12832, _source: 'endpoint', severity: 'critical', user: 'marcus.delacroix', host: 'fs01', description: 'rclone sync to Backblaze B2' }
    ]
  };
}

test('breach UI renders DREAD/SABSA evidence instead of stale generic summary', async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'janusec-playwright-local');
    localStorage.setItem('tenantId', 'default');
    localStorage.setItem('selectedModel', 'qwen3:14b');
  });

  await page.route(`**/api/v1/assessments/${AID}`, route => route.fulfill({ json: assessmentBody() }));
  await page.route(`**/api/v1/assessments/${AID}/executive-summary`, route => route.fulfill({
    json: {
      assessment_id: AID,
      headline: 'Confirmed breach: PRIMARY BREACH',
      subline: '6 evidence rows across 4 sources - DREAD/SABSA evidence narrative',
      executive_summary: `${dreadFragments.damage} ${dreadFragments.reproducibility} ${dreadFragments.exploitability} Business consequence: Confidential, Reputable, and Authorised attributes degraded. 2,356 rows were separately ruled out as authorized security test or benign context.`,
      narrative_source: 'DREAD+SABSA',
      narrative_provenance: 'dread_deterministic_fragments',
      render_warning: 'LLM render unavailable; deterministic evidence summary shown.',
      evidence_refs: [4548, 5711, 5713, 12832],
      why_confirmed: [],
      model_used: 'qwen3:14b',
      from_cache: false
    }
  }));

  await page.goto(`${BASE}/static/breach.html?assessment=${AID}`);

  const body = page.locator('body');
  await expect(body).toContainText('Confirmed breach: PRIMARY BREACH');
  await expect(body).toContainText('source: DREAD+SABSA');
  await expect(body).toContainText('SFL_DATA');
  await expect(body).toContainText('FINANCE_WH');
  await expect(body).toContainText('Business consequence');
  await expect(body).toContainText('LLM render unavailable');
  await expect(body).toContainText('AUTHORIZED SECURITY TEST');
  await expect(page.locator('.br-card__verdict').first()).toContainText('CONFIRMED BREACH');
  await expect(page.locator('.br-card__evidence-title').first()).toContainText('What happened');
  await expect(page.locator('.br-exec__refs').first()).toContainText('5711');
});

test('threat-case detail renders evidence narrative and framework layer', async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem('apiKey', 'janusec-playwright-local');
    localStorage.setItem('tenantId', 'default');
  });
  await page.route(`**/api/v1/assessments/${AID}`, route => route.fulfill({ json: assessmentBody() }));
  await page.route('**/api/v1/config/tenant/default/crown-jewels', route => route.fulfill({
    json: {
      assets: { SFL_DATA: { tier: 'crown_jewel' }, FINANCE_WH: { tier: 'crown_jewel' }, fs01: { tier: 'tier_2' } },
      accounts: { SVC_SFL_ANALYTICS_FED: { tier: 'service_account' }, 'marcus.delacroix': { tier: 'privileged_user' } },
      destinations: { backblaze: { tier: 'unapproved_cloud' } },
      subnets: {}
    }
  }));
  await page.route('**/api/v1/assessments/**/timeline', route => route.fulfill({ json: { phases: [], rows: [] } }));
  await page.route('**/api/v1/assessments/**/repeat-entities', route => route.fulfill({ json: { match_count: 0, matches: [] } }));
  await page.route('**/api/v1/assessments/**/tier2*', route => route.fulfill({ json: { steps: [] } }));

  await page.goto(`${BASE}/static/breach.html?assessment=${AID}&cluster=case-primary-breach`);

  await expect(page.locator('[data-testid="bct-evidence-narrative"]')).toBeVisible();
  await expect(page.locator('[data-testid="bct-evidence-narrative"]')).toContainText('DAMAGE');
  await expect(page.locator('[data-testid="bct-evidence-narrative"]')).toContainText('Diamond');
  await expect(page.locator('[data-testid="bct-evidence-narrative"]')).toContainText('PASTA');
  await expect(page.locator('[data-testid="bct-evidence-narrative"]')).toContainText('SABSA');
  await expect(page.locator('#bct-cj-review')).toContainText('SFL_DATA');
});
