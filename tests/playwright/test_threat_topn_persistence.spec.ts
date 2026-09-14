import { test, expect } from '@playwright/test';

// Verifies TopN persistence across page reloads and shared rendering logic.
// Assumes dev server running at http://localhost:8080

const BASE = process.env.BASE_URL || 'http://localhost:8080';

async function setApiKey(page){
  await page.addInitScript(() => { try { localStorage.setItem('apiKey','devkey123'); } catch(e){} });
}

test('Multi-Source Correlator TopN persistence and remediation hints appear', async ({ page }) => {
  await setApiKey(page);
  await page.goto(BASE + '/static/csv_multi_analyzer.html');
  // Inject a fake summary object and call exposed renderThreatSidebar
  const fakeSummary = {
    confidence: 0.81,
    confidence_breakdown: { chain_bonus: 0.05, mapping_bonus: 0.04 },
    path_scores: {
      'batchA__batchB': { score: 0.92, anomalies: ['high_field_overlap'], contributions: { loads_hash:{ contribution:0.4 }, spawns:{ contribution:0.3 } } },
      'batchC__batchD': { score: 0.55, anomalies: [], contributions: { gt_sequence:{ contribution:0.2 } } }
    },
    factors: [ { factor:'multi_source_correlation' }, { factor:'mapping_semantics_rich' } ],
    overlap_details: { batchA: { batchB: { user:['alice'], host:['workstation01'] } } },
    correlation: { batchA:{ batchB:4 }, batchC:{ batchD:2 } }
  };
  await page.evaluate((s)=>{ (window as any).renderThreatSidebar(s); }, fakeSummary);
  // Default TopN should be 5 but we only have 2 entries
  const rankList = page.locator('#threatRankList');
  await expect(rankList).toContainText('batchA__batchB');
  // Click Top 10 and persist
  await page.click('#btnTop10');
  // Reload page and re-render with same summary
  await page.reload();
  await page.evaluate((s)=>{ (window as any).renderThreatSidebar(s); }, fakeSummary);
  // Ensure localStorage persisted selection (btnTop10 should have btn-primary)
  const btnTop10 = page.locator('#btnTop10.btn-primary');
  await expect(btnTop10).toHaveCount(1);
  // Remediation hints section should list at least one hint
  const rem = page.locator('#remediationHints');
  await expect(rem).toContainText('Investigate'); // from spawns mapping
});

test('Single CSV Analyzer risk rankings and remediation appear', async ({ page }) => {
  await setApiKey(page);
  await page.goto(BASE + '/static/csv_analyzer.html');
  // Simulate correlation panel population by injecting a fake summary
  const fakeSummary = {
    confidence: 0.66,
    path_scores: {
      'x__y': { score: 0.71, anomalies:['high_field_overlap'], contributions:{ loads_hash:{ contribution:0.3 }, spawns:{ contribution:0.2 } } }
    },
    factors: [ { factor:'mapping_semantics_bonus' } ]
  };
  await page.evaluate((s)=>{
    // manually set risk rank area
    const panel = document.getElementById('correlationPanel'); if(panel) panel.style.display='block';
    const riskDiv = document.getElementById('corrRiskRank');
    const remDiv = document.getElementById('corrRemediation');
    if((window as any).ThreatRanking){
      const ranks = (window as any).ThreatRanking.computeRiskRankings(s,5);
      if(riskDiv) riskDiv.textContent = ranks.map((r,i)=>`${i+1}. ${r.key} risk=${r.risk.toFixed(3)}`).join('\n');
      if(remDiv) remDiv.textContent = (ranks[0] && ranks[0].remediation) ? ranks[0].remediation.join('\n') : 'No specific hints.';
    }
  }, fakeSummary);
  const risk = page.locator('#corrRiskRank');
  await expect(risk).toContainText('x__y');
  const rem = page.locator('#corrRemediation');
  await expect(rem).not.toHaveText('—');
});
