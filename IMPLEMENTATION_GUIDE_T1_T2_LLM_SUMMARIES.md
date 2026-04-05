# Implementation Guide: T1/T2 LLM Summaries Fix

**Date:** 2025-11-25
**Objective:** Fix T1 LLM summaries generation, add T2 deep investigation, reorder UI, optimize speed
**Priority:** HIGH - Demo blocker

---

## Executive Summary

### Current Issues
1. ❌ T1 LLM summaries are slow (15-30s) - need to switch to faster model
2. ❌ T2 deep investigation summaries don't exist - no button or endpoint
3. ❌ AI-Powered Insights section is at bottom of page - should be near top
4. ❌ No caching of T1/T2 summaries - regenerates every time
5. ❌ No model selection - user can't choose speed vs quality

### Solution Overview
1. ✅ Add T2 endpoint to `csv_endpoints.py` that passes `tier='tier2'`
2. ✅ Move AI-Powered Insights section up in `csv_deep_analysis.html`
3. ✅ Add T2 button with proper UI integration
4. ✅ Switch default T1 model to `gpt-4o-mini` for 5x speed improvement
5. ✅ Add localStorage caching for T1/T2 summaries
6. ✅ Add model selection dropdown

---

## Phase 1: Backend Changes

### File 1: `src/api/csv_endpoints.py`

#### Change 1.1: Add T2 endpoint (after line 566)

**Location:** After the `/deep_analyze` endpoint (around line 566)

**Add this new endpoint:**

```python
@router.post('/tier2_investigate')
async def csv_tier2_investigate(
    payload: dict,
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    api_key: str | None = Header(None, alias='x-api-key')
) -> dict:
    """Generate Tier 2 deep investigation summary for a single row.

    Expected payload:
        {
            "row": {...},
            "assessment_id": "assessment-xxx",
            "session_id": "session-xxx",
            "org": "orgname",
            "model": "gpt-4o"  # optional
        }

    Returns:
        {
            "tier2_summary": "...",
            "tier2_meta": {...},
            "cost": 0.015,
            "model": "gpt-4o"
        }
    """
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail='invalid_payload')

    row = payload.get('row') or {}
    if not isinstance(row, dict):
        raise HTTPException(status_code=400, detail='invalid_row')

    org = payload.get('org') or payload.get('tenant') or tenant_id or 'unknown'
    model = payload.get('model') or 'gpt-4o'  # Default to gpt-4o for T2

    try:
        from src.analysis.auto_llm import LLMAssessmentClient

        # Build context with tier2 flag
        context = {
            'tier': 'tier2',
            'org': org,
            'model': model,
            'assessment_id': payload.get('assessment_id'),
            'session_id': payload.get('session_id'),
            'auto_llm': True
        }

        # Call LLM client with tier2 context
        client = LLMAssessmentClient()
        result = client.summarize_row(row, context)

        # Extract results
        if isinstance(result, dict):
            tier2_summary = result.get('text') or result.get('summary') or ''
            tier2_meta = result.get('meta') or {}
            model_used = result.get('model') or model
            cost = float(tier2_meta.get('estimated_cost') or tier2_meta.get('cost') or 0.015)
        else:
            tier2_summary = str(result)
            tier2_meta = {}
            model_used = model
            cost = 0.015

        return {
            'tier2_summary': tier2_summary,
            'tier2_meta': tier2_meta,
            'cost': cost,
            'model': model_used,
            'status': 'success'
        }

    except Exception as e:
        import traceback
        return {
            'tier2_summary': f'Error generating T2 summary: {str(e)}',
            'tier2_meta': {},
            'cost': 0.0,
            'model': model,
            'status': 'error',
            'error': str(e),
            'traceback': traceback.format_exc()
        }
```

#### Change 1.2: Update deep_analyze to use faster default model (line 476)

**Location:** `src/api/csv_endpoints.py` around line 476

**Change FROM:**
```python
built = build_llm_row(src_row, {'auto_llm': auto, 'org': org, 'assessment_id': assessment_id, 'session_id': session_id})
```

**Change TO:**
```python
# Use gpt-4o-mini for T1 fast triage (5x faster than gpt-4o)
model = options.get('model') or os.getenv('T1_MODEL') or 'gpt-4o-mini'
built = build_llm_row(src_row, {
    'auto_llm': auto,
    'org': org,
    'assessment_id': assessment_id,
    'session_id': session_id,
    'model': model,
    'tier': 'tier1'  # Explicit tier1 for fast triage
})
```

---

### File 2: `src/analysis/auto_llm.py`

#### Change 2.1: Update default model in summarize_row (line 430)

**Location:** `src/analysis/auto_llm.py` line 430

**Change FROM:**
```python
resp = self._client.generate(user_prompt, model=context.get('model') or 'gpt-4o-mini', max_tokens=1024, tenant_id=context.get('org'), overrides=overrides)
```

**Change TO:**
```python
# Tier-based model selection
tier = (context or {}).get('tier', 'tier1')
default_model = 'gpt-4o' if tier == 'tier2' else 'gpt-4o-mini'
model = context.get('model') or os.getenv('T1_MODEL' if tier == 'tier1' else 'T2_MODEL') or default_model
max_tokens = 2048 if tier == 'tier2' else 1024  # More tokens for T2

resp = self._client.generate(
    user_prompt,
    model=model,
    max_tokens=max_tokens,
    tenant_id=context.get('org'),
    overrides=overrides
)
```

#### Change 2.2: Add cost tracking by tier (line 518)

**Location:** `src/analysis/auto_llm.py` line 518

**Change FROM:**
```python
row['_llm_cost'] = float(meta.get('estimated_cost') or meta.get('cost') or os.getenv('LLM_COST_PER_ROW') or 0.003)
```

**Change TO:**
```python
# Tier-based cost defaults
tier = (context or {}).get('tier', 'tier1')
default_cost = 0.015 if tier == 'tier2' else 0.003
row['_llm_cost'] = float(meta.get('estimated_cost') or meta.get('cost') or os.getenv('LLM_COST_PER_ROW') or default_cost)
row['_llm_tier'] = tier  # Track which tier generated this summary
```

---

## Phase 2: Frontend Changes

### File 3: `frontend/static/csv_deep_analysis.html`

#### Change 3.1: Move AI-Powered Insights section UP (lines 194-240)

**Location:** Currently around line 194

**Action:** CUT the entire `<section class="panel ai-panel">` (lines 194-240) and PASTE it RIGHT AFTER the Decision Snapshot section (after line 101).

**New Order should be:**
1. Top bar (lines 56-65)
2. LLM Summary panel (lines 67-77)
3. Decision Snapshot (lines 79-101)
4. **👉 AI-Powered Insights (moved here!)** ← NEW LOCATION
5. Quick Filter (lines 103-107)
6. Historical Context (lines 109-112)
7. ... rest of sections

**The moved section should look like:**

```html
  </section>

  <!-- AI-POWERED INSIGHTS - MOVED UP FOR VISIBILITY -->
  <section class="panel ai-panel">
    <h3 style="margin:0 0 8px;">🤖 AI-Powered Insights (On-Demand)</h3>
    <p class="inline-muted" style="margin:0 0 12px;">Each button calls the LLM only when needed. Costs are added to the running total.</p>

    <!-- NEW: Tier 2 Deep Investigation -->
    <div class="insight-row" style="border:2px solid var(--accent); padding:12px; border-radius:8px; margin-bottom:16px;">
      <div>
        <div style="font-weight:600; font-size:14px;">🔍 Tier 2: Deep Investigation (NEW!)</div>
        <div class="inline-muted" style="margin-top:4px;">
          Generate comprehensive 60-100 line threat hunting report with:
          <ul style="margin:6px 0 0; padding-left:20px; font-size:12px;">
            <li>Historical incident context (similar attacks in last 90 days)</li>
            <li>Attack scenario analysis with business impact</li>
            <li>Domain-specific forensic playbooks (endpoint vs network)</li>
            <li>MITRE-mapped required logs</li>
            <li>Decision criteria with hunt queries (KQL/SPL)</li>
          </ul>
        </div>
        <div class="cost-pill" style="margin-top:6px;">
          <span id="tier2Cost">$0.015</span> per run |
          <span id="tier2Model">gpt-4o</span> |
          Takes ~10-15s
        </div>
      </div>
      <div style="margin-top:10px;">
        <label style="display:inline-flex; align-items:center; gap:6px; margin-right:10px;">
          Model:
          <select id="tier2ModelSelect" class="btn" style="padding:4px 8px;">
            <option value="gpt-4o" selected>GPT-4o (Best quality)</option>
            <option value="claude-3-5-sonnet-20241022">Claude 3.5 Sonnet (Best reasoning)</option>
            <option value="gpt-4o-mini">GPT-4o-mini (Fast, cheaper)</option>
          </select>
        </label>
        <button class="btn btn-primary" onclick="generateTier2Investigation()" id="tier2Btn">
          Generate T2 Investigation ▶
        </button>
      </div>
      <div id="tier2Output" class="insight-output" style="margin-top:12px; display:none;">
        <pre style="white-space:pre-wrap; line-height:1.4; font-size:12px;" id="tier2SummaryPre"></pre>
      </div>
    </div>

    <!-- Existing DREAD Scenarios -->
    <div class="insight-row">
      <div>
        <div>Generate Detailed DREAD Scenarios</div>
        <div class="cost-pill">$0.001 per run | Last run cost: <span id="dreadLastCost">$0.0010</span></div>
      </div>
      <button class="btn" onclick="generateDREAD()">Generate</button>
    </div>
    <div id="dreadOutput" class="insight-output"></div>

    <!-- Existing Collection Playbook -->
    <div class="insight-row">
      <div>
        <div>Generate Collection Playbook for Missing Logs</div>
        <div class="cost-pill">$0.00000 per run (rule-based)</div>
      </div>
      <button class="btn" onclick="generatePlaybook()">Generate</button>
    </div>
    <div id="playbookOutput" class="insight-output"></div>
  </section>

  <section class="panel filter-panel">
    <h3 style="margin:0 0 6px;">Quick Filter</h3>
    <!-- rest of filter section -->
```

#### Change 3.2: Add Tier 2 JavaScript function (after line 680)

**Location:** Bottom of the `<script>` section, after the existing functions

**Add these functions:**

```javascript
      // ========================================================================
      // TIER 2 DEEP INVESTIGATION
      // ========================================================================

      async function generateTier2Investigation() {
        const btn = document.getElementById('tier2Btn');
        const output = document.getElementById('tier2Output');
        const summaryPre = document.getElementById('tier2SummaryPre');
        const modelSelect = document.getElementById('tier2ModelSelect');

        if (!currentRow) {
          alert('No row loaded. Return to CSV Analyzer and select a row.');
          return;
        }

        // Show loading state
        btn.disabled = true;
        btn.textContent = 'Generating T2 Investigation...';
        output.style.display = 'block';
        summaryPre.textContent = 'Calling LLM... This may take 10-15 seconds.\n\nBuilding comprehensive investigation report with:\n- Historical incident analysis\n- Attack scenario modeling\n- Domain-specific playbooks\n- MITRE-mapped log requirements\n- Hunt queries and decision criteria\n\nPlease wait...';

        const startTime = Date.now();
        const selectedModel = modelSelect.value;

        try {
          const response = await fetch('/api/v1/csv/tier2_investigate', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              ...authHeaders()
            },
            body: JSON.stringify({
              row: currentRow,
              assessment_id: currentRow._assessment_id || 'unknown',
              session_id: currentRow._session_id || 'unknown',
              org: localStorage.getItem('tenant_id') || 'demo',
              model: selectedModel
            })
          });

          if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
          }

          const result = await response.json();
          const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

          if (result.status === 'error') {
            summaryPre.textContent = `ERROR: ${result.error}\n\n${result.traceback || ''}`;
            return;
          }

          const tier2Summary = result.tier2_summary || 'No summary generated';
          const cost = result.cost || 0.015;
          const modelUsed = result.model || selectedModel;

          // Cache T2 summary in localStorage
          try {
            const cacheKey = `tier2_${currentRow.row_index || 0}_${currentRow.hash_sha256 || ''}`;
            localStorage.setItem(cacheKey, JSON.stringify({
              summary: tier2Summary,
              model: modelUsed,
              cost: cost,
              timestamp: Date.now()
            }));
          } catch (e) {
            console.warn('Failed to cache T2 summary:', e);
          }

          // Update running cost
          runningCost += cost;
          updateCostDisplay();

          // Display summary
          summaryPre.textContent = `═══════════════════════════════════════════════════════════════════\n` +
                                   `TIER 2 DEEP INVESTIGATION REPORT\n` +
                                   `═══════════════════════════════════════════════════════════════════\n` +
                                   `Model: ${modelUsed} | Cost: $${cost.toFixed(4)} | Time: ${elapsed}s\n` +
                                   `═══════════════════════════════════════════════════════════════════\n\n` +
                                   tier2Summary;

          // Update cost display
          document.getElementById('tier2Cost').textContent = `$${cost.toFixed(4)}`;
          document.getElementById('tier2Model').textContent = modelUsed;

        } catch (error) {
          summaryPre.textContent = `NETWORK ERROR: ${error.message}\n\nPlease check:\n1. Server is running\n2. Network connectivity\n3. Browser console for details`;
          console.error('Tier 2 generation failed:', error);
        } finally {
          btn.disabled = false;
          btn.textContent = 'Generate T2 Investigation ▶';
        }
      }

      // Check for cached T2 summary on page load
      function loadCachedTier2() {
        if (!currentRow) return;

        try {
          const cacheKey = `tier2_${currentRow.row_index || 0}_${currentRow.hash_sha256 || ''}`;
          const cached = localStorage.getItem(cacheKey);

          if (cached) {
            const data = JSON.parse(cached);
            const ageMinutes = Math.floor((Date.now() - data.timestamp) / 60000);

            if (ageMinutes < 60) {  // Cache valid for 1 hour
              const output = document.getElementById('tier2Output');
              const summaryPre = document.getElementById('tier2SummaryPre');

              summaryPre.textContent = `[CACHED ${ageMinutes}m ago]\n\n` + data.summary;
              output.style.display = 'block';

              document.getElementById('tier2Cost').textContent = `$${data.cost.toFixed(4)}`;
              document.getElementById('tier2Model').textContent = data.model;
            }
          }
        } catch (e) {
          console.warn('Failed to load cached T2:', e);
        }
      }
```

#### Change 3.3: Call loadCachedTier2 in hydrateSummary (line 339)

**Location:** End of `hydrateSummary()` function around line 339

**Add this line at the end of the function:**

```javascript
        renderHistoricalContext();
        loadAttackGraph();
        loadCachedTier2();  // ← ADD THIS LINE
      }
```

---

### File 4: `frontend/static/csv_analyzer.html`

#### Change 4.1: Update right panel to show T1 summaries (around line 450)

**Location:** Right panel where LLM summaries are displayed

**Find the section that shows row details in the right panel** (around line 450-500) and ensure it displays `llm_summary`:

```javascript
function showRowDetails(row, rowIndex) {
  const panel = document.getElementById('rowDetailsPanel');
  const content = document.getElementById('rowDetailsContent');

  if (!row) {
    panel.style.display = 'none';
    return;
  }

  // Build details HTML
  let html = `<h3>${row.process_name || row.name || 'Artifact'} on ${row.host || 'unknown'}</h3>`;
  html += `<div class="verdict-badge ${(row.verdict || '').toLowerCase()}">${row.verdict || 'Unknown'}</div>`;

  // Show T1 LLM Summary if available
  if (row.llm_summary) {
    html += `
      <div style="margin-top:12px; padding:12px; background:var(--bg-tertiary); border-radius:8px;">
        <h4 style="margin:0 0 8px;">🤖 AI Summary (T1)</h4>
        <pre style="white-space:pre-wrap; line-height:1.4; font-size:12px;">${escapeHtml(row.llm_summary)}</pre>
        <div style="margin-top:8px; font-size:11px; color:var(--text-muted);">
          Model: ${row._llm_model || 'unknown'} |
          Cost: $${(row._llm_cost || 0.003).toFixed(4)}
        </div>
      </div>
    `;
  } else {
    html += `
      <div style="margin-top:12px; padding:12px; background:var(--bg-tertiary); border-radius:8px; border:1px dashed var(--border-color);">
        <div style="color:var(--text-muted);">No AI summary generated. Enable Auto-LLM in settings.</div>
      </div>
    `;
  }

  // Rest of row details...
  html += `<div style="margin-top:12px;">`;
  html += `<strong>DREAD:</strong> ${row.dread_score || row._dread?.score || 0}<br>`;
  html += `<strong>Factors:</strong> ${(row.factors || []).join(', ')}<br>`;
  html += `</div>`;

  content.innerHTML = html;
  panel.style.display = 'block';
}
```

#### Change 4.2: Add model selection to settings modal (around line 300)

**Location:** In the settings/options modal

**Add a model selection dropdown:**

```html
<div class="form-group">
  <label for="t1ModelSelect">T1 Model (Fast Triage):</label>
  <select id="t1ModelSelect" class="form-control">
    <option value="gpt-4o-mini" selected>GPT-4o-mini (Fastest, $0.002/row)</option>
    <option value="claude-3-haiku-20240307">Claude 3 Haiku (Fast, $0.003/row)</option>
    <option value="gpt-4o">GPT-4o (Best quality, $0.008/row)</option>
  </select>
  <small class="form-text">Used for per-row summaries in Auto-LLM mode</small>
</div>
```

---

## Phase 3: Environment Configuration

### File 5: `.env`

**Add these new environment variables:**

```bash
# LLM Model Configuration for T1/T2
T1_MODEL=gpt-4o-mini           # Fast triage model (2-4s, $0.002/row)
T2_MODEL=gpt-4o                # Deep investigation model (10-15s, $0.015/row)

# Cost defaults (optional overrides)
LLM_COST_PER_ROW=0.003         # T1 default cost
T2_COST_PER_ROW=0.015          # T2 default cost

# Risk thresholds for T1 summaries
LLM_RISK_HIGH=7.0              # DREAD >= 7 = High risk
LLM_RISK_MED=4.0               # DREAD >= 4 = Medium risk
```

---

## Phase 4: Testing Procedures

### Test 1: T1 Summary Generation Speed Test

**File:** `tests/test_t1_summary_speed.py` (NEW)

```python
"""Test T1 summary generation speed with different models."""
import time
import pytest
from src.analysis.auto_llm import LLMAssessmentClient


def test_t1_gpt4o_mini_speed():
    """Test T1 summary with gpt-4o-mini (should be 2-5s)."""
    client = LLMAssessmentClient()

    test_row = {
        'process_name': 'msiexec.exe',
        'host': 'WORKSTATION-01',
        'user': 'admin',
        'factors': ['unsigned_sensitive_path', 'novel_global', 'parent_child_anomaly'],
        'verdict': 'SUSPICIOUS',
        'row_index': 0
    }

    context = {
        'tier': 'tier1',
        'model': 'gpt-4o-mini',
        'org': 'test',
        'auto_llm': True
    }

    start = time.time()
    result = client.summarize_row(test_row, context)
    elapsed = time.time() - start

    print(f"\n✓ T1 Summary generated in {elapsed:.2f}s")
    print(f"✓ Model: {result.get('model')}")
    print(f"✓ Cost: ${result.get('meta', {}).get('estimated_cost', 0):.4f}")
    print(f"✓ Length: {len(result.get('text', ''))} chars")

    assert elapsed < 10, f"T1 too slow: {elapsed:.2f}s (should be <10s)"
    assert result.get('text'), "No summary generated"
    assert 'WHAT IS IT' in result.get('text', '').upper(), "Missing required section"


def test_t1_vs_t2_speed_comparison():
    """Compare T1 vs T2 speed."""
    client = LLMAssessmentClient()

    test_row = {
        'process_name': 'powershell.exe',
        'host': 'WORKSTATION-02',
        'factors': ['cmdline_obfuscation', 'beaconing', 'c2_communication'],
        'verdict': 'CRITICAL'
    }

    # Test T1
    start_t1 = time.time()
    t1_result = client.summarize_row(test_row, {'tier': 'tier1', 'model': 'gpt-4o-mini'})
    t1_time = time.time() - start_t1

    # Test T2
    start_t2 = time.time()
    t2_result = client.summarize_row(test_row, {'tier': 'tier2', 'model': 'gpt-4o'})
    t2_time = time.time() - start_t2

    print(f"\n✓ T1: {t1_time:.2f}s | {len(t1_result.get('text', ''))} chars")
    print(f"✓ T2: {t2_time:.2f}s | {len(t2_result.get('text', ''))} chars")
    print(f"✓ T2 is {t2_time/t1_time:.1f}x slower (expected 2-4x)")

    assert t1_time < t2_time, "T1 should be faster than T2"
    assert len(t2_result.get('text', '')) > len(t1_result.get('text', '')), "T2 should be longer"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
```

**Run test:**
```bash
cd D:\AI\Threat_thy_sniffer
python -m pytest tests/test_t1_summary_speed.py -v -s
```

**Expected output:**
```
test_t1_gpt4o_mini_speed PASSED
✓ T1 Summary generated in 3.24s
✓ Model: gpt-4o-mini
✓ Cost: $0.0024
✓ Length: 842 chars

test_t1_vs_t2_speed_comparison PASSED
✓ T1: 3.45s | 856 chars
✓ T2: 12.31s | 2847 chars
✓ T2 is 3.6x slower (expected 2-4x)
```

---

### Test 2: T2 Endpoint Test

**File:** `tests/test_t2_endpoint.py` (NEW)

```python
"""Test T2 investigation endpoint."""
import pytest
from fastapi.testclient import TestClient
from src.api.app import app

client = TestClient(app)


def test_tier2_investigate_endpoint():
    """Test /api/v1/csv/tier2_investigate endpoint."""

    payload = {
        'row': {
            'process_name': 'cmd.exe',
            'host': 'SERVER-01',
            'user': 'SYSTEM',
            'factors': ['privilege_escalation', 'lateral_movement_smb', 'credential_dumping'],
            'verdict': 'CRITICAL',
            'dread_score': 9.2,
            'row_index': 5
        },
        'assessment_id': 'test-assessment-001',
        'org': 'test-org',
        'model': 'gpt-4o-mini'  # Use mini for faster test
    }

    response = client.post(
        '/api/v1/csv/tier2_investigate',
        json=payload,
        headers={'x-api-key': 'devkey123'}
    )

    assert response.status_code == 200, f"Failed: {response.text}"

    result = response.json()
    print(f"\n✓ T2 Response received")
    print(f"✓ Status: {result.get('status')}")
    print(f"✓ Model: {result.get('model')}")
    print(f"✓ Cost: ${result.get('cost', 0):.4f}")
    print(f"✓ Summary length: {len(result.get('tier2_summary', ''))} chars")

    assert result['status'] == 'success', f"Error: {result.get('error')}"
    assert result['tier2_summary'], "No T2 summary generated"
    assert 'SECTION 1:' in result['tier2_summary'], "Missing T2 sections"
    assert len(result['tier2_summary']) > 1000, "T2 summary too short"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
```

**Run test:**
```bash
python -m pytest tests/test_t2_endpoint.py -v -s
```

---

### Test 3: End-to-End UI Test

**File:** `tests/test_csv_deep_analysis_ui.py` (NEW)

```python
"""Playwright test for csv_deep_analysis.html T1/T2 UI."""
import pytest
from playwright.sync_api import sync_playwright, expect
import json
import time


def test_csv_deep_analysis_t1_t2_flow():
    """Test full T1 summary display and T2 button functionality."""

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        page = browser.new_page()

        # Mock data with T1 summary
        mock_rows = [{
            'row_index': 0,
            'process_name': 'powershell.exe',
            'host': 'WORKSTATION-01',
            'user': 'admin',
            'verdict': 'SUSPICIOUS',
            'factors': ['cmdline_obfuscation', 'encoded_command'],
            'llm_summary': 'WHAT IS IT?: PowerShell execution with encoded command\n\nEXPLOITABILITY: High - encoded commands often hide malicious payloads\n\nWHAT TO DO?: Decode command, check for C2 indicators\n\nCONCISE PLAYBOOK:\n  1. Decode base64: [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($cmd))\n  2. Check process tree: Get-Process powershell | Select ParentProcessId\n  3. Isolate if suspicious',
            '_llm_model': 'gpt-4o-mini',
            '_llm_cost': 0.0028,
            '_llm_tier': 'tier1',
            'dread_score': 7.5
        }]

        # Set localStorage with mock data
        page.goto('http://localhost:8080/static/csv_deep_analysis.html')
        page.evaluate(f"localStorage.setItem('csv_last_results', '{json.dumps(mock_rows)}')")
        page.evaluate("localStorage.setItem('csv_deep_row', '0')")
        page.reload()

        print("\n✓ Page loaded with mock data")

        # Test 1: Check T1 summary is displayed
        time.sleep(1)
        llm_summary = page.locator('#llmSummary')
        expect(llm_summary).to_be_visible()
        summary_text = llm_summary.text_content()

        assert 'WHAT IS IT' in summary_text, "T1 summary not displayed"
        print(f"✓ T1 Summary displayed ({len(summary_text)} chars)")

        # Test 2: Check AI-Powered Insights section is AFTER Decision Snapshot
        ai_section = page.locator('.ai-panel')
        decision_section = page.locator('.snapshot-panel')

        expect(ai_section).to_be_visible()
        expect(decision_section).to_be_visible()

        # Check order: Decision Snapshot should come before AI Insights
        sections = page.locator('section.panel').all()
        ai_index = None
        decision_index = None

        for i, section in enumerate(sections):
            if 'ai-panel' in section.get_attribute('class'):
                ai_index = i
            if 'snapshot-panel' in section.get_attribute('class'):
                decision_index = i

        assert decision_index < ai_index, f"AI section ({ai_index}) should come AFTER Decision ({decision_index})"
        print(f"✓ AI-Powered Insights section in correct position (#{ai_index} after Decision #{decision_index})")

        # Test 3: Check T2 button exists
        tier2_btn = page.locator('#tier2Btn')
        expect(tier2_btn).to_be_visible()
        print("✓ T2 Investigation button found")

        # Test 4: Click T2 button and wait for response
        print("✓ Clicking T2 button (will take 10-15s)...")
        tier2_btn.click()

        # Wait for loading state
        expect(tier2_btn).to_contain_text('Generating', timeout=2000)
        print("✓ T2 generation started")

        # Wait for completion (up to 30s)
        expect(tier2_btn).to_contain_text('Generate T2 Investigation', timeout=30000)
        print("✓ T2 generation completed")

        # Test 5: Check T2 output is displayed
        tier2_output = page.locator('#tier2Output')
        expect(tier2_output).to_be_visible()

        tier2_text = page.locator('#tier2SummaryPre').text_content()
        assert len(tier2_text) > 1000, f"T2 summary too short: {len(tier2_text)} chars"
        assert 'SECTION 1:' in tier2_text, "Missing T2 section headers"
        assert 'SECTION 2:' in tier2_text, "Missing T2 historical context"

        print(f"✓ T2 Summary displayed ({len(tier2_text)} chars)")
        print(f"✓ Contains required sections: SECTION 1, SECTION 2")

        # Test 6: Check cost tracking
        running_cost = page.locator('#runningCost').text_content()
        assert running_cost != '$0.0000', "Cost not updated"
        print(f"✓ Running cost updated: {running_cost}")

        browser.close()
        print("\n✅ ALL UI TESTS PASSED")


if __name__ == '__main__':
    test_csv_deep_analysis_t1_t2_flow()
```

**Run test:**
```bash
python tests/test_csv_deep_analysis_ui.py
```

---

### Test 4: Manual Testing Checklist

**Step-by-step manual test:**

1. **Start server:**
   ```bash
   cd D:\AI\Threat_thy_sniffer
   python run_platform.py
   ```

2. **Upload test CSV to CSV Analyzer:**
   - Go to `http://localhost:8080/static/csv_analyzer.html`
   - Upload `dump/Cyberstash_csv2.xlsx`
   - Enable "Auto-LLM" checkbox
   - Set Model to "gpt-4o-mini"
   - Click "Analyze CSV"

3. **Wait for T1 summaries (should take 2-4s per row):**
   - Watch right panel for T1 summaries appearing
   - Check console for timing logs
   - Verify summaries contain: WHAT IS IT, EXPLOITABILITY, WHAT TO DO, PLAYBOOK

4. **Open Deep Dive for a row:**
   - Click any row
   - Click "Deep Dive" button (or click row to open in new tab)
   - Should show T1 summary at top

5. **Check AI-Powered Insights section position:**
   - Scroll down
   - AI-Powered Insights should be RIGHT AFTER Decision Snapshot
   - Should see new "Tier 2: Deep Investigation" section at top

6. **Test T2 generation:**
   - Select model (default: gpt-4o)
   - Click "Generate T2 Investigation ▶"
   - Should see "Generating T2 Investigation..." for 10-15s
   - When complete, should show 60-100 line report with sections:
     - SECTION 1: WHAT IS IT? WHY SUSPICIOUS?
     - SECTION 2: HISTORICAL CONTEXT
     - SECTION 3: ATTACK SCENARIO & BUSINESS IMPACT
     - SECTION 4: FORENSIC COLLECTION PLAYBOOK
     - SECTION 5: REQUIRED LOGS
     - SECTION 6: DECISION CRITERIA

7. **Test caching:**
   - Refresh page (F5)
   - T2 summary should load from cache instantly
   - Should show "[CACHED Xm ago]" at top

8. **Test cost tracking:**
   - Running cost at top should increase after T2 generation
   - Should show model used and cost per run

---

## Phase 5: Verification Checklist

After implementing all changes, verify:

### Backend Verification
- [ ] `/api/v1/csv/tier2_investigate` endpoint exists
- [ ] Endpoint accepts `model` parameter
- [ ] Endpoint passes `tier='tier2'` to `LLMAssessmentClient`
- [ ] T1 summaries use `gpt-4o-mini` by default
- [ ] T2 summaries use `gpt-4o` by default
- [ ] Cost tracking differentiates T1 vs T2

### Frontend Verification
- [ ] AI-Powered Insights section is AFTER Decision Snapshot (not at bottom)
- [ ] T2 Investigation button exists and is styled prominently
- [ ] T2 model selector dropdown works
- [ ] T2 summary displays in collapsible section
- [ ] T2 generation shows loading state
- [ ] T2 cost/time displays correctly
- [ ] T1 summary shows in right panel of csv_analyzer.html
- [ ] T1 summary shows at top of csv_deep_analysis.html

### Performance Verification
- [ ] T1 summaries generate in 2-5s (gpt-4o-mini)
- [ ] T2 summaries generate in 10-15s (gpt-4o)
- [ ] T1 summaries are 30-45 lines / 500-1000 chars
- [ ] T2 summaries are 60-100 lines / 2000-4000 chars
- [ ] Cached T2 summaries load instantly

### Functional Verification
- [ ] T1 prompt includes: WHAT IS IT, EXPLOITABILITY, WHAT TO DO, PLAYBOOK
- [ ] T2 prompt includes all 6 sections (WHAT IS IT, HISTORICAL, ATTACK SCENARIO, PLAYBOOK, LOGS, DECISION)
- [ ] T2 historical context queries work (if `HistoricalIncidentsRepo` available)
- [ ] T2 domain detection works (network vs endpoint)
- [ ] T2 MITRE-mapped logs work (if `get_logs_for_mitre` available)

---

## Phase 6: Rollback Plan

If issues occur, rollback by reverting these files:

```bash
git checkout HEAD -- src/api/csv_endpoints.py
git checkout HEAD -- src/analysis/auto_llm.py
git checkout HEAD -- frontend/static/csv_deep_analysis.html
git checkout HEAD -- frontend/static/csv_analyzer.html
```

---

## Expected Results

### Before Changes
- T1 summaries: 15-30s (too slow!)
- T2 summaries: Don't exist
- AI section: At bottom of page
- Cost: $0.008-0.015 per T1 row

### After Changes
- T1 summaries: 2-5s ✅ (5-10x faster)
- T2 summaries: 10-15s ✅ (new feature!)
- AI section: After Decision Snapshot ✅
- Cost: $0.002-0.003 per T1 row ✅ (3-5x cheaper)

### Speed Comparison Matrix

| Model | T1 Speed | T1 Cost | T2 Speed | T2 Cost | Recommendation |
|-------|----------|---------|----------|---------|----------------|
| gpt-4o-mini | ⚡ 2-4s | $0.002 | 5-8s | $0.005 | **Best for T1** |
| claude-3-haiku | ⚡ 2-5s | $0.003 | 6-10s | $0.008 | **Best for T1** |
| gpt-4o | 6-10s | $0.008 | ⚡ 10-15s | $0.015 | **Best for T2** |
| claude-3.5-sonnet | 8-12s | $0.015 | ⚡ 12-18s | $0.020 | **Best for T2** |

---

## Troubleshooting

### Issue 1: T1 summaries still slow (>10s)
**Cause:** Not using gpt-4o-mini
**Fix:** Check `.env` has `T1_MODEL=gpt-4o-mini` and restart server

### Issue 2: T2 button does nothing
**Cause:** Endpoint not found
**Fix:** Check `src/api/csv_endpoints.py` has `@router.post('/tier2_investigate')` and server restarted

### Issue 3: T2 summary is short (<500 chars)
**Cause:** Using T1 prompt instead of T2
**Fix:** Check `tier='tier2'` is passed in context

### Issue 4: AI section still at bottom
**Cause:** HTML changes not applied
**Fix:** Clear browser cache (Ctrl+Shift+R) and check line 103 in csv_deep_analysis.html

### Issue 5: Cost not tracking
**Cause:** Meta object not updated
**Fix:** Check `row['_llm_cost']` is set in `build_llm_row()`

---

## File Changes Summary

| File | Lines Changed | Change Type |
|------|--------------|-------------|
| `src/api/csv_endpoints.py` | +80 lines after 566 | Add T2 endpoint |
| `src/analysis/auto_llm.py` | ~10 lines (430, 518) | Model selection |
| `frontend/static/csv_deep_analysis.html` | Move 50 lines + add 120 lines | Reorder + T2 UI |
| `frontend/static/csv_analyzer.html` | ~30 lines | T1 display |
| `.env` | +8 lines | Config |
| `tests/test_t1_summary_speed.py` | +80 lines (new) | Tests |
| `tests/test_t2_endpoint.py` | +50 lines (new) | Tests |
| `tests/test_csv_deep_analysis_ui.py` | +120 lines (new) | Tests |

**Total:** ~550 lines added/modified across 8 files

---

## Success Criteria

✅ **Implementation is successful when:**

1. T1 summaries generate in <5s per row
2. T2 button exists and generates 60-100 line reports in 10-15s
3. AI-Powered Insights section appears right after Decision Snapshot
4. T1 summaries display in CSV Analyzer right panel
5. All 3 test files pass
6. Manual testing checklist completes without errors
7. Cost per T1 row drops from $0.008 to $0.002-0.003
8. User can select T1/T2 models via dropdown

---

**END OF IMPLEMENTATION GUIDE**

Generated: 2025-11-25
Version: 1.0
Priority: HIGH - Demo Blocker
