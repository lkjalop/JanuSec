# LLM Triage Summary - Implementation Guide

**Purpose:** Fast triage with 30-45 line LLM summaries, budget-conscious, prioritized processing

**Date:** 2025-01-21

**Status:** Implementation Ready

---

## 🎯 Core Requirements

### User Workflow
1. **Upload CSV/XLSX** (e.g., 550 rows)
2. **Deep Analyze runs** → 150 rows flagged suspicious
3. **Prioritized LLM processing:**
   - Don't process all 150 upfront
   - Toggleable limit: Top 25, 50, 75, or All (sorted by DREAD)
   - User can request more summaries on-demand
4. **30-45 line summary per row:**
   - What is it?
   - Exploitability factor
   - What to do?
   - Concise playbook (3-5 commands)
   - Missing logs (IF suspected by 21-stage pipeline)
5. **Fast triage decision:**
   - Glance at summary (30 seconds)
   - Escalate → Click "Investigate Further" (new tab)
   - OR Move on → Next row
6. **Track processed rows:**
   - Visual indicator (✅ vs ⏸️)
   - Don't re-process (save GPU/tokens)
7. **Cost tracking:**
   - External API: Track tokens + cost
   - Local GPU: Track calls + GPU time (no $$$ assigned)

---

## 📋 30-45 Line Summary Schema

### Output Format

```
╔═══════════════════════════════════════════════════════════════════╗
║ Row 42: powershell.exe (DREAD 9.2) - CRITICAL                    ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║ 📌 WHAT IS IT? (2-3 lines)                                        ║
║ Excel macro spawned encoded PowerShell. Likely C2 beacon from    ║
║ phishing email. Base64 decodes to '$client' variable.            ║
║                                                                   ║
║ 💥 EXPLOITABILITY (3-4 lines)                                     ║
║ Attacker can use this to:                                        ║
║ • Steal credentials (Mimikatz, browser passwords)                ║
║ • Lateral movement to DC if user1 has domain privileges          ║
║ • Deploy ransomware across network                               ║
║                                                                   ║
║ ⚡ WHAT TO DO? (3-4 lines)                                        ║
║ 1. ISOLATE host INFECTED-01 immediately                          ║
║ 2. Decode Base64 command to find C2 domain                       ║
║ 3. Reset user1 password + check AD for lateral movement          ║
║                                                                   ║
║ 📋 CONCISE PLAYBOOK (5-8 lines)                                   ║
║ Step 1: Isolate-Host -HostName INFECTED-01                       ║
║ Step 2: Decode: [Convert]::FromBase64String('JABj...')           ║
║ Step 3: Check AD: Get-WinEvent -Id 4624 | Where user1            ║
║ Step 4: Block C2 domain at firewall                              ║
║ Step 5: Reimage host, don't just "clean"                         ║
║                                                                   ║
║ ⚠️ MISSING LOGS (3-5 lines - IF suspected):                      ║
║ [21-stage pipeline flagged potential correlation]                ║
║ • No PowerShell Event 4104 - can't see full script content       ║
║ • No firewall logs - can't confirm C2 IP/domain                  ║
║ • No AD Event 4624 - can't verify lateral movement               ║
║ Collecting these would CONFIRM/DENY if this is real C2 vs FP.    ║
║                                                                   ║
║ [🔍 Investigate Further - Open New Tab]                          ║
╚═══════════════════════════════════════════════════════════════════╝

Lines: ~35-40 ✅
Read time: ~30 seconds
Decision: Escalate OR Move on
```

### Line Budget

| Section | Lines | Purpose |
|---------|-------|---------|
| Header | 1-2 | Row index, process name, DREAD, verdict |
| What is it? | 2-3 | Quick context |
| Exploitability | 3-4 | How attackers use it |
| What to do? | 3-4 | Immediate action |
| Concise playbook | 5-8 | Copy-paste commands |
| Missing logs (conditional) | 3-5 | IF 21-stage pipeline flagged |
| Footer | 1 | "Investigate Further" button |
| **Total** | **30-45** | |

---

## 🎯 Prioritization & Toggleable Limits

### Problem
- 550 rows uploaded, 150 flagged suspicious
- Processing all 150 × $0.003 = **$0.45** upfront
- 150 × 2s LLM latency = **5 minutes** wait time
- Analyst drowns in 150 × 40 lines = **6,000 lines**

### Solution: Prioritize Top N by DREAD

#### Backend Logic
```python
def prioritize_rows_for_llm(rows, limit=25):
    """
    Sort suspicious rows by DREAD score, take top N
    """
    # Filter suspicious only
    suspicious = [r for r in rows if r.get('verdict', '').upper() in ['SUSPICIOUS', 'CRITICAL', 'HIGH']]

    # Sort by DREAD score (high to low)
    sorted_rows = sorted(
        suspicious,
        key=lambda r: r.get('_dread', {}).get('score', 0),
        reverse=True
    )

    # Take top N
    return sorted_rows[:limit] if limit > 0 else sorted_rows
```

#### Frontend UI
```html
<label style="display:inline-flex; align-items:center; gap:8px;">
  <span class="small">LLM Summaries:</span>
  <select id="llmLimit" class="btn" style="padding:6px 10px;">
    <option value="25" selected>Top 25 (DREAD sorted)</option>
    <option value="50">Top 50</option>
    <option value="75">Top 75</option>
    <option value="0">All suspicious rows</option>
  </select>
</label>
<span class="small inline-info" id="llmCostEstimate">Est. cost: $0.075</span>
```

#### Cost Calculation
```javascript
document.getElementById('llmLimit').addEventListener('change', function(){
  var limit = parseInt(this.value, 10);
  var suspiciousCount = (window.LAST_RESULTS || []).filter(r =>
    ['SUSPICIOUS', 'CRITICAL', 'HIGH'].includes((r.verdict||'').toUpperCase())
  ).length;

  var actualCount = (limit === 0) ? suspiciousCount : Math.min(limit, suspiciousCount);
  var cost = (actualCount * 0.003).toFixed(3);

  document.getElementById('llmCostEstimate').textContent =
    'Est. cost: $' + cost + ' (' + actualCount + ' rows)';
});
```

#### "Generate More Summaries" Button
```html
<button id="btnGenerateMore" class="btn" style="display:none;">
  Generate Next 25 LLM Summaries
</button>
```

```javascript
document.getElementById('btnGenerateMore').addEventListener('click', async function(){
  // Find rows without LLM summary, sorted by DREAD
  var pending = (window.LAST_RESULTS || [])
    .filter(r => !r._llm_processed && ['SUSPICIOUS', 'CRITICAL', 'HIGH'].includes((r.verdict||'').toUpperCase()))
    .sort((a, b) => (b._dread?.score || 0) - (a._dread?.score || 0))
    .slice(0, 25);

  if (!pending.length) {
    alert('All suspicious rows already have LLM summaries');
    return;
  }

  // Call backend to generate summaries for next 25
  var resp = await fetch('/api/v1/assessments/generate_llm_summaries', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ row_indices: pending.map((r, idx) => idx) })
  });

  if (resp.ok) {
    var updated = await resp.json();
    // Merge updated rows back into LAST_RESULTS
    window.LAST_RESULTS = window.LAST_RESULTS.map(r => {
      var match = updated.rows.find(u => u.row_index === r.row_index);
      return match || r;
    });
    renderTableFromResults();
  }
});
```

### Cost Impact

| Rows Processed | Cost | Latency | Lines Output |
|----------------|------|---------|--------------|
| **25** (Top priority) | **$0.075** | **~50s** | **1,000** |
| 50 | $0.15 | ~100s | 2,000 |
| 75 | $0.225 | ~150s | 3,000 |
| 150 (All) | $0.45 | ~300s | 6,000 |

**Savings (Top 25 vs All):** 83% cost, 83% latency, 83% cognitive load

---

## ✅ Track Which Rows Have LLM Summary (Don't Re-Process)

### Problem
- User clicks "Generate More" multiple times
- Without tracking → re-process same rows → waste GPU/tokens
- Need visual indicator: which rows already have summary?

### Solution: Add `_llm_processed` Flag

#### Backend Metadata
```python
def generate_llm_summary(row, context):
    """
    Generate 30-45 line LLM summary
    """
    # Call LLM
    llm_output = llm_client.summarize_row(row, context, max_lines=45)

    # Add metadata
    row['llm_summary'] = llm_output
    row['_llm_processed'] = True
    row['_llm_timestamp'] = datetime.utcnow().isoformat()
    row['_llm_model'] = context.get('model', 'gpt-4o')
    row['_llm_cost'] = context.get('cost', 0.003)  # 0 for local GPU
    row['_llm_tokens'] = {
        'input': context.get('input_tokens', 0),
        'output': context.get('output_tokens', 0)
    }

    return row
```

#### Skip Already-Processed Rows
```python
def generate_batch_summaries(rows, batch_size=25):
    """
    Process only rows without LLM summary
    """
    # Filter pending rows
    pending = [r for r in rows if not r.get('_llm_processed')]

    if not pending:
        return {'message': 'All rows already processed', 'rows': []}

    # Sort by DREAD
    sorted_pending = sorted(
        pending,
        key=lambda r: r.get('_dread', {}).get('score', 0),
        reverse=True
    )

    # Take top N
    to_process = sorted_pending[:batch_size]

    # Process batch
    processed = []
    for row in to_process:
        row_with_summary = generate_llm_summary(row, context={})
        processed.append(row_with_summary)

    return {'rows': processed, 'count': len(processed)}
```

#### Frontend Visual Indicator
```javascript
function renderRow(row, index){
  var hasLLM = row._llm_processed || row.llm_summary;
  var icon = hasLLM ? '✅' : '⏸️';
  var tooltip = hasLLM
    ? 'LLM summary generated at ' + (row._llm_timestamp || 'unknown')
    : 'No LLM summary yet - click "Generate More" to process';

  var modelBadge = '';
  if (hasLLM && row._llm_model) {
    var isLocal = row._llm_model.toLowerCase().includes('ollama') ||
                  row._llm_model.toLowerCase().includes('llama');
    var costText = isLocal ? 'Local GPU' : '$' + (row._llm_cost || 0.003);
    modelBadge = '<span class="pill" style="font-size:10px; margin-left:6px;" title="Model: '+row._llm_model+'">'
               + costText + '</span>';
  }

  return '<tr>'
    + '<td><span title="'+tooltip+'">'+icon+'</span> '+index+modelBadge+'</td>'
    + '<td>'+escapeHtml(row.process_name || 'unknown')+'</td>'
    + '<td>'+escapeHtml(row.verdict || 'unknown')+'</td>'
    + '<td>'+((row._dread && row._dread.score) || 0)+'</td>'
    + '<td>'
    + (hasLLM ? '<button class="btn" onclick="showLLMSummary('+index+')">View Summary</button>' : '')
    + '</td>'
    + '</tr>';
}
```

#### Show "Generate More" Button If Pending
```javascript
function updateGenerateMoreButton(){
  var pendingCount = (window.LAST_RESULTS || []).filter(r =>
    !r._llm_processed &&
    ['SUSPICIOUS', 'CRITICAL', 'HIGH'].includes((r.verdict||'').toUpperCase())
  ).length;

  var btn = document.getElementById('btnGenerateMore');
  if (pendingCount > 0) {
    btn.style.display = 'inline-flex';
    btn.textContent = 'Generate Next ' + Math.min(25, pendingCount) + ' LLM Summaries';
  } else {
    btn.style.display = 'none';
  }
}
```

---

## ⚠️ Missing Logs - Conditional Logic

### When to Include "Missing Logs" Section

**Don't show for every row!** Only if 21-stage pipeline detected:
1. **Correlation score > 0.5** (suspicious relationships found)
2. **Attack pattern identified** (C2, lateral movement, persistence, credential access)
3. **LLM confidence < 0.8** (needs more data to confirm/deny)

#### Backend Logic
```python
def should_include_missing_logs(row, pipeline_context):
    """
    Only include missing logs if 21-stage pipeline flagged something

    Args:
        row: The artifact row
        pipeline_context: Results from 21-stage deep analyze pipeline

    Returns:
        bool: True if missing logs section should be included
    """
    # Check correlation score from graph/correlation stage
    correlation_score = pipeline_context.get('correlation', {}).get('score', 0)
    if correlation_score > 0.5:
        return True

    # Check if high-risk attack patterns detected
    attack_patterns = pipeline_context.get('attack_patterns', [])
    high_risk_patterns = ['c2', 'lateral_movement', 'persistence', 'credential_access', 'exfiltration']
    if any(pattern in attack_patterns for pattern in high_risk_patterns):
        return True

    # Check if LLM confidence is low (needs more data)
    llm_confidence = pipeline_context.get('llm_confidence', 1.0)
    if llm_confidence < 0.8:
        return True

    # Check if factors suggest missing critical telemetry
    factors = row.get('factors', [])
    telemetry_gaps = ['no_network_logs', 'no_parent_process', 'no_user_context', 'no_registry_data']
    if any(gap in factors for gap in telemetry_gaps):
        return True

    # Otherwise, skip missing logs section
    return False
```

#### LLM Prompt - Conditional Section
```python
def build_llm_prompt(row, pipeline_context):
    """
    Build 30-45 line LLM summary prompt
    """
    prompt = f"""
You are a SOC analyst performing FAST TRIAGE. Analyze this artifact and provide a concise 30-45 line summary.

ARTIFACT:
{json.dumps(row, indent=2)}

21-STAGE PIPELINE CONTEXT:
- DREAD Score: {pipeline_context.get('dread_score', 'N/A')}
- MITRE Techniques: {pipeline_context.get('mitre_tags', [])}
- Suspicious Factors: {pipeline_context.get('factors', [])}
- Graph Correlation Score: {pipeline_context.get('correlation', {}).get('score', 0)}
- Attack Patterns Detected: {pipeline_context.get('attack_patterns', [])}
- Threat Intel Hits: {pipeline_context.get('threat_intel', 'None')}

OUTPUT FORMAT (30-45 lines max):

📌 WHAT IS IT? (2-3 lines)
[Brief context: what process, what behavior, what attack pattern]

💥 EXPLOITABILITY (3-4 lines)
Attacker can use this to:
• [Damage scenario 1]
• [Damage scenario 2]
• [Damage scenario 3]

⚡ WHAT TO DO? (3-4 lines)
[Immediate action - 3 steps max, be specific]

📋 CONCISE PLAYBOOK (5-8 lines)
Step 1: [PowerShell/CLI command with context]
Step 2: [PowerShell/CLI command with context]
Step 3: [PowerShell/CLI command with context]
...
"""

    # CONDITIONAL: Only add missing logs if pipeline flagged something
    if should_include_missing_logs(row, pipeline_context):
        prompt += """
⚠️ MISSING LOGS (3-5 lines):
The 21-stage pipeline detected correlation/attack patterns but lacks complete telemetry.
Identify what logs would help CONFIRM or DENY if this is a real attack:
• [Missing log 1] - would confirm/deny [specific suspicion]
• [Missing log 2] - would confirm/deny [specific suspicion]
"""
    else:
        prompt += """
[Sufficient telemetry available - no missing logs section needed]
"""

    prompt += """
RULES:
- Keep total output to 30-45 lines
- Be concise but actionable
- Use bullet points for readability
- Include copy-paste commands in playbook
- Base all analysis on provided context (no hallucination)
"""

    return prompt
```

#### Example Output (With Missing Logs)
```
📌 WHAT IS IT?
Excel macro spawned encoded PowerShell. Likely C2 beacon from phishing email.

💥 EXPLOITABILITY
Attacker can use this to:
• Steal credentials (Mimikatz, browser passwords)
• Lateral movement to DC if user has privileges
• Deploy ransomware

⚡ WHAT TO DO?
1. ISOLATE host INFECTED-01 immediately
2. Decode Base64 command to find C2 domain
3. Reset user1 password + check AD for lateral movement

📋 CONCISE PLAYBOOK
Step 1: Isolate-Host -HostName INFECTED-01
Step 2: [Convert]::FromBase64String('JABj...')
Step 3: Get-WinEvent -Id 4624 | Where user1

⚠️ MISSING LOGS:
• No PowerShell Event 4104 - can't see full script content
• No firewall logs - can't confirm C2 IP/domain
• No AD Event 4624 - can't verify lateral movement
Collecting these would CONFIRM/DENY if this is real C2.
```

#### Example Output (No Missing Logs)
```
📌 WHAT IS IT?
Signed Microsoft binary (taskmgr.exe) launched from normal path.

💥 EXPLOITABILITY
Low risk - legitimate system process.

⚡ WHAT TO DO?
No immediate action needed. Monitor for anomalies.

📋 CONCISE PLAYBOOK
Step 1: Verify signature: Get-AuthenticodeSignature C:\Windows\System32\taskmgr.exe
Step 2: Check parent process for legitimacy
Step 3: Allowlist if confirmed benign

[No missing logs section - sufficient telemetry confirms benign]
```

---

## 🔍 "Investigate Further" New Tab - Progressive Disclosure

### Design: Option C (RECOMMENDED)

**Cost-conscious, doesn't overload analyst, transparent**

#### Tab Structure
```
╔═══════════════════════════════════════════════════════════════════╗
║ Deep Dive - Row 42: powershell.exe                               ║
║ DREAD: 9.2 | Verdict: CRITICAL | Host: INFECTED-01               ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║ [30-45 line LLM summary - always visible, cached, FREE]          ║
║                                                                   ║
╠═══════════════════════════════════════════════════════════════════╣
║ 📊 ADDITIONAL CONTEXT (free - from 21-stage pipeline)            ║
║                                                                   ║
║ ▶ Raw Artifact Data [click to expand]                            ║
║   Process: powershell.exe                                        ║
║   Path: C:\Windows\System32\WindowsPowerShell\v1.0\...          ║
║   Hash: badbadbadbadbadbadbadbadbadbadb                          ║
║   Parent: excel.exe                                              ║
║   Command: powershell.exe -NoProfile -e JABjAGwAaQ...           ║
║                                                                   ║
║ ▶ 21-Stage Pipeline Results [click to expand]                    ║
║   Stage 1 (GeoIP): Country=US, ASN=15169                         ║
║   Stage 2 (ThreatIntel): No VirusTotal hits                      ║
║   Stage 3 (DREAD): Score=9.2 (Critical)                          ║
║   Stage 4 (MITRE): T1059.001 (PowerShell)                       ║
║   ...                                                             ║
║                                                                   ║
║ ▶ MITRE ATT&CK Mapping [click to expand]                         ║
║   T1059.001: Command and Scripting Interpreter (PowerShell)     ║
║   T1566.001: Phishing - Spearphishing Attachment                ║
║                                                                   ║
║ ▶ Graph Correlation [click to expand]                            ║
║   Correlation Score: 0.87 (High)                                 ║
║   Related Entities: excel.exe → powershell.exe → network        ║
║                                                                   ║
╠═══════════════════════════════════════════════════════════════════╣
║ 💡 AI-POWERED INSIGHTS (on-demand, costs tokens)                 ║
║                                                                   ║
║ ▶ Generate Detailed DREAD Scenarios [$0.001] [Generate]          ║
║   Expands damage/exploitability with business impact             ║
║                                                                   ║
║ ▶ Generate Collection Playbook for Missing Logs [$0.0008]        ║
║   Step-by-step commands to collect AD/network/registry logs      ║
║                                                                   ║
║ ▶ Generate Lateral Movement Hunt Query [$0.0008] [Generate]      ║
║   Kusto/Splunk query to find other compromised hosts             ║
║                                                                   ║
║ ▶ Generate Executive Summary (CISO) [$0.0005] [Generate]         ║
║   Non-technical business impact summary                          ║
║                                                                   ║
║ Running cost for this row: $0.003 (initial summary only)         ║
║                                                                   ║
╠═══════════════════════════════════════════════════════════════════╣
║ 📋 ANALYST NOTES                                                  ║
║ ┌─────────────────────────────────────────────────────────────┐  ║
║ │ [Analyst types investigation notes here]                    │  ║
║ │                                                             │  ║
║ └─────────────────────────────────────────────────────────────┘  ║
║                                                                   ║
║ Analyst: alice@company.com | Timestamp: 2025-01-21 14:32 UTC    ║
║                                                                   ║
║ [Save Notes] [Mark as Escalated] [Mark as False Positive]        ║
║ [Export to PDF] [Copy Triage Summary]                            ║
╚═══════════════════════════════════════════════════════════════════╝
```

#### Implementation: `csv_deep_analysis.html` (New File)

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Deep Dive - Row Analysis</title>
  <link rel="stylesheet" href="/static/css/theme.css" />
  <script defer src="/static/js/theme.js"></script>
  <style>
    .section-header {
      cursor: pointer;
      padding: 8px;
      background: var(--bg-tertiary);
      border-radius: 6px;
      margin: 8px 0;
    }
    .section-body {
      display: none;
      padding: 12px;
      border-left: 2px solid var(--border);
      margin-left: 12px;
    }
    .section-body.expanded { display: block; }
    .ai-insight-btn {
      margin: 6px 0;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .cost-badge {
      font-size: 11px;
      padding: 2px 6px;
      border-radius: 999px;
      background: rgba(255,255,255,0.08);
    }
  </style>
</head>
<body>
  <div class="wrapper">
    <h2 id="rowTitle">Deep Dive - Row Analysis</h2>

    <!-- 30-45 line LLM summary (cached) -->
    <div class="panel">
      <h3>LLM Triage Summary</h3>
      <pre id="llmSummary" style="white-space: pre-wrap; line-height: 1.4;">Loading...</pre>
    </div>

    <!-- Free sections (21-stage pipeline data) -->
    <div class="panel">
      <h3>Additional Context (Free)</h3>

      <div class="section-header" onclick="toggleSection('rawData')">
        ▶ Raw Artifact Data
      </div>
      <div id="rawData" class="section-body"></div>

      <div class="section-header" onclick="toggleSection('pipelineResults')">
        ▶ 21-Stage Pipeline Results
      </div>
      <div id="pipelineResults" class="section-body"></div>

      <div class="section-header" onclick="toggleSection('mitreMapping')">
        ▶ MITRE ATT&CK Mapping
      </div>
      <div id="mitreMapping" class="section-body"></div>

      <div class="section-header" onclick="toggleSection('graphCorr')">
        ▶ Graph Correlation
      </div>
      <div id="graphCorr" class="section-body"></div>
    </div>

    <!-- Paid AI insights (on-demand) -->
    <div class="panel">
      <h3>AI-Powered Insights (On-Demand)</h3>

      <div class="ai-insight-btn">
        <span>▶ Generate Detailed DREAD Scenarios</span>
        <button class="btn" onclick="generateInsight('dread')">
          <span class="cost-badge">$0.001</span> Generate
        </button>
      </div>
      <div id="insight-dread" style="display:none; margin-top:8px;"></div>

      <div class="ai-insight-btn">
        <span>▶ Generate Collection Playbook for Missing Logs</span>
        <button class="btn" onclick="generateInsight('playbook')">
          <span class="cost-badge">$0.0008</span> Generate
        </button>
      </div>
      <div id="insight-playbook" style="display:none; margin-top:8px;"></div>

      <div class="ai-insight-btn">
        <span>▶ Generate Lateral Movement Hunt Query</span>
        <button class="btn" onclick="generateInsight('hunt')">
          <span class="cost-badge">$0.0008</span> Generate
        </button>
      </div>
      <div id="insight-hunt" style="display:none; margin-top:8px;"></div>

      <div class="ai-insight-btn">
        <span>▶ Generate Executive Summary (CISO)</span>
        <button class="btn" onclick="generateInsight('executive')">
          <span class="cost-badge">$0.0005</span> Generate
        </button>
      </div>
      <div id="insight-executive" style="display:none; margin-top:8px;"></div>

      <div style="margin-top:12px; font-size:12px; color:var(--text-muted);">
        Running cost for this row: <span id="runningCost">$0.003</span>
      </div>
    </div>

    <!-- Analyst notes -->
    <div class="panel">
      <h3>Analyst Notes</h3>
      <textarea id="analystNotes" class="review-note" placeholder="Document your investigation findings..."></textarea>
      <div style="margin-top:8px; font-size:12px; color:var(--text-muted);">
        Analyst: <span id="analystUser">unknown</span> |
        Timestamp: <span id="timestamp">...</span>
      </div>
      <div style="margin-top:12px; display:flex; gap:8px;">
        <button class="btn btn-primary" onclick="saveNotes()">Save Notes</button>
        <button class="btn" onclick="markEscalated()">Mark as Escalated</button>
        <button class="btn" onclick="markFalsePositive()">Mark as False Positive</button>
        <button class="btn" onclick="exportPDF()">Export to PDF</button>
        <button class="btn" onclick="copyTriageSummary()">Copy Triage Summary</button>
      </div>
    </div>
  </div>

  <script>
    // Load row data from localStorage
    var rowIndex = parseInt(localStorage.getItem('csv_deep_row') || '0', 10);
    var allRows = JSON.parse(localStorage.getItem('csv_last_results') || '[]');
    var row = allRows[rowIndex] || {};
    var runningCost = row._llm_cost || 0.003;

    // Initialize page
    document.getElementById('rowTitle').textContent = 'Deep Dive - Row ' + rowIndex + ': ' + (row.process_name || 'unknown');
    document.getElementById('llmSummary').textContent = row.llm_summary || 'No LLM summary generated yet.';
    document.getElementById('timestamp').textContent = new Date().toISOString();
    document.getElementById('runningCost').textContent = '$' + runningCost.toFixed(4);

    // Load raw data section
    document.getElementById('rawData').innerHTML =
      '<pre style="font-size:12px;">' + JSON.stringify(row, null, 2) + '</pre>';

    // Load 21-stage pipeline results
    if (row._pipeline_stages) {
      var stagesHTML = row._pipeline_stages.map(function(stage){
        return '<div><strong>Stage '+stage.idx+':</strong> '+stage.name+' - '+stage.status+'</div>';
      }).join('');
      document.getElementById('pipelineResults').innerHTML = stagesHTML;
    }

    // Toggle section visibility
    function toggleSection(id){
      var el = document.getElementById(id);
      if (el) {
        el.classList.toggle('expanded');
      }
    }

    // Generate AI insight (on-demand LLM call)
    async function generateInsight(type){
      var costs = { dread: 0.001, playbook: 0.0008, hunt: 0.0008, executive: 0.0005 };
      var cost = costs[type] || 0.001;

      if (!confirm('This will call the LLM and cost $' + cost + '. Continue?')) return;

      var targetDiv = document.getElementById('insight-' + type);
      targetDiv.style.display = 'block';
      targetDiv.textContent = 'Generating...';

      try {
        var resp = await fetch('/api/v1/assessments/generate_insight', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...authHeaders() },
          body: JSON.stringify({ row_index: rowIndex, insight_type: type })
        });

        if (!resp.ok) throw new Error('Failed to generate insight');

        var result = await resp.json();
        targetDiv.innerHTML = '<pre style="white-space:pre-wrap;">' + result.insight + '</pre>';

        // Update running cost
        runningCost += cost;
        document.getElementById('runningCost').textContent = '$' + runningCost.toFixed(4);
      } catch(e) {
        targetDiv.textContent = 'Error: ' + e.message;
      }
    }

    // Save analyst notes
    function saveNotes(){
      var notes = document.getElementById('analystNotes').value;
      // TODO: POST to backend
      alert('Notes saved (TODO: implement backend)');
    }

    // Placeholder functions
    function markEscalated(){ alert('TODO: Mark as escalated'); }
    function markFalsePositive(){ alert('TODO: Mark as false positive'); }
    function exportPDF(){ alert('TODO: Export to PDF'); }
    function copyTriageSummary(){
      var summary = document.getElementById('llmSummary').textContent;
      navigator.clipboard.writeText(summary).then(function(){
        alert('Triage summary copied to clipboard');
      });
    }
  </script>
</body>
</html>
```

---

## 💰 Cost Tracking

### External API (OpenAI, Anthropic, etc.)

#### Track: Tokens + Cost + Running Total

```python
class ExternalLLMCostTracker:
    def __init__(self):
        self.calls = []
        self.total_cost = 0.0

    def track_call(self, row_index, model, input_tokens, output_tokens, cost):
        """
        Track a single LLM API call
        """
        self.calls.append({
            'timestamp': datetime.utcnow().isoformat(),
            'row_index': row_index,
            'model': model,
            'input_tokens': input_tokens,
            'output_tokens': output_tokens,
            'cost': cost
        })
        self.total_cost += cost

    def get_summary(self):
        """
        Get cost summary
        """
        model_breakdown = {}
        for call in self.calls:
            model = call['model']
            if model not in model_breakdown:
                model_breakdown[model] = {'calls': 0, 'cost': 0.0}
            model_breakdown[model]['calls'] += 1
            model_breakdown[model]['cost'] += call['cost']

        return {
            'total_calls': len(self.calls),
            'total_cost': round(self.total_cost, 4),
            'avg_cost_per_call': round(self.total_cost / len(self.calls), 5) if self.calls else 0,
            'models': model_breakdown
        }

    def export_csv(self, filepath):
        """
        Export cost tracking to CSV for audit
        """
        import csv
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['timestamp', 'row_index', 'model', 'input_tokens', 'output_tokens', 'cost'])
            writer.writeheader()
            writer.writerows(self.calls)
```

#### Display in UI
```html
<div class="panel" id="costTrackerPanel" style="display:none;">
  <h3>💰 LLM Cost Tracker (External API)</h3>
  <div id="costSummary"></div>
</div>

<script>
function renderCostTracker(summary){
  var html = '<div style="font-size:13px; line-height:1.6;">';
  html += '<p><strong>Total API Calls:</strong> ' + summary.total_calls + '</p>';
  html += '<p><strong>Total Cost:</strong> $' + summary.total_cost.toFixed(4) + '</p>';
  html += '<p><strong>Avg Cost/Call:</strong> $' + summary.avg_cost_per_call.toFixed(5) + '</p>';
  html += '<p><strong>Breakdown by Model:</strong></p>';
  html += '<ul>';
  for (var model in summary.models) {
    var m = summary.models[model];
    html += '<li>' + model + ': ' + m.calls + ' calls, $' + m.cost.toFixed(4) + '</li>';
  }
  html += '</ul>';
  html += '</div>';

  document.getElementById('costSummary').innerHTML = html;
  document.getElementById('costTrackerPanel').style.display = 'block';
}
</script>
```

---

### Local GPU (Ollama, vLLM, etc.)

#### Track: Calls + GPU Time + Tokens (No $$$ Assigned)

```python
class LocalLLMTracker:
    def __init__(self):
        self.calls = []

    def track_call(self, row_index, model, input_tokens, output_tokens, gpu_time_ms):
        """
        Track a local GPU LLM call (no cost)
        """
        self.calls.append({
            'timestamp': datetime.utcnow().isoformat(),
            'row_index': row_index,
            'model': model,
            'input_tokens': input_tokens,
            'output_tokens': output_tokens,
            'gpu_time_ms': gpu_time_ms,
            'cost': 0.0  # Local = free (no token cost)
        })

    def get_summary(self):
        """
        Get usage summary (no cost)
        """
        total_gpu_time = sum(c['gpu_time_ms'] for c in self.calls)
        avg_tokens = sum(c['input_tokens'] + c['output_tokens'] for c in self.calls) / len(self.calls) if self.calls else 0

        return {
            'total_calls': len(self.calls),
            'total_gpu_time_ms': total_gpu_time,
            'total_gpu_time_sec': round(total_gpu_time / 1000, 2),
            'avg_tokens_per_call': round(avg_tokens, 0),
            'models': list(set(c['model'] for c in self.calls))
        }
```

#### Display in UI (No $$$ Figure)
```html
<div class="panel" id="localGPUTrackerPanel" style="display:none;">
  <h3>🖥️ Local LLM Usage (Ollama/vLLM)</h3>
  <div id="localGPUSummary"></div>
  <div style="margin-top:12px; padding:8px; background:rgba(255,255,255,0.02); border-radius:6px; font-size:12px; color:var(--text-muted);">
    💡 <strong>Note:</strong> Local GPU usage has no token cost. Electricity and hardware
    costs are subjective and not tracked here. If you want to estimate costs,
    track GPU time (seconds) and apply your own cost assumptions.
  </div>
</div>

<script>
function renderLocalGPUTracker(summary){
  var html = '<div style="font-size:13px; line-height:1.6;">';
  html += '<p><strong>Total Calls:</strong> ' + summary.total_calls + '</p>';
  html += '<p><strong>Model(s):</strong> ' + summary.models.join(', ') + '</p>';
  html += '<p><strong>Total GPU Time:</strong> ' + summary.total_gpu_time_sec + ' seconds</p>';
  html += '<p><strong>Avg Tokens/Call:</strong> ' + summary.avg_tokens_per_call + '</p>';
  html += '</div>';

  document.getElementById('localGPUSummary').innerHTML = html;
  document.getElementById('localGPUTrackerPanel').style.display = 'block';
}
</script>
```

#### Optional: Let User Input Their Own Cost Assumptions
```html
<div style="margin-top:12px;">
  <label style="display:inline-flex; align-items:center; gap:8px;">
    <span class="small">Your GPU cost (optional):</span>
    <input type="number" id="localGPUCostPerHour" placeholder="e.g., 0.50" step="0.01" style="width:100px;" />
    <span class="small">USD/hour</span>
  </label>
  <div id="estimatedCost" style="margin-top:6px; font-size:12px; color:var(--text-muted);"></div>
</div>

<script>
document.getElementById('localGPUCostPerHour').addEventListener('input', function(){
  var costPerHour = parseFloat(this.value) || 0;
  var gpuTimeSec = 45; // from summary.total_gpu_time_sec
  var estimatedCost = (gpuTimeSec / 3600) * costPerHour;
  document.getElementById('estimatedCost').textContent =
    'Estimated cost: $' + estimatedCost.toFixed(4) + ' (' + gpuTimeSec + 's × $' + costPerHour + '/hr ÷ 3600s)';
});
</script>
```

---

## 🚀 GitHub Copilot Implementation Prompts

### Prompt 1: Update `auto_llm.py` - 30-45 Line Summary

```
Update src/analysis/auto_llm.py to generate 30-45 line LLM summaries for fast triage.

Requirements:
1. Modify build_llm_prompt() to use this template:

📌 WHAT IS IT? (2-3 lines)
[Brief context: what process, what behavior, what attack pattern]

💥 EXPLOITABILITY (3-4 lines)
Attacker can use this to:
• [Damage scenario 1]
• [Damage scenario 2]
• [Damage scenario 3]

⚡ WHAT TO DO? (3-4 lines)
[Immediate action - 3 steps max, be specific]

📋 CONCISE PLAYBOOK (5-8 lines)
Step 1: [PowerShell/CLI command]
Step 2: [PowerShell/CLI command]
...

⚠️ MISSING LOGS (3-5 lines - IF suspected):
[Only if 21-stage pipeline flagged correlation/attack patterns]
• [Missing log 1] - would confirm/deny [specific suspicion]

2. Add should_include_missing_logs() function:
   - Check correlation_score > 0.5
   - Check attack_patterns for ['c2', 'lateral_movement', 'persistence']
   - Check llm_confidence < 0.8
   - Return bool

3. Add sanitize_llm_summary() to enforce 30-45 line limit

4. Add metadata to row after LLM call:
   row['_llm_processed'] = True
   row['_llm_timestamp'] = datetime.utcnow().isoformat()
   row['_llm_model'] = model_name
   row['_llm_cost'] = cost (or 0 for local)
```

### Prompt 2: Update `deep_analyze_endpoints.py` - Prioritization & Batch Processing

```
Update src/api/deep_analyze_endpoints.py to add prioritized LLM processing.

Add new function prioritize_rows_for_llm(rows, limit=25):
1. Filter suspicious rows (verdict in ['SUSPICIOUS', 'CRITICAL', 'HIGH'])
2. Sort by DREAD score (descending)
3. Return top N rows

Add new endpoint /api/v1/assessments/generate_llm_summaries:
POST body: { row_indices: [0, 1, 2, ...], limit: 25 }
Response: { rows: [...with llm_summary], count: 25 }

Logic:
1. Filter rows that don't have _llm_processed flag
2. Prioritize by DREAD
3. Take top 'limit' rows
4. Generate summaries (call auto_llm.py)
5. Mark rows with _llm_processed = True
6. Return updated rows

Add batch processing with progress callback:
- Process in batches of 20
- Yield progress: {"progress": 40, "total": 100}
```

### Prompt 3: Update `csv_analyzer.html` - UI for Prioritization

```
Update frontend/static/csv_analyzer.html to add LLM summary controls.

Add dropdown after "Deep Analyze Options":
<label>
  LLM Summaries:
  <select id="llmLimit">
    <option value="25">Top 25 (DREAD sorted)</option>
    <option value="50">Top 50</option>
    <option value="75">Top 75</option>
    <option value="0">All suspicious rows</option>
  </select>
</label>
<span id="llmCostEstimate">Est. cost: $0.075</span>

Add button after table:
<button id="btnGenerateMore" style="display:none;">
  Generate Next 25 LLM Summaries
</button>

Update table to show ✅/⏸️ icon in first column:
- ✅ if row._llm_processed
- ⏸️ if pending
- Tooltip: "LLM summary generated at [timestamp]" or "No LLM summary yet"

Wire btnGenerateMore click handler:
1. Find pending rows (filter !_llm_processed)
2. POST to /api/v1/assessments/generate_llm_summaries
3. Update LAST_RESULTS with returned rows
4. Re-render table
```

### Prompt 4: Create `csv_deep_analysis.html` - "Investigate Further" Tab

```
Create new file frontend/static/csv_deep_analysis.html for deep dive tab.

Structure:
1. Load row data from localStorage.getItem('csv_deep_row')
2. Display 30-45 line LLM summary (cached, always visible)
3. Add collapsible sections (free):
   - Raw Artifact Data
   - 21-Stage Pipeline Results
   - MITRE Mapping
   - Graph Correlation
4. Add AI-powered insights (on-demand, costs tokens):
   - Generate Detailed DREAD Scenarios [$0.001]
   - Generate Collection Playbook [$0.0008]
   - Generate Hunt Query [$0.0008]
   - Generate Executive Summary [$0.0005]
5. Show running cost: "Running cost for this row: $0.003"
6. Add analyst notes textarea
7. Add buttons: Save, Escalate, False Positive, Export PDF

Use progressive disclosure:
- Free sections: Click to expand (no LLM call)
- Paid insights: Click "Generate" button → POST to /api/v1/assessments/generate_insight

Track cost per insight, update running total
```

### Prompt 5: Add Cost Tracking Classes

```
Create new file src/analysis/cost_tracker.py

Add two classes:
1. ExternalLLMCostTracker:
   - track_call(row_index, model, input_tokens, output_tokens, cost)
   - get_summary() → {total_calls, total_cost, avg_cost_per_call, models: {...}}
   - export_csv(filepath)

2. LocalLLMTracker:
   - track_call(row_index, model, input_tokens, output_tokens, gpu_time_ms)
   - get_summary() → {total_calls, total_gpu_time_sec, avg_tokens_per_call, models: []}
   - NOTE: cost always 0 for local

Integrate with auto_llm.py:
- After LLM call, check if external API or local
- If external: ExternalLLMCostTracker.track_call(...)
- If local (Ollama): LocalLLMTracker.track_call(...)

Add endpoint /api/v1/metrics/llm_costs:
GET response: {
  external: { total_calls: 25, total_cost: 0.075, ... },
  local: { total_calls: 50, total_gpu_time_sec: 120, ... }
}
```

---

## ✅ Testing & Validation

### Test Scenario 1: Prioritization
1. Upload CSV with 550 rows
2. 150 flagged suspicious
3. Select "Top 25" from dropdown
4. Verify:
   - Only 25 LLM calls made
   - Cost = $0.075
   - Rows sorted by DREAD (high to low)
   - ✅ icon appears on 25 rows
   - "Generate More" button visible

### Test Scenario 2: Don't Re-Process
1. Generate top 25 summaries
2. Click "Generate More" (next 25)
3. Verify:
   - First 25 rows skipped (already have ✅)
   - Rows 26-50 processed
   - Cost += $0.075 (not duplicate)

### Test Scenario 3: Missing Logs - Conditional
1. Row with high correlation (0.8) → Should show "Missing Logs" section
2. Row with low correlation (0.2), signed binary → Should NOT show "Missing Logs"
3. Verify LLM output matches expectation

### Test Scenario 4: "Investigate Further" Tab
1. Click row with LLM summary
2. Click "Investigate Further"
3. Verify new tab opens with:
   - 30-45 line summary (cached)
   - Free sections (collapsible)
   - AI insights (buttons, not generated yet)
   - Running cost = $0.003
4. Click "Generate Collection Playbook"
5. Verify:
   - LLM call made
   - Output appears
   - Running cost += $0.0008 → $0.0038

### Test Scenario 5: Cost Tracking
1. Generate 25 summaries with GPT-4o
2. Generate 10 summaries with Ollama
3. Check /api/v1/metrics/llm_costs
4. Verify:
   - External: 25 calls, $0.075
   - Local: 10 calls, ~30s GPU time, $0

---

## 📝 Next Steps

1. ✅ Review this implementation guide
2. ⏭️ Use GitHub Copilot prompts to implement
3. ⏭️ Test with 10 real CSV rows
4. ⏭️ Validate no hallucinations in LLM output
5. ⏭️ Get CEO approval: "Is this what you wanted?"
6. ⏭️ Deploy to production

---

**END OF IMPLEMENTATION GUIDE**
