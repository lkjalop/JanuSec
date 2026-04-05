# Complete User Flow: LLM Summaries → Reports → Sending

**Date:** 2025-01-22
**Purpose:** Step-by-step guide for generating, viewing, and sending LLM-powered security reports

---

## 📋 TABLE OF CONTENTS

1. [Quick Overview](#quick-overview)
2. [User Flow Diagram](#user-flow-diagram)
3. [Step-by-Step Walkthrough](#step-by-step-walkthrough)
4. [Testing Procedures](#testing-procedures)
5. [Troubleshooting](#troubleshooting)

---

## 🎯 QUICK OVERVIEW

### The Complete Flow (5 Stages)

```
Stage 1: Upload CSV
   ↓
Stage 2: View Analysis Results (Pipeline Processing)
   ↓
Stage 3: Generate LLM Summaries (Tier 1 or Tier 2)
   ↓
Stage 4: Generate Report (HTML/PDF)
   ↓
Stage 5: Send/Export Report (Email, Slack, Download)
```

### Time Estimates

| Stage | Time | Cost |
|-------|------|------|
| Upload CSV (10 rows) | 5 sec | Free |
| Pipeline Processing | 10-30 sec | Free |
| LLM Tier 1 (all 10 rows) | 10-20 sec | $0.005 |
| LLM Tier 2 (top 5 rows) | 15-45 sec | $0.015 |
| Generate Report | 2-5 sec | Free |
| Send Report | 1-2 sec | Free |
| **TOTAL** | **1-2 min** | **$0.005-$0.02** |

---

## 🗺️ USER FLOW DIAGRAM

```
┌─────────────────────────────────────────────────────────────────┐
│                     STAGE 1: UPLOAD CSV                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Browser: http://localhost:8000/static/csv_analyzer.html       │
│                                                                 │
│  [Choose File] → Select: tests/test_data/option_c_demo.csv     │
│                                                                 │
│  [Analyze CSV] ← Click                                          │
│                                                                 │
│  Backend: POST /api/v1/csv/analyze                              │
│           - Runs 21-stage pipeline                              │
│           - Calculates DREAD, MITRE, factors                    │
│           - Returns analyzed rows (NO LLM yet)                  │
│                                                                 │
└────────────────────────┬────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────────┐
│              STAGE 2: VIEW ANALYSIS RESULTS                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  UI Shows Table:                                                │
│  ┌─────────────┬──────────┬─────────┬──────────────┬─────────┐ │
│  │ Process     │ Host     │ Verdict │ DREAD Score  │ Actions │ │
│  ├─────────────┼──────────┼─────────┼──────────────┼─────────┤ │
│  │powershell   │WORKST-42 │Suspicio │ 8.5          │[Investi]│ │
│  │mimikatz.exe │WORKST-42 │Malicio  │ 9.2          │[Investi]│ │
│  │svchost.exe  │SERVER-87 │Suspicio │ 6.8          │[Investi]│ │
│  └─────────────┴──────────┴─────────┴──────────────┴─────────┘ │
│                                                                 │
│  Each row has:                                                  │
│  - Verdict (from pipeline)                                      │
│  - DREAD score (from pipeline)                                  │
│  - Factors (from pipeline)                                      │
│  - NO LLM summary yet (not generated until clicked)             │
│                                                                 │
└────────────────────────┬────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────────┐
│         STAGE 3A: TIER 1 SUMMARY (Optional Batch)               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Option A: Generate Tier 1 for ALL rows at once                │
│                                                                 │
│  [Generate Summaries for All Rows] ← Click                      │
│                                                                 │
│  Backend: POST /api/v1/csv/batch_summarize                      │
│           {                                                     │
│             "rows": [...],  // All 10 rows                      │
│             "tier": "tier1"                                     │
│           }                                                     │
│                                                                 │
│  Processing:                                                    │
│  - Loops through each row                                       │
│  - Calls AutoLLM.summarize_row(row, tier='tier1')              │
│  - Generates 30-45 line summary per row                         │
│  - Cost: 10 rows × $0.0005 = $0.005                            │
│                                                                 │
│  Result: Table updates with "Summary" column:                   │
│  ┌─────────────┬──────────┬─────────┬──────────────────────┐    │
│  │ Process     │ Verdict  │ DREAD   │ Tier 1 Summary       │    │
│  ├─────────────┼──────────┼─────────┼──────────────────────┤    │
│  │powershell   │Suspicio  │ 8.5     │WHAT: PowerShell with │    │
│  │             │          │         │process_injection...  │    │
│  │             │          │         │[View Full]           │    │
│  └─────────────┴──────────┴─────────┴──────────────────────┘    │
│                                                                 │
└────────────────────────┬────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────────┐
│      STAGE 3B: TIER 2 SUMMARY (Investigate Further)            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  User clicks [Investigate Further] on suspicious row           │
│                                                                 │
│  New tab opens: csv_deep_analysis.html?row_id=2                │
│                                                                 │
│  Page loads and auto-triggers:                                 │
│                                                                 │
│  1. Tier 2 LLM Summary Generation                              │
│     Backend: POST /api/v1/llm/summarize                         │
│              {                                                  │
│                "row": {...},                                    │
│                "tier": "tier2",                                 │
│                "context": {...}                                 │
│              }                                                  │
│                                                                 │
│     Processing:                                                 │
│     - Detects domain (network vs endpoint)                      │
│     - Queries historical incidents                              │
│     - Enriches correlation context                              │
│     - Generates 60-147 line deep analysis prompt                │
│     - Cost: $0.003                                              │
│                                                                 │
│  2. HopGraph Attack Reconstruction                              │
│     Backend: POST /api/v1/graph/attack_reconstruction           │
│              {                                                  │
│                "row": {...},                                    │
│                "max_hops": 3                                    │
│              }                                                  │
│                                                                 │
│     Returns:                                                    │
│     - Attack chain narrative                                    │
│     - Timeline (3 events)                                       │
│     - Node list with risk scores                                │
│                                                                 │
│  3. AI Insights (On-Demand Buttons)                             │
│     User clicks: [Generate DREAD Scenarios]                     │
│                                                                 │
│     Backend: POST /api/v1/insights/generate                     │
│              {                                                  │
│                "row": {...},                                    │
│                "insight_type": "dread"                          │
│              }                                                  │
│                                                                 │
│     Returns: 3 DREAD scenarios with scoring                     │
│     Cost: $0.001                                                │
│                                                                 │
│     User can also click:                                        │
│     - [Generate Playbook] → Investigation steps (FREE)          │
│     - [Generate Hunt Query] → KQL/SPL/Sigma ($0.0008)          │
│     - [Generate Executive Summary] → 5 sentences ($0.0005)      │
│                                                                 │
└────────────────────────┬────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────────┐
│              STAGE 4: GENERATE REPORT                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Option A: Generate from CSV Analyzer (Batch)                  │
│                                                                 │
│    Button: [Generate Report for All Rows]                      │
│                                                                 │
│    Backend: POST /api/v1/report/generate                        │
│             {                                                   │
│               "rows": [...],  // All 10 analyzed rows           │
│               "summary": {                                      │
│                 "total": 10,                                    │
│                 "malicious": 2,                                 │
│                 "suspicious": 5,                                │
│                 "benign": 3                                     │
│               },                                                │
│               "format": "html",  // or "pdf"                    │
│               "include_model": true  // Add LLM exec summary    │
│             }                                                   │
│                                                                 │
│    Processing:                                                  │
│    - Calls build_report_html(payload)                           │
│    - If include_model=true:                                     │
│      - Generates executive summary via LLM                      │
│      - Adds to top of report                                    │
│    - Returns HTML or PDF                                        │
│                                                                 │
│  Option B: Generate from Deep Analysis Page (Single Row)       │
│                                                                 │
│    Button: [Export This Investigation]                         │
│                                                                 │
│    Backend: POST /api/v1/report/generate_single                 │
│             {                                                   │
│               "row": {...},                                     │
│               "tier2_summary": "...",                           │
│               "ai_insights": {...},                             │
│               "hopgraph": {...}                                 │
│             }                                                   │
│                                                                 │
│  Option C: Prioritized Report (Smart Batching)                 │
│                                                                 │
│    Button: [Generate Prioritized Report]                       │
│                                                                 │
│    Backend: POST /api/v1/report/generate_prioritized            │
│             {                                                   │
│               "rows": [...],  // All 135 rows                   │
│               "persona": "soc_analyst",                         │
│               "max_high_priority": 10,                          │
│               "max_medium_priority": 15,                        │
│               "include_llm": true                               │
│             }                                                   │
│                                                                 │
│    Processing:                                                  │
│    - Calculates priority scores                                 │
│    - Top 10: Tier 2 deep analysis                              │
│    - Next 15: Tier 1 fast triage                               │
│    - Bottom 110: Pipeline only                                 │
│    - Cost: $0.0375 (vs $0.40 for all rows)                     │
│                                                                 │
└────────────────────────┬────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────────┐
│           STAGE 5: SEND/EXPORT REPORT                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Report generated successfully. Now choose delivery method:    │
│                                                                 │
│  ┌───────────────────────────────────────────────────────┐     │
│  │  Report Generated Successfully!                       │     │
│  │                                                       │     │
│  │  [Download HTML]  [Download PDF]  [Send via Email]   │     │
│  │                                                       │     │
│  │  [Send to Slack]  [Send to Teams]  [Copy Link]       │     │
│  └───────────────────────────────────────────────────────┘     │
│                                                                 │
│  Option A: Download HTML                                        │
│    - Browser downloads report.html                              │
│    - Can open in any browser                                    │
│    - Can share via file attachment                              │
│                                                                 │
│  Option B: Download PDF                                         │
│    - Backend converts HTML → PDF (WeasyPrint)                   │
│    - Downloads report.pdf                                       │
│    - Professional format for stakeholders                       │
│                                                                 │
│  Option C: Send via Email (Not yet implemented)                │
│    Modal opens:                                                 │
│    ┌───────────────────────────────────────┐                   │
│    │ Send Report via Email                 │                   │
│    │                                       │                   │
│    │ To: [soc-team@company.com          ] │                   │
│    │ CC: [                              ] │                   │
│    │ Subject: [Security Alert Report...  ] │                   │
│    │                                       │                   │
│    │ Message:                              │                   │
│    │ [Automated security analysis...     ] │                   │
│    │                                       │                   │
│    │ Attach: [✓] HTML  [✓] PDF            │                   │
│    │                                       │                   │
│    │        [Cancel]  [Send Email]         │                   │
│    └───────────────────────────────────────┘                   │
│                                                                 │
│    Backend: POST /api/v1/report/send_email                      │
│             {                                                   │
│               "report_id": "rpt_20250122_001",                  │
│               "to": ["soc-team@company.com"],                   │
│               "cc": [],                                         │
│               "subject": "Security Alert Report",               │
│               "message": "See attached...",                     │
│               "attachments": ["html", "pdf"]                    │
│             }                                                   │
│                                                                 │
│  Option D: Send to Slack (Existing Implementation)             │
│    Modal opens:                                                 │
│    ┌───────────────────────────────────────┐                   │
│    │ Send Report to Slack                  │                   │
│    │                                       │                   │
│    │ Channel: [#security-alerts         ▼] │                   │
│    │                                       │                   │
│    │ Preview:                              │                   │
│    │ ┌───────────────────────────────────┐ │                   │
│    │ │ 🚨 Security Alert Report          │ │                   │
│    │ │                                   │ │                   │
│    │ │ Total Alerts: 10                  │ │                   │
│    │ │ • Malicious: 2                    │ │                   │
│    │ │ • Suspicious: 5                   │ │                   │
│    │ │ • Benign: 3                       │ │                   │
│    │ │                                   │ │                   │
│    │ │ Top Threats:                      │ │                   │
│    │ │ 1. mimikatz.exe (DREAD: 9.2)      │ │                   │
│    │ │ 2. powershell.exe (DREAD: 8.5)    │ │                   │
│    │ │                                   │ │                   │
│    │ │ [View Full Report]                │ │                   │
│    │ └───────────────────────────────────┘ │                   │
│    │                                       │                   │
│    │        [Cancel]  [Send to Slack]      │                   │
│    └───────────────────────────────────────┘                   │
│                                                                 │
│    Backend: POST /api/v1/integrations/slack/send_report         │
│             {                                                   │
│               "report_id": "rpt_20250122_001",                  │
│               "channel": "#security-alerts",                    │
│               "summary": {                                      │
│                 "total": 10,                                    │
│                 "malicious": 2,                                 │
│                 "suspicious": 5,                                │
│                 "benign": 3                                     │
│               },                                                │
│               "top_threats": [...]                              │
│             }                                                   │
│                                                                 │
│    Processing:                                                  │
│    - Formats Slack message (blocks API)                         │
│    - Uploads HTML/PDF as file attachment                        │
│    - Posts to specified channel                                 │
│    - Returns success/failure                                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📝 STEP-BY-STEP WALKTHROUGH

### STAGE 1: Upload CSV (30 seconds)

**Step 1.1: Start Platform**
```bash
cd D:\AI\Threat_thy_sniffer
python run_platform.py

# Wait for: "Uvicorn running on http://0.0.0.0:8000"
```

**Step 1.2: Open CSV Analyzer**
```
Browser: http://localhost:8000/static/csv_analyzer.html
```

**Step 1.3: Select Test CSV**
```
[Choose File] → Navigate to:
D:\AI\Threat_thy_sniffer\tests\test_data\option_c_demo.csv

[Analyze CSV] ← Click
```

**Step 1.4: Wait for Processing**
```
Progress bar shows:
[████████████████████] 100%

Status: "Analysis complete. 10 rows processed."
```

**What Happens Behind the Scenes:**
```javascript
// Frontend: frontend/static/csv_analyzer.html
async function analyzeCSV() {
  const formData = new FormData();
  formData.append('file', fileInput.files[0]);

  const response = await fetch('/api/v1/csv/analyze', {
    method: 'POST',
    body: formData
  });

  const result = await response.json();
  // result.rows = [...] // 10 analyzed rows with DREAD, MITRE, factors
  displayResults(result.rows);
}
```

```python
# Backend: src/api/csv_endpoints.py
@router.post('/api/v1/csv/analyze')
async def analyze_csv(file: UploadFile):
    # Read CSV
    df = pd.read_csv(file.file)

    # Run 21-stage pipeline on each row
    analyzed_rows = []
    for _, row in df.iterrows():
        enriched = await run_pipeline(row.to_dict())
        # enriched now has: verdict, dread_score, mitre_tags, factors
        analyzed_rows.append(enriched)

    return {"rows": analyzed_rows, "total": len(analyzed_rows)}
```

**Expected Result:**
- Table displays 10 rows
- Each row shows: process_name, host, verdict, DREAD score
- No LLM summaries yet (blank "Summary" column)
- [Investigate Further] button on each row

---

### STAGE 2: View Analysis Results (Browse the table)

**What You See:**

```
┌──────────────┬─────────────┬────────────┬──────────┬─────────────┬────────────┐
│ Process Name │ Host        │ Verdict    │ DREAD    │ Factors     │ Actions    │
├──────────────┼─────────────┼────────────┼──────────┼─────────────┼────────────┤
│ powershell   │ WORKST-42   │ Suspicious │ 8.5      │ process_in  │[Investi]   │
│              │             │            │          │ jection,    │            │
│              │             │            │          │ unsigned... │            │
├──────────────┼─────────────┼────────────┼──────────┼─────────────┼────────────┤
│ mimikatz.exe │ WORKST-42   │ Malicious  │ 9.2      │ credential  │[Investi]   │
│              │             │            │          │ _dumping... │            │
├──────────────┼─────────────┼────────────┼──────────┼─────────────┼────────────┤
│ svchost.exe  │ SERVER-87   │ Suspicious │ 6.8      │ suspicious  │[Investi]   │
│              │             │            │          │ _dns,       │            │
│              │             │            │          │ beaconing   │            │
└──────────────┴─────────────┴────────────┴──────────┴─────────────┴────────────┘
```

**Interactive Elements:**
- **Verdict badge**: Color-coded (red=malicious, yellow=suspicious, green=benign)
- **DREAD score**: Sortable column (click to sort high→low)
- **Factors**: Hover to see full list
- **[Investigate Further] button**: Click to open deep analysis

**No LLM Yet:**
- Notice: No summary text generated yet
- Pipeline data is free (DREAD, MITRE, factors already calculated)
- LLM summaries only generated when user requests them

---

### STAGE 3A: Generate Tier 1 Summaries (Optional Batch)

**When to Use:**
- You want a quick summary for ALL rows at once
- Budget-conscious (Tier 1 is $0.0005/row vs Tier 2 $0.003/row)
- Need fast triage across entire dataset

**Step 3A.1: Click Batch Summary Button**
```
Top of table: [Generate Summaries for All Rows]
```

**Step 3A.2: Modal Opens**
```
┌─────────────────────────────────────────────┐
│ Generate LLM Summaries                      │
│                                             │
│ Tier: [●] Tier 1 (Fast - 30-45 lines)      │
│       [ ] Tier 2 (Deep - 60-100 lines)      │
│                                             │
│ Rows to process: 10                         │
│ Estimated cost: $0.005                      │
│ Estimated time: 10-20 seconds               │
│                                             │
│        [Cancel]  [Generate Summaries]       │
└─────────────────────────────────────────────┘
```

**Step 3A.3: Processing**
```
Progress modal:
┌─────────────────────────────────────────────┐
│ Generating Summaries...                     │
│                                             │
│ [████████░░░░░░░░░░░░] 40% (4/10)          │
│                                             │
│ Currently processing: svchost.exe           │
│ Estimated remaining: 6 seconds              │
└─────────────────────────────────────────────┘
```

**Backend Processing:**
```python
# Backend: src/api/csv_endpoints.py
@router.post('/api/v1/csv/batch_summarize')
async def batch_summarize(request: Request):
    payload = await request.json()
    rows = payload.get('rows', [])
    tier = payload.get('tier', 'tier1')

    from src.analysis.auto_llm import AutoLLM
    llm = AutoLLM()

    summaries = []
    total_cost = 0.0

    for i, row in enumerate(rows):
        context = {'tier': tier}
        summary = llm.summarize_row(row, context)

        summaries.append({
            'row_index': i,
            'summary_text': summary.get('text', ''),
            'cost': 0.0005 if tier == 'tier1' else 0.003
        })

        total_cost += summaries[-1]['cost']

        # Yield progress (SSE - Server-Sent Events)
        yield json.dumps({
            'progress': (i + 1) / len(rows) * 100,
            'current_row': row.get('process_name'),
            'summaries': summaries
        })

    yield json.dumps({
        'complete': True,
        'summaries': summaries,
        'total_cost': total_cost
    })
```

**Step 3A.4: View Results**

Table updates with new "Summary" column:

```
┌──────────────┬────────────┬──────────────────────────────────────┐
│ Process Name │ DREAD      │ Tier 1 Summary                       │
├──────────────┼────────────┼──────────────────────────────────────┤
│ powershell   │ 8.5        │ WHAT IS IT? WHY SUSPICIOUS?          │
│              │            │ PowerShell execution with process    │
│              │            │ injection and unsigned binary.       │
│              │            │                                      │
│              │            │ EXPLOITABILITY                       │
│              │            │ High - Common attack vector for...   │
│              │            │                                      │
│              │            │ WHAT TO DO?                          │
│              │            │ 1. Isolate host immediately          │
│              │            │ 2. Dump memory for analysis          │
│              │            │                                      │
│              │            │ [View Full Summary] [Investigate]    │
└──────────────┴────────────┴──────────────────────────────────────┘
```

**Cost Tracking:**
```
Top right corner:
💰 LLM Cost This Session: $0.005 (10 rows × Tier 1)
```

---

### STAGE 3B: Generate Tier 2 Summary (Investigate Further)

**When to Use:**
- User wants deep investigation of specific suspicious artifact
- Need comprehensive analysis with historical context
- Want HopGraph attack chain visualization
- Need AI insights (DREAD scenarios, hunt queries, etc.)

**Step 3B.1: Click [Investigate Further]**
```
Click on any row's [Investigate Further] button
(Example: mimikatz.exe row with DREAD 9.2)
```

**Step 3B.2: Deep Analysis Page Opens**
```
New tab: http://localhost:8000/static/csv_deep_analysis.html?row_id=1
```

**Page Layout:**
```
┌─────────────────────────────────────────────────────────────────┐
│  ← Back to CSV Analyzer                    💰 Cost: $0.003      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  🔴 MALICIOUS ARTIFACT DETECTED                                 │
│                                                                 │
│  Process: mimikatz.exe                                          │
│  Host: WORKSTATION-042                                          │
│  User: admin                                                    │
│  SHA256: deadbeef12345678...                                    │
│                                                                 │
│  Verdict: MALICIOUS  │  DREAD: 9.2/10  │  Factors: 3            │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  📄 TIER 2 DEEP ANALYSIS (Auto-Generated)                       │
│                                                                 │
│  [Loading...] ← Shows spinner for 2-5 seconds                   │
│                                                                 │
│  Then populates with 60-147 line analysis:                      │
│                                                                 │
│  ─────────────────────────────────────────────────────────      │
│  FOR: THREAT HUNTER | FORENSIC ANALYST                          │
│  DOMAIN: ENDPOINT (Confidence: 0.92)                            │
│  ─────────────────────────────────────────────────────────      │
│                                                                 │
│  SECTION 1: WHAT IS IT? WHY SUSPICIOUS?                         │
│                                                                 │
│  This is mimikatz.exe, a well-known credential dumping tool    │
│  used to extract passwords, hashes, and Kerberos tickets from   │
│  memory. Detection factors:                                     │
│  • credential_dumping - Accessing LSASS process memory          │
│  • lsass_access - Reading sensitive security subsystem         │
│  • privilege_escalation - Attempting to gain SYSTEM access      │
│                                                                 │
│  SECTION 2: HISTORICAL CONTEXT ⚠️ CRITICAL!                     │
│                                                                 │
│  🚨 WARNING: Similar incident detected 7 days ago!              │
│                                                                 │
│  Previous Instance:                                             │
│  - Date: 2025-01-15                                             │
│  - Host: WORKSTATION-038 (different host, same network)        │
│  - Outcome: CONFIRMED_MALICIOUS                                 │
│  - Analyst Notes: "Part of APT29 campaign. Attackers used      │
│    Mimikatz to dump domain admin credentials, then moved       │
│    laterally to file server. Host reimaged, passwords reset."  │
│                                                                 │
│  ⚠️ RECOMMENDATION: This appears to be related attack activity. │
│     Assume lateral movement attempt. Isolate immediately.       │
│                                                                 │
│  SECTION 3: ATTACK SCENARIO & BUSINESS IMPACT                   │
│                                                                 │
│  Likely Attack Chain:                                           │
│  1. Initial Access: Phishing email or compromised credentials   │
│  2. Execution: Dropped mimikatz.exe to disk                     │
│  3. Credential Access: Dumped LSASS memory (current stage)      │
│  4. Lateral Movement: Use stolen creds to access other systems  │
│  5. Impact: Deploy ransomware or exfiltrate data                │
│                                                                 │
│  Business Impact:                                               │
│  - If successful: Full domain compromise                        │
│  - Potential data breach (PII, financial records)               │
│  - Estimated recovery cost: $50,000 - $200,000                  │
│  - Downtime: 3-7 days for incident response                     │
│                                                                 │
│  [... continues for 60-147 lines total ...]                     │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  🕸️ ATTACK CHAIN RECONSTRUCTION (HopGraph)                      │
│                                                                 │
│  [Loading attack graph...] ← Shows spinner for 1-2 seconds      │
│                                                                 │
│  Then displays:                                                 │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                                                         │   │
│  │  📊 3-Hop Attack Chain Detected                         │   │
│  │                                                         │   │
│  │  Timeline:                                              │   │
│  │  10:30 AM - explorer.exe spawned mimikatz.exe           │   │
│  │  10:31 AM - mimikatz.exe accessed lsass.exe             │   │
│  │  10:32 AM - Outbound SMB to 10.50.20.15 (file server)   │   │
│  │                                                         │   │
│  │  Attack Path Visualization:                             │   │
│  │                                                         │   │
│  │  [explorer.exe] ──spawned──> [mimikatz.exe]             │   │
│  │   PID: 1024                   PID: 5678                 │   │
│  │   Risk: 2/10                  Risk: 9/10                │   │
│  │                                    │                    │   │
│  │                                    │ accessed           │   │
│  │                                    ↓                    │   │
│  │                              [lsass.exe]                │   │
│  │                               PID: 688                  │   │
│  │                               Risk: 8/10                │   │
│  │                                    │                    │   │
│  │                                    │ lateral move       │   │
│  │                                    ↓                    │   │
│  │                          [10.50.20.15:445]              │   │
│  │                           FILE-SERVER-01                │   │
│  │                           Risk: 7/10                    │   │
│  │                                                         │   │
│  │  Correlation Explanation:                               │   │
│  │  This attack chain shows credential theft followed by   │   │
│  │  lateral movement. High confidence (0.87) that these    │   │
│  │  events are part of coordinated attack campaign.        │   │
│  │                                                         │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  🤖 AI-POWERED INSIGHTS (On-Demand)                             │
│                                                                 │
│  [Generate DREAD Scenarios] [Generate Playbook]                │
│  [Generate Hunt Query]      [Generate Executive Summary]       │
│                                                                 │
│  Cost per insight: DREAD ($0.001), Playbook (FREE),            │
│                    Hunt ($0.0008), Executive ($0.0005)          │
│                                                                 │
│  ─── Example: After clicking [Generate DREAD Scenarios] ───    │
│                                                                 │
│  💸 Cost: $0.001  │  Time: 2.3 seconds                          │
│                                                                 │
│  SCENARIO 1: Domain Admin Compromise                           │
│  Damage: 9 - Full domain takeover, all systems at risk         │
│  Reproducibility: 8 - Well-documented attack technique         │
│  Exploitability: 7 - Requires local admin but widely known     │
│  Affected Users: 10 - All 500 employees affected               │
│  Discoverability: 6 - Detected by EDR but may evade AV         │
│  Total DREAD Score: 8.0                                         │
│                                                                 │
│  SCENARIO 2: Ransomware Deployment                             │
│  [...]                                                          │
│                                                                 │
│  SCENARIO 3: Data Exfiltration                                 │
│  [...]                                                          │
│                                                                 │
│  ─── Example: After clicking [Generate Playbook] ───           │
│                                                                 │
│  💸 Cost: $0.00 (instant, no LLM)                               │
│                                                                 │
│  INVESTIGATION PLAYBOOK: mimikatz.exe                           │
│  Domain: ENDPOINT                                               │
│                                                                 │
│  STEP 1: Immediate Containment                                  │
│  • Isolate host from network immediately                        │
│    Command: netsh interface set interface "Ethernet" disabled  │
│                                                                 │
│  • Kill mimikatz process                                        │
│    Command: taskkill /F /PID 5678                               │
│                                                                 │
│  STEP 2: Evidence Collection                                    │
│  • Memory dump (CRITICAL - do this first!)                      │
│    Tool: KAPE or FTK Imager                                     │
│    Command: DumpIt.exe /O D:\Evidence\memory.dmp                │
│                                                                 │
│  • Collect event logs                                           │
│    Command: wevtutil epl Security D:\Evidence\Security.evtx    │
│    Command: wevtutil epl Sysmon D:\Evidence\Sysmon.evtx        │
│                                                                 │
│  • Registry persistence check                                   │
│    Tool: RegRipper                                              │
│    Keys: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run    │
│                                                                 │
│  STEP 3: Network Analysis                                       │
│  • Check for lateral movement                                   │
│    Command: netstat -ano | findstr ESTABLISHED                 │
│                                                                 │
│  • Review SMB connections                                       │
│    Log source: Event ID 4624, 4625, 4776                        │
│                                                                 │
│  [... continues with 5-8 more steps ...]                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Backend Processing (Auto-triggered on page load):**

```javascript
// Frontend: csv_deep_analysis.html
async function loadDeepAnalysis() {
  const rowId = new URLSearchParams(window.location.search).get('row_id');
  const row = sessionStorage.getItem(`row_${rowId}`);

  // 1. Generate Tier 2 Summary
  showSpinner('tier2-section');
  const tier2Response = await fetch('/api/v1/llm/summarize', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      row: JSON.parse(row),
      tier: 'tier2'
    })
  });
  const tier2Summary = await tier2Response.json();
  displayTier2Summary(tier2Summary.text);
  updateCost(0.003);

  // 2. Load HopGraph
  showSpinner('hopgraph-section');
  const hopgraphResponse = await fetch('/api/v1/graph/attack_reconstruction', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      row: JSON.parse(row),
      max_hops: 3
    })
  });
  const hopgraph = await hopgraphResponse.json();
  displayHopGraph(hopgraph);

  // 3. AI Insights buttons (wait for user to click)
  setupInsightButtons(row);
}
```

---

### STAGE 4: Generate Report

**Option A: Generate Report from CSV Analyzer (All Rows)**

**Step 4A.1: Click Report Button**
```
Bottom of CSV Analyzer page:
[Generate Report for All Rows]
```

**Step 4A.2: Report Options Modal**
```
┌─────────────────────────────────────────────────────┐
│ Generate Security Report                            │
│                                                     │
│ Format:                                             │
│ [●] HTML  [ ] PDF  [ ] JSON                         │
│                                                     │
│ Include:                                            │
│ [✓] Executive Summary (LLM-generated)               │
│ [✓] MITRE ATT&CK Coverage                           │
│ [✓] DREAD Distribution Chart                        │
│ [✓] Detailed Row Analysis                           │
│ [✓] Recommendations                                 │
│                                                     │
│ Persona:                                            │
│ [●] SOC Analyst  [ ] CISO  [ ] Security Engineer    │
│                                                     │
│ Rows to include: 10                                 │
│ Estimated cost: $0.01 (exec summary)                │
│                                                     │
│           [Cancel]  [Generate Report]               │
└─────────────────────────────────────────────────────┘
```

**Step 4A.3: Processing**
```
[████████████████████] Generating report...
```

**Step 4A.4: Report Opens in New Tab**
```
New tab: http://localhost:8000/api/v1/report/view?id=rpt_20250122_001
```

**Report Content:**
```html
┌────────────────────────────────────────────────────────────────┐
│  JANUSEC SECURITY PLATFORM - THREAT ANALYSIS REPORT            │
│  Generated: 2025-01-22 14:30:00                                │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  📊 EXECUTIVE SUMMARY                                          │
│  (LLM-Generated - Cost: $0.01)                                 │
│                                                                │
│  Analysis of 10 security artifacts revealed 2 confirmed       │
│  malicious threats and 5 suspicious activities requiring      │
│  investigation. Critical finding: mimikatz.exe detected on     │
│  WORKSTATION-042, indicating credential theft attempt.         │
│  Immediate action required to prevent lateral movement.        │
│  Estimated business impact if unmitigated: $50K-$200K.         │
│                                                                │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  📈 SUMMARY STATISTICS                                         │
│                                                                │
│  Total Artifacts Analyzed: 10                                  │
│  • Malicious: 2 (20%)                                          │
│  • Suspicious: 5 (50%)                                         │
│  • Benign: 3 (30%)                                             │
│                                                                │
│  Average DREAD Score: 7.2/10 (HIGH)                            │
│  Highest DREAD: 9.2 (mimikatz.exe)                             │
│                                                                │
│  MITRE ATT&CK Coverage:                                        │
│  • Credential Access: T1003 (3 instances)                      │
│  • Execution: T1059 (5 instances)                              │
│  • Defense Evasion: T1055 (2 instances)                        │
│                                                                │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  🔴 HIGH PRIORITY THREATS (Top 3)                              │
│                                                                │
│  1. mimikatz.exe (DREAD: 9.2) - MALICIOUS                      │
│     Host: WORKSTATION-042                                      │
│     Factors: credential_dumping, lsass_access                  │
│     Recommendation: Isolate host immediately, reset all domain │
│                     passwords, investigate for lateral movement│
│                                                                │
│  2. powershell.exe (DREAD: 8.5) - SUSPICIOUS                   │
│     Host: WORKSTATION-042 (same host!)                         │
│     Factors: process_injection, cmdline_obfuscation            │
│     Recommendation: Memory forensics, check for encoded payload│
│                                                                │
│  3. chrome.exe (DREAD: 7.8) - MALICIOUS                        │
│     Host: LAPTOP-055                                           │
│     Factors: data_exfiltration, c2_communication               │
│     Recommendation: Network capture, block C2 domain           │
│                                                                │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  📊 DREAD SCORE DISTRIBUTION                                   │
│                                                                │
│  10 │                         ██                               │
│   9 │                         ██  ██                           │
│   8 │                 ██      ██  ██                           │
│   7 │         ██      ██      ██  ██                           │
│   6 │         ██      ██      ██  ██  ██                       │
│   5 │         ██      ██      ██  ██  ██                       │
│     └─────────────────────────────────────────────────         │
│       Benign  Suspi  Suspi  Mali  Mali                         │
│                                                                │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  📋 DETAILED ANALYSIS (All 10 Rows)                            │
│                                                                │
│  [Click to expand each row for full Tier 1/Tier 2 analysis]   │
│                                                                │
│  ▼ Row 1: mimikatz.exe                                         │
│    [Full Tier 2 analysis shown here...]                        │
│                                                                │
│  ▶ Row 2: powershell.exe                                       │
│  ▶ Row 3: svchost.exe                                          │
│  [... 7 more rows ...]                                         │
│                                                                │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  💡 RECOMMENDATIONS                                            │
│                                                                │
│  Immediate Actions (Next 1 Hour):                              │
│  1. Isolate WORKSTATION-042 from network                       │
│  2. Reset domain admin password                                │
│  3. Review all logins from compromised host (Event ID 4624)    │
│                                                                │
│  Short Term (Next 24 Hours):                                   │
│  1. Memory forensics on WORKSTATION-042 and LAPTOP-055         │
│  2. Deploy detection rules for identified IOCs                 │
│  3. Threat hunt for lateral movement (SMB/RDP logs)            │
│                                                                │
│  Long Term (Next Week):                                        │
│  1. Credential rotation for all users on affected systems      │
│  2. Deploy EDR on endpoints lacking coverage                   │
│  3. Security awareness training (phishing simulation)          │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

**Bottom of Report:**
```
┌────────────────────────────────────────────────────┐
│  Report Actions                                    │
│                                                    │
│  [Download HTML]  [Download PDF]  [Send via Email] │
│                                                    │
│  [Send to Slack]  [Send to Teams]  [Copy Link]    │
└────────────────────────────────────────────────────┘
```

---

**Option B: Prioritized Report (Smart Batching for 135+ Rows)**

**Step 4B.1: Upload Large CSV**
```
Upload: large_alerts.csv (135 rows)
Wait for pipeline processing (30-60 seconds)
```

**Step 4B.2: Click Prioritized Report Button**
```
New button appears when rows > 25:
[Generate Prioritized Report] (Recommended for large datasets)
```

**Step 4B.3: Prioritization Options Modal**
```
┌─────────────────────────────────────────────────────┐
│ Generate Prioritized Report                         │
│                                                     │
│ Total Rows: 135                                     │
│                                                     │
│ Processing Strategy:                                │
│                                                     │
│ High Priority (Tier 2 Deep Analysis):               │
│ Top [10▼] rows by DREAD score                       │
│ Cost: $0.03 (10 × $0.003)                           │
│                                                     │
│ Medium Priority (Tier 1 Fast Triage):               │
│ Next [15▼] rows                                     │
│ Cost: $0.0075 (15 × $0.0005)                        │
│                                                     │
│ Low Priority (Pipeline Only):                       │
│ Remaining 110 rows                                  │
│ Cost: $0.00 (no LLM)                                │
│                                                     │
│ Total Estimated Cost: $0.0375                       │
│ (vs $0.40 if processing all 135 rows)               │
│ Savings: $0.3625 (91%)                              │
│                                                     │
│ Persona:                                            │
│ [●] SOC Analyst  [ ] Threat Hunter  [ ] CISO        │
│                                                     │
│           [Cancel]  [Generate Report]               │
└─────────────────────────────────────────────────────┘
```

**Step 4B.4: Processing with Progress**
```
┌─────────────────────────────────────────────────────┐
│ Processing Prioritized Report...                    │
│                                                     │
│ [████████████████░░░░] 80%                          │
│                                                     │
│ Stage: Processing medium priority rows              │
│ Current: Row 22/25                                  │
│ Time remaining: ~8 seconds                          │
│                                                     │
│ Completed:                                          │
│ ✓ Prioritization (135 rows sorted)                  │
│ ✓ High priority (10 rows, Tier 2)                  │
│ ✓ Medium priority (15 rows, Tier 1) - in progress  │
│ ⏳ Low priority (110 rows, pipeline only) - pending │
└─────────────────────────────────────────────────────┘
```

**Step 4B.5: Prioritized Report Opens**
```
Report shows:
- Executive summary focused on top 10 threats
- High priority section: Full Tier 2 analysis for each
- Medium priority section: Tier 1 summaries
- Low priority section: Table with verdict/DREAD only
- Benign count: "30 benign artifacts excluded from report"
```

---

### STAGE 5: Send/Export Report

**Option A: Download HTML**

**Step 5A.1: Click Download HTML**
```
[Download HTML] ← Click
```

**Step 5A.2: Browser Downloads File**
```
Downloads folder:
security_report_20250122_143000.html (456 KB)
```

**Step 5A.3: Open in Browser**
```
Double-click HTML file
Opens in default browser
Can share via email attachment or file share
```

---

**Option B: Download PDF**

**Step 5B.1: Click Download PDF**
```
[Download PDF] ← Click
```

**Backend Processing:**
```python
# Backend: src/api/report_endpoints.py
@router.post('/api/v1/report/generate_pdf')
async def generate_pdf_report(req: Request):
    payload = await req.json()
    html = build_report_html(payload)

    # Convert HTML → PDF using WeasyPrint
    from weasyprint import HTML
    pdf_bytes = HTML(string=html).write_pdf()

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type='application/pdf',
        headers={'Content-Disposition': 'attachment; filename="report.pdf"'}
    )
```

**Step 5B.2: Browser Downloads PDF**
```
Downloads folder:
security_report_20250122_143000.pdf (892 KB)
```

---

**Option C: Send to Slack**

**Step 5C.1: Click Send to Slack**
```
[Send to Slack] ← Click
```

**Step 5C.2: Slack Configuration Modal**
```
┌─────────────────────────────────────────────────────┐
│ Send Report to Slack                                │
│                                                     │
│ Webhook URL:                                        │
│ [https://hooks.slack.com/services/T00.../B00...]    │
│                                                     │
│ Channel:                                            │
│ [#security-alerts                               ▼]  │
│                                                     │
│ Message Preview:                                    │
│ ┌───────────────────────────────────────────────┐   │
│ │ 🚨 Security Alert Report                      │   │
│ │ Generated: 2025-01-22 14:30:00                │   │
│ │                                               │   │
│ │ 📊 Summary:                                   │   │
│ │ • Total Alerts: 10                            │   │
│ │ • Malicious: 2                                │   │
│ │ • Suspicious: 5                               │   │
│ │ • Benign: 3                                   │   │
│ │                                               │   │
│ │ 🔴 Top Threats:                               │   │
│ │ 1. mimikatz.exe (DREAD: 9.2)                  │   │
│ │ 2. powershell.exe (DREAD: 8.5)                │   │
│ │                                               │   │
│ │ <http://localhost:8000/reports/rpt_001|       │   │
│ │  View Full Report>                            │   │
│ └───────────────────────────────────────────────┘   │
│                                                     │
│ Attach Files:                                       │
│ [✓] HTML Report  [✓] PDF Report                     │
│                                                     │
│           [Cancel]  [Send to Slack]                 │
└─────────────────────────────────────────────────────┘
```

**Step 5C.3: Send Processing**
```
Backend: POST /api/v1/integrations/slack/send_report
         {
           "report_id": "rpt_20250122_001",
           "channel": "#security-alerts",
           "webhook_url": "https://hooks.slack.com/...",
           "summary": {...},
           "top_threats": [...],
           "attach_html": true,
           "attach_pdf": true
         }
```

```python
# Backend: src/integrations/slack_notifier.py
async def send_report_to_slack(payload: dict):
    # Build Slack blocks message
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🚨 Security Alert Report"}
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Total Alerts:* {payload['summary']['total']}"}
        },
        # ... more blocks
    ]

    # Upload HTML/PDF as file attachments
    files = []
    if payload.get('attach_html'):
        files.append(('file', ('report.html', html_bytes, 'text/html')))
    if payload.get('attach_pdf'):
        files.append(('file', ('report.pdf', pdf_bytes, 'application/pdf')))

    # Send to Slack
    response = requests.post(
        payload['webhook_url'],
        json={"blocks": blocks},
        files=files
    )

    return {"success": response.status_code == 200}
```

**Step 5C.4: Slack Message Posted**
```
Slack #security-alerts channel:

┌─────────────────────────────────────────────────┐
│ JanuSec Bot  14:30                              │
├─────────────────────────────────────────────────┤
│ 🚨 Security Alert Report                        │
│ Generated: 2025-01-22 14:30:00                  │
│                                                 │
│ 📊 Summary:                                     │
│ • Total Alerts: 10                              │
│ • Malicious: 2                                  │
│ • Suspicious: 5                                 │
│ • Benign: 3                                     │
│                                                 │
│ 🔴 Top Threats:                                 │
│ 1. mimikatz.exe (DREAD: 9.2)                    │
│ 2. powershell.exe (DREAD: 8.5)                  │
│                                                 │
│ 📎 Attachments:                                 │
│ 📄 report.html (456 KB)                         │
│ 📄 report.pdf (892 KB)                          │
│                                                 │
│ [View Full Report]                              │
└─────────────────────────────────────────────────┘
```

---

## 🧪 TESTING PROCEDURES

### Test 1: End-to-End Flow (Happy Path)

**Objective:** Verify complete flow from upload → summary → report → download

**Steps:**
1. Start platform: `python run_platform.py`
2. Upload: `tests/test_data/option_c_demo.csv`
3. Wait for pipeline processing (10-30 sec)
4. Click [Investigate Further] on mimikatz.exe row
5. Wait for Tier 2 analysis (2-5 sec)
6. Click all 4 AI Insight buttons
7. Verify HopGraph shows attack chain
8. Go back to CSV Analyzer
9. Click [Generate Report for All Rows]
10. Select HTML format, include executive summary
11. Wait for report generation (5-10 sec)
12. Verify report opens in new tab
13. Click [Download HTML]
14. Verify HTML file downloads successfully

**Expected Results:**
- ✅ All 10 rows displayed with verdicts
- ✅ Tier 2 analysis generates (60-147 lines)
- ✅ All 4 AI insights work (DREAD, playbook, hunt, executive)
- ✅ HopGraph shows 3-node attack chain
- ✅ Report includes executive summary
- ✅ HTML downloads successfully

**Cost:** ~$0.015 total

**Time:** ~2-3 minutes

---

### Test 2: Batch Summary Generation

**Objective:** Verify Tier 1 summaries for all rows

**Steps:**
1. Upload: `tests/test_data/option_c_demo.csv`
2. Click [Generate Summaries for All Rows]
3. Select Tier 1
4. Confirm cost estimate ($0.005)
5. Click [Generate Summaries]
6. Watch progress bar (should complete in 10-20 sec)
7. Verify table updates with "Summary" column
8. Click [View Full Summary] on any row
9. Verify 30-45 line summary displays

**Expected Results:**
- ✅ Progress bar shows real-time updates
- ✅ All 10 summaries generated
- ✅ Cost tracking shows $0.005
- ✅ Summaries are 30-45 lines each

---

### Test 3: Prioritized Report (Large Dataset)

**Objective:** Verify smart batching for 135+ rows

**Prerequisites:**
```bash
# Create large test CSV
python scripts/generate_test_csv.py --rows 135 --output tests/test_data/large_alerts.csv
```

**Steps:**
1. Upload: `tests/test_data/large_alerts.csv`
2. Wait for pipeline processing (30-60 sec)
3. Click [Generate Prioritized Report]
4. Verify default settings (Top 10 Tier 2, Next 15 Tier 1)
5. Verify cost estimate (~$0.0375 vs $0.40 naive)
6. Click [Generate Report]
7. Watch progress (should take 60-90 sec)
8. Verify report structure:
   - High priority section: 10 rows with Tier 2 analysis
   - Medium priority section: 15 rows with Tier 1 summaries
   - Low priority section: 110 rows with pipeline data only

**Expected Results:**
- ✅ Prioritization works correctly (sorted by DREAD)
- ✅ Cost savings: 91% vs processing all rows
- ✅ Report focuses detail on high-priority threats
- ✅ Processing completes in < 2 minutes

---

### Test 4: Slack Integration

**Prerequisites:**
```bash
# Create Slack webhook (one-time setup)
# 1. Go to https://api.slack.com/apps
# 2. Create new app
# 3. Enable Incoming Webhooks
# 4. Create webhook for #security-alerts channel
# 5. Copy webhook URL

# Add to .env
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T00.../B00.../abc123
```

**Steps:**
1. Generate any report (follow Test 1 steps 1-10)
2. Click [Send to Slack]
3. Verify webhook URL populated
4. Select channel: #security-alerts
5. Verify message preview looks correct
6. Check [✓] Attach HTML and PDF
7. Click [Send to Slack]
8. Wait 2-3 seconds
9. Check Slack #security-alerts channel

**Expected Results:**
- ✅ Message posted to Slack within 3 seconds
- ✅ Summary statistics correct
- ✅ Top threats listed
- ✅ HTML and PDF attached
- ✅ "View Full Report" link works

---

### Test 5: Historical Context

**Objective:** Verify historical incident matching works

**Steps:**
1. Verify historical incidents seeded:
   ```bash
   sqlite3 janusec_dev.db "SELECT sha256, process_name, outcome FROM historical_incidents;"
   ```

2. Upload CSV with matching SHA256:
   ```csv
   process_name,host,sha256,factors,verdict
   powershell.exe,WORKST-42,9bf41199f05fa1de8be5b84c6ef6e0a37f7b3d3f7a6e5d4c3b2a1f0e9d8c7b6a,process_injection,suspicious
   ```

3. Click [Investigate Further]
4. Look for "SECTION 2: HISTORICAL CONTEXT" in Tier 2 analysis
5. Verify it mentions:
   - "⚠️ WARNING: Similar incident detected 14 days ago!"
   - "Outcome: confirmed_malicious"
   - "Analyst Notes: Emotet dropper..."

**Expected Results:**
- ✅ Historical match detected
- ✅ Past incident details included
- ✅ Recommendation enhanced with historical context

---

## 🐛 TROUBLESHOOTING

### Issue: No LLM Summaries Generating

**Symptom:** Click "Generate Summaries" but nothing happens

**Possible Causes:**
1. LLM client not configured
2. API key missing/invalid
3. Network issue

**Fix:**
```bash
# Check LLM client configuration
grep -E "DEFAULT_CLIENT|ANTHROPIC_API_KEY" .env

# Test LLM client directly
python -c "
from src.integrations.llm_client import generate_summary
result = generate_summary('Test prompt', max_tokens=50)
print(result)
"

# If error, check API key
echo $ANTHROPIC_API_KEY  # Should not be empty
```

---

### Issue: Report Generation Fails

**Symptom:** Click "Generate Report" → 500 error

**Possible Causes:**
1. WeasyPrint not installed (for PDF)
2. Report payload too large
3. LLM timeout

**Fix:**
```bash
# For PDF issues, install WeasyPrint
pip install weasyprint

# Check backend logs
tail -f logs/platform.log

# Look for specific error message
```

---

### Issue: Slack Send Fails

**Symptom:** "Failed to send to Slack" error

**Possible Causes:**
1. Invalid webhook URL
2. File too large for Slack (>100 MB)
3. Network/firewall block

**Fix:**
```bash
# Test webhook manually
curl -X POST https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
  -H 'Content-Type: application/json' \
  -d '{"text":"Test message"}'

# Should return "ok"
```

---

## ✅ SUCCESS CRITERIA

You've successfully tested the complete flow if:

- ✅ CSV uploads and pipeline processes all rows
- ✅ Tier 1 summaries generate for batch processing
- ✅ Tier 2 deep analysis works on individual rows
- ✅ HopGraph attack chain displays
- ✅ All 4 AI Insights generate (DREAD, playbook, hunt, executive)
- ✅ Reports generate in HTML and PDF formats
- ✅ Prioritized reports work for 135+ row datasets
- ✅ Reports download successfully
- ✅ Slack integration posts messages and attachments
- ✅ Historical context appears when SHA256 matches
- ✅ Cost tracking updates accurately

---

## 📚 RELATED DOCUMENTATION

- **OLLAMA_INTEGRATION_GUIDE.md** - Local LLM testing
- **REPORT_GENERATION_AND_BATCH_STRATEGY.md** - Prioritization logic
- **OPTION_C_FINAL_STATUS.md** - Implementation status
- **READY_FOR_LIVE_TESTING.md** - Testing checklist
- **docs/CEO_DEMO_SCRIPT.md** - Demo walkthrough

---

**Ready to test the complete user flow? Start with Test 1!**
