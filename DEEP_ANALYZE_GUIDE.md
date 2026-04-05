# Deep Analyze Feature - Complete Guide

## Overview
The Deep Analyze feature provides AI-powered per-row analysis with strict schema output, persona-specific reports, and multi-framework mapping (MITRE, STRIDE, DREAD, etc.).

## How It Works

### 1. **Upload and Load CSV/Excel File**

1. Go to `http://localhost:8000/static/csv_analyzer.html`
2. Click "Choose File" and select `dump\Cyberstash_csv2.xlsx`
3. Click "Load" button
4. You'll see rows loaded in the table

### 2. **Trigger Deep Analyze**

**Option A: Analyze All Rows**
- Simply click "Deep Analyze" button (no rows selected = all rows analyzed)

**Option B: Analyze Selected Rows**
- Check the checkboxes next to specific rows you want to analyze
- Click "Deep Analyze"

### 3. **Deep Analyze Modal**

When you click "Deep Analyze", a modal appears with options:

```
┌─────────────────────────────────────────┐
│  Deep Analyze Options                   │
├─────────────────────────────────────────┤
│  Mode:  ○ Basic  ○ Advanced             │
│  ☑ Auto-LLM                             │
│                                         │
│  Detected Columns & Mapping Preview    │
│  ┌───────────────────────────────────┐ │
│  │ ☑ user → user                     │ │
│  │ ☑ host → host                     │ │
│  │ ☑ process → process               │ │
│  │ ☑ file_hash → file_hash           │ │
│  └───────────────────────────────────┘ │
│                                         │
│  [Cancel]  [Run Deep Analyze]          │
└─────────────────────────────────────────┘
```

**Options Explained:**
- **Basic Mode**: Runs 4 core stages (GeoIP, ThreatIntel, GraphTraversal, LLMSummary) - ~20 signals
- **Advanced Mode**: Adds eBPF and PCAP analysis stages for deeper inspection
- **Auto-LLM**: Generates strict-schema per-row summaries with:
  - `verdict` (pass/fail/suspicious)
  - `risk_level` (low/medium/high)
  - `llm_summary` (natural language explanation)
  - `recommendation` (remediation steps)
  - `classification` (threat category)

### 4. **Viewing Analysis Progress**

After clicking "Run Deep Analyze":
- A drawer/panel appears showing:
  - Assessment ID
  - Pipeline stages (GeoIP → ThreatIntel → Graph → LLM)
  - Progress indicator
  - Status updates

### 5. **Viewing LLM Output (Per-Row Summaries)**

**Method 1: Via API (JSON Output)**
```bash
# Get the assessment ID from the drawer (e.g., assessment-1234567890-abc123)
curl -X GET "http://localhost:8000/api/v1/assessments/{assessment_id}/rows" \
  -H "x-api-key: devkey123"
```

Response:
```json
{
  "assessment_id": "assessment-1234567890-abc123",
  "row_count": 50,
  "rows": [
    {
      "row_index": 0,
      "verdict": "suspicious",
      "risk_level": "high",
      "llm_summary": "Process powershell.exe running from unusual path C:\\Temp with encoded command. High risk indicators include: unsigned binary, sensitive path, novel command pattern.",
      "recommendation": "1. Isolate host immediately\n2. Collect memory dump\n3. Review parent process chain\n4. Block hash across fleet",
      "classification": "potential_malware",
      "process_name": "powershell.exe",
      "file_path": "C:\\Temp\\powershell.exe",
      "host": "workstation-42",
      "factors": ["unsigned_sensitive_path", "lolbin", "novel_global"]
    }
  ]
}
```

**Method 2: Via UI (Drawer)**
- After analysis completes, the drawer shows:
  - "View Rows" button
  - Click to see per-row summaries in formatted cards

**Method 3: Polling Endpoint**
```javascript
// Frontend polls this automatically
GET /api/v1/assessments/{assessment_id}

// Returns full assessment including:
// - status: "pending", "completed", "failed"
// - llm_rows: array of per-row summaries
// - canonical: framework mappings
// - mappings: { mitre: [...], stride: [...], dread: {...} }
```

### 6. **Generating Persona-Specific Reports**

Reports tailor the output for different audiences:
- **CISO**: Executive summary, business impact, compliance gaps
- **SOC**: Tactical indicators, hunt queries, triage priorities
- **Hunter**: Threat hypotheses, attack chains, advanced analytics
- **Forensics**: Timeline, artifacts, evidence chain

**Steps:**
1. Fill in report fields (above the table):
   - Company: `Cyberstash`
   - Recipients: `ciso@company.com, soc@company.com`
   - Persona: Select from dropdown (CISO/SOC/Hunter/Forensics)
   - ☑ Include Model Summary (for AI provenance)

2. Click "Export Report"

3. **Report opens in new window** with:
   - Executive summary
   - MITRE technique heatmap
   - Per-row DREAD scores (visual bars)
   - Playbook suggestions
   - Compliance controls

**Viewing Reports Live:**
- After clicking "Export Report", a new browser tab opens with HTML report
- The report is also stored in `REPORT_STORE` and can be re-accessed via:
  ```javascript
  // In browser console
  window.__LAST_GENERATED_REPORT.html
  ```

### 7. **Sharing Reports**

Click "Share Report" button (next to Export):
- Choose channel: Webhook, Email, WhatsApp, Teams
- Enter target (URL or email)
- Optional message
- Click "Send"

Backend uploads report HTML to `/api/v1/report/upload` and sends via `/api/v1/integrations/send_report`

---

## Full Workflow Example

### Scenario: Analyzing Cyberstash_csv2.xlsx

1. **Start Server**
   ```bash
   cd D:\AI\Threat_thy_sniffer
   python run_platform.py
   # OR
   python -m uvicorn src.api.app:app --host 0.0.0.0 --port 8000
   ```

2. **Open CSV Analyzer**
   - Navigate to: `http://localhost:8000/static/csv_analyzer.html`

3. **Load File**
   - Click file input → select `dump\Cyberstash_csv2.xlsx`
   - Click "Load"
   - See rows populate in table

4. **Deep Analyze**
   - Click "Deep Analyze" button
   - Modal appears → check "Auto-LLM"
   - Select "Advanced" if you want eBPF/PCAP stages
   - Review column mappings (auto-detected)
   - Click "Run Deep Analyze"

5. **Monitor Progress**
   - Drawer slides in showing:
     ```
     Assessment ID: assessment-1737123456-7a2b3c4d
     Status: pending

     Pipeline Stages:
     ✓ GeoIP (23ms)
     ✓ ThreatIntel (45ms)
     ⏳ GraphTraversal (running...)
     ⏸ LLMSummary (queued)
     ```

6. **View LLM Output**
   - Once status = "completed", click "View Rows" in drawer
   - See per-row cards with:
     - Risk score (0-100)
     - Verdict badge (PASS/FAIL/SUSPICIOUS)
     - LLM summary
     - Recommendations
     - Reviewer notes section

7. **Export Report**
   - Set Company: `Cyberstash`
   - Set Recipients: `analyst@cyberstash.com`
   - Select Persona: `Forensics`
   - ☑ Include Model Summary
   - Click "Export Report"
   - New tab opens with HTML report

8. **Review Report**
   Report includes:
   - **MITRE Heatmap**: Top techniques (T1218, T1036, T1071)
   - **DREAD Summary**: Visual bars showing risk per row
   - **Playbook**: "Verify signer → check parent → network telemetry → contain"
   - **Compliance**: CIS, NIST, SANS controls mapped

---

## Troubleshooting

### "Nothing happens when I click Deep Analyze"

**Possible Causes:**
1. **No rows loaded** - Load CSV first
2. **JavaScript error** - Check browser console (F12 → Console tab)
3. **Modal blocked** - Look for modal overlay (semi-transparent background)
4. **Server not running** - Check `netstat -an | findstr 8000`

**Debug Steps:**
```javascript
// In browser console:
window.LAST_RESULTS  // Should show loaded rows
window.initiateDeepAnalyze  // Should be a function
```

### "Button appears blurry"
- This is just CSS styling (blur effect on hover)
- Button is NOT disabled
- Click it anyway - modal should appear

### "No LLM output visible"
- Wait for status to show "completed" (poll every 2s)
- Check `/api/v1/assessments/{assessment_id}/rows` endpoint
- Ensure `auto_llm: true` in options

### "Report is empty"
- Deep Analyze must complete first
- Click "Export Report" AFTER seeing completed status
- Check `window.__LAST_GENERATED_REPORT` in console

---

## API Reference

### Start Analysis
```http
POST /api/v1/assessments/deep_analyze
Content-Type: application/json

{
  "rows": [
    {
      "row_index": 0,
      "raw": {
        "process": "powershell.exe",
        "host": "workstation-1",
        "user": "admin",
        "file_hash": "abc123..."
      }
    }
  ],
  "options": {
    "auto_llm": true
  },
  "analyze_mode": "advanced",
  "org": "cyberstash"
}
```

Response:
```json
{
  "assessment_id": "assessment-1234567890-abc123",
  "session_id": "session-...",
  "status": "pending",
  "pipeline_stages": [
    {"idx": 0, "name": "GeoIP"},
    {"idx": 1, "name": "ThreatIntel"}
  ],
  "canonical": {...},
  "mappings": {...}
}
```

### Poll Status
```http
GET /api/v1/assessments/{assessment_id}
x-api-key: devkey123
```

### Get LLM Rows
```http
GET /api/v1/assessments/{assessment_id}/rows
x-api-key: devkey123
```

### Export Report
```http
POST /api/v1/assessments/{assessment_id}/report
Content-Type: application/json

{
  "persona": "ciso",
  "company": "Cyberstash",
  "recipients": ["analyst@cyberstash.com"],
  "include_model": true,
  "max_rows": 50
}
```

---

## Advanced: Strict Schema Output

Each LLM row follows this schema:

```typescript
interface LLMRow {
  row_index: number;

  // Core classification
  verdict: "pass" | "fail" | "suspicious" | "unknown";
  risk_level: "low" | "medium" | "high" | "critical";
  classification: string;  // e.g., "potential_malware", "privilege_escalation"

  // AI-generated content
  llm_summary: string;  // Natural language explanation
  recommendation: string;  // Remediation steps (multi-line)

  // Original data
  process_name?: string;
  file_path?: string;
  host?: string;
  sha256?: string;

  // Signal metadata
  factors: string[];  // e.g., ["lolbin", "unsigned_sensitive_path"]

  // Framework mappings (auto-generated)
  mitre?: Array<{id: string, name: string, tactic: string}>;
  stride?: string[];
  dread?: {score: number, level: string};
}
```

---

## Architecture Flow

```
User Clicks "Deep Analyze"
        ↓
  Modal with Options
        ↓
POST /api/v1/assessments/deep_analyze
        ↓
Backend creates assessment_id
        ↓
Spawns async worker (stages: GeoIP → ThreatIntel → Graph → LLM)
        ↓
Persists to disk: data/assessments/{org}/{date}/{assessment_id}.json
        ↓
Frontend polls GET /api/v1/assessments/{assessment_id}
        ↓
Worker updates file as each stage completes
        ↓
Frontend detects status: "completed"
        ↓
User clicks "View Rows" → GET /api/v1/assessments/{assessment_id}/rows
        ↓
Displays per-row LLM summaries with verdict/risk/recommendations
        ↓
User clicks "Export Report" → POST /api/v1/assessments/{assessment_id}/report
        ↓
Backend builds persona-specific HTML document
        ↓
Opens in new tab (with MITRE heatmap, DREAD bars, playbooks)
```

---

## Next Steps

1. **Test with your file**: Follow steps 1-7 above
2. **Verify LLM output**: Check assessment endpoint for `llm_rows`
3. **Generate reports**: Try all 4 personas (CISO, SOC, Hunter, Forensics)
4. **Integrate with workflows**: Use API to automate batch analysis

## Files to Inspect

- Frontend: `frontend/static/csv_analyzer.html` (UI)
- JS Logic: `frontend/static/js/csv_analyzer.js` (client-side orchestration)
- Backend: `src/api/deep_analyze_endpoints.py` (assessment API)
- LLM Builder: `src/analysis/auto_llm.py` (per-row schema generation)
- Pipeline: `src/pipeline/deep_analyze_pipeline.py` (stage orchestration)
