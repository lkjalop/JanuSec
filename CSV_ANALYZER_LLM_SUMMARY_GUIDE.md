# CSV Analyzer - LLM Summary Per Row Guide

## 📸 Current Issue: SELECTED_ROWS Error

Based on the screenshot `csv-analyser-llm-summary.PNG`, you're encountering:
```
Error initiating Deep Analyze: SELECTED_ROWS is not defined
```

---

## 🔧 How to Prompt GitHub Copilot to Fix This

### Prompt 1: Fix the SELECTED_ROWS Scoping Issue
```
@workspace In frontend/static/csv_analyzer.html line 652, when window.initiateDeepAnalyze()
is called from the modal, it throws "SELECTED_ROWS is not defined". The SELECTED_ROWS
variable is defined in js/csv_analyzer.js line 7 inside an IIFE. Please fix the scoping
issue so that initiateDeepAnalyze can access SELECTED_ROWS. Consider either:
1. Exposing SELECTED_ROWS on window object (like window.csvSelectedRows)
2. Ensuring csv_analyzer.js loads before the inline modal script runs
3. Passing selected rows as a parameter to initiateDeepAnalyze from the modal
```

### Prompt 2: Ensure Script Loading Order
```
@workspace In frontend/static/csv_analyzer.html, the inline script at line 597-663
(deepAnalyze modal) runs before csv_analyzer.js fully loads. Please ensure that
csv_analyzer.js is loaded with defer or move the modal initialization code into
csv_analyzer.js so SELECTED_ROWS is always in scope.
```

### Prompt 3: Add Error Handling
```
@workspace In frontend/static/js/csv_analyzer.js function initiateDeepAnalyze() at
line 1535, add a null check for SELECTED_ROWS with a fallback to window.csvSelectedRows
or an empty Set(). Also add helpful error messages when no rows are selected.
```

---

## 📊 Visual User Flow: Viewing LLM Summary Per Row

```
┌─────────────────────────────────────────────────────────────────────┐
│                      CSV ANALYZER INTERFACE                         │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Step 1: Upload CSV File                                            │
│  ┌──────────────┐                                                   │
│  │ Choose File  │  [cyberstash_csv2.xlsx]  [Load]                   │
│  └──────────────┘                                                   │
│                                                                      │
│  Results: 135 rows loaded                                           │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Step 2: Filter & Select Rows                                       │
│  ┌────┐  ┌────────────┐  ┌────────┐                                │
│  │All │  │Suspicious  │  │Passed  │                                │
│  └────┘  └────────────┘  └────────┘                                │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ ☑ Row 1: unknown - c:\windows\temp\fsagentcrash7...        │   │
│  │ ☑ Row 2: unknown - c:\windows\system32\msiezec.exe         │   │
│  │ □ Row 3: msiexec.exe - c:\windows\system32\msiexec.exe     │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Risk Appetite: [Medium ▼]                                          │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Step 3: Click "Deep Analyze" Button                                │
│  ┌──────────────────┐                                               │
│  │  Deep Analyze    │  ← Click this button                          │
│  └──────────────────┘                                               │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│          DEEP ANALYZE OPTIONS MODAL                                 │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Mode: ◉ Basic    ○ Advanced                                │   │
│  │  ☑ Auto-LLM  ← ENABLE THIS FOR LLM SUMMARIES               │   │
│  │                                                              │   │
│  │  Detected Columns:                                          │   │
│  │  ☑ process_name → [process ▼]                              │   │
│  │  ☑ file_path    → [file_path ▼]                            │   │
│  │  ☑ sha256       → [file_hash ▼]                            │   │
│  │  ☑ host         → [host ▼]                                 │   │
│  │                                                              │   │
│  │  [Save Preset]  [Preset: ▼]                                │   │
│  │                                                              │   │
│  │  [Cancel]  [Run Deep Analyze]  ← Click to start            │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Step 4: Assessment Processing (Right Drawer Opens)                 │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Deep Analyze Progress                                      │   │
│  │  ━━━━━━━━━━━━━━━━━━━━━━━━ 75%                             │   │
│  │                                                              │   │
│  │  Started - assessment-1732024089-a3f7e2b4                  │   │
│  │  Status: Processing rows...                                 │   │
│  │                                                              │   │
│  │  Stages Complete:                                           │   │
│  │  ✓ GeoIP                                                    │   │
│  │  ✓ ThreatIntel                                              │   │
│  │  ✓ GraphTraversal                                           │   │
│  │  ⏳ LLMSummary (if Auto-LLM enabled)                        │   │
│  │                                                              │   │
│  │  Rows Processed: 135 / 135                                  │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Step 5: View LLM Summaries Per Row                                 │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  🎯 PRIORITY ROWS (Sorted by Risk - Critical First)        │   │
│  │                                                              │   │
│  │  ┌────────────────────────────────────────────────────┐    │   │
│  │  │ #1  CRITICAL | Risk: 9.2 | fsagentcrash7-6-2021... │    │   │
│  │  │     LLM Summary: "Unsigned executable in temp     │    │   │
│  │  │     directory with rare global signature.         │    │   │
│  │  │     Potential malware or unauthorized software."  │    │   │
│  │  │                                                    │    │   │
│  │  │     MITRE: T1036 (Masquerading)                   │    │   │
│  │  │     Recommendation: Quarantine immediately        │    │   │
│  │  │                                                    │    │   │
│  │  │     [Triage] [Escalate] [Dismiss] [Investigated]  │    │   │
│  │  │     Notes: ________________________________        │    │   │
│  │  └────────────────────────────────────────────────────┘    │   │
│  │                                                              │   │
│  │  ┌────────────────────────────────────────────────────┐    │   │
│  │  │ #2  HIGH | Risk: 7.8 | msiezec.exe               │    │   │
│  │  │     LLM Summary: "System32 process with unsigned  │    │   │
│  │  │     signature. Moderate threat indicators."       │    │   │
│  │  │     [Triage] [Escalate] [Dismiss]                 │    │   │
│  │  └────────────────────────────────────────────────────┘    │   │
│  │                                                              │   │
│  │  ... (more rows sorted by priority)                         │   │
│  │                                                              │   │
│  │  Review Progress: 12 / 135 reviewed (8.9%)                  │   │
│  │                                                              │   │
│  │  [Export Report]  [Download JSON]                           │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Step 6: Export Report (Optional)                                   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Export Settings:                                           │   │
│  │  Persona: [CISO ▼]                                          │   │
│  │  Company: [Your Org]                                        │   │
│  │  Recipients: analyst@company.com                            │   │
│  │  Include Model Details: ☑                                   │   │
│  │  Max Rows: [25]                                             │   │
│  │                                                              │   │
│  │  [Generate Report]                                          │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Current Batch Processing Availability

### ❌ **Batch Processing DOES NOT Currently Exist**

The current implementation processes:
- **Individual assessment**: All selected rows in one analysis
- **No batch separation**: Cannot split rows into priority-based batches
- **No queue system**: No "process critical first, then high, then medium"

---

## 📋 Recommendations: How to Implement Batch Processing with Priority

### Architecture Recommendation

```
┌─────────────────────────────────────────────────────────────────┐
│             BATCH PROCESSING ARCHITECTURE                       │
└─────────────────────────────────────────────────────────────────┘

Step 1: Pre-Analysis Risk Scoring
  ├─ Client-side DREAD scoring (frontend/static/js/csv_analyzer.js)
  ├─ Factor-based risk calculation (2-3 seconds for 1000 rows)
  └─ Sort rows: CRITICAL > HIGH > MEDIUM > LOW

Step 2: Batch Creation
  ├─ Batch 1: CRITICAL (risk >= 8.0)  → Max 50 rows
  ├─ Batch 2: HIGH (risk 6.0-7.9)     → Max 100 rows
  ├─ Batch 3: MEDIUM (risk 4.0-5.9)   → Max 200 rows
  └─ Batch 4: LOW (risk < 4.0)        → Remaining rows

Step 3: Sequential Processing
  ├─ POST /api/v1/assessments/deep_analyze (Batch 1)
  │   └─ Auto-LLM: YES (critical needs human review)
  ├─ Poll until complete
  ├─ POST /api/v1/assessments/deep_analyze (Batch 2)
  │   └─ Auto-LLM: YES (high needs review)
  ├─ Poll until complete
  ├─ POST /api/v1/assessments/deep_analyze (Batch 3)
  │   └─ Auto-LLM: Optional (medium can be bulk processed)
  └─ POST /api/v1/assessments/deep_analyze (Batch 4)
      └─ Auto-LLM: NO (low risk, skip LLM to save cost)

Step 4: Result Aggregation
  └─ Combine all assessment results into unified view
```

### Files to Modify for Batch Processing

#### 1. **Frontend: Batch UI Logic**
**File:** `frontend/static/js/csv_analyzer.js`

**Prompt for Copilot:**
```
@workspace Create a new function createBatchedAssessments() in
frontend/static/js/csv_analyzer.js that:
1. Takes all selected rows and calculates risk score using computeDreadBreakdown()
2. Sorts rows into 4 batches: CRITICAL (risk>=8), HIGH (6-7.9), MEDIUM (4-5.9), LOW (<4)
3. Shows a modal with batch summary: "5 critical, 23 high, 67 medium, 40 low"
4. Asks user: "Process all batches? [Yes] or [Customize]"
5. Sequentially calls initiateDeepAnalyze() for each batch
6. Updates progress: "Batch 1/4 complete (5 critical rows processed)"
7. Combines results in single assessment drawer
```

**Changes needed:**
- [ ] Add `createBatchedAssessments(rows, options)` function
- [ ] Add batch progress UI in assessment drawer
- [ ] Modify `initiateDeepAnalyze()` to accept `batch_meta` parameter
- [ ] Store batch results with IDs: `assessment-batch-1-{timestamp}`
- [ ] Add "View All Batches" button to see combined results

#### 2. **Backend: Batch Metadata**
**File:** `src/api/deep_analyze_endpoints.py`

**Prompt for Copilot:**
```
@workspace In src/api/deep_analyze_endpoints.py, modify the deep_analyze endpoint
to accept optional batch_meta in the request payload:
{
  "batch_meta": {
    "batch_number": 1,
    "total_batches": 4,
    "priority_level": "CRITICAL",
    "parent_assessment_id": "assessment-parent-12345"
  }
}
Store batch_meta in the assessment object and include it in the response.
Add a GET endpoint /api/v1/assessments/batch/{parent_id} that returns all
child assessments for a parent batch assessment.
```

**Changes needed:**
- [ ] Accept `batch_meta` in POST payload (line ~162)
- [ ] Store in `assessment_obj['batch_meta']` (line ~247)
- [ ] Add GET `/api/v1/assessments/batch/{parent_id}` endpoint
- [ ] Return sorted list of child assessments by batch_number

#### 3. **Backend: Priority-Based LLM Cost Control**
**File:** `src/integrations/llm_client.py`

**Prompt for Copilot:**
```
@workspace In src/integrations/llm_client.py, add priority-aware LLM routing:
- CRITICAL: Always use full LLM with max_tokens=800
- HIGH: Use LLM with max_tokens=500
- MEDIUM: Use LLM only if budget allows, else use fallback
- LOW: Skip LLM entirely, return deterministic summary
Check batch_meta.priority_level in context to determine routing.
```

**Changes needed:**
- [ ] Add priority check in `generate()` method
- [ ] Route LOW to mock/deterministic response
- [ ] Track cost per batch in telemetry

#### 4. **Frontend: Batch Results Visualization**
**File:** `frontend/static/csv_analyzer.html`

**Prompt for Copilot:**
```
@workspace Add a batch results panel to csv_analyzer.html that shows:
┌────────────────────────────────────────┐
│ Batch Processing Complete              │
│ ┌────────────────────────────────────┐ │
│ │ ✓ Batch 1: CRITICAL (5 rows)      │ │
│ │   2 escalated, 3 under review     │ │
│ │ ✓ Batch 2: HIGH (23 rows)         │ │
│ │   5 dismissed, 18 triaged         │ │
│ │ ⏳ Batch 3: MEDIUM (67 rows)      │ │
│ │   Processing... 34/67             │ │
│ │ ⏸️ Batch 4: LOW (40 rows)         │ │
│ │   Queued                          │ │
│ └────────────────────────────────────┘ │
│ [View All] [Pause] [Resume]            │
└────────────────────────────────────────┘
```

---

## 🛡️ Fallback When LLM Not Available

### Current Fallback: Already Implemented ✅

**File:** `src/analysis/auto_llm.py` (line 40-46)

```python
# Fallback deterministic response
try:
    proc = row.get('process_name') or row.get('process') or row.get('file_path') or 'row'
    text = f"Mock summary for {proc}: likely suspicious based on hashes and factors."
    return {'text': text, 'model': 'fallback-mock', 'meta': {}}
except Exception:
    return {'text': 'LLM not available', 'model': 'none', 'meta': {}}
```

### Additional Improvements Needed

#### Add User Notification
**File:** `frontend/static/js/csv_analyzer.js` (line ~1590)

**Prompt for Copilot:**
```
@workspace In frontend/static/js/csv_analyzer.js around line 1590, when initiateDeepAnalyze
catches an error, check if the error message contains "LLM not available" or "mock".
If so, show a warning toast:
"⚠️ LLM service unavailable. Using deterministic fallback summaries.
Configure Ollama or external AI API in Settings to enable full LLM analysis."
Add a [Settings] button that links to /static/ai_settings.html
```

#### Add Settings Page Check
**File:** `frontend/static/ai_settings.html`

**Prompt for Copilot:**
```
@workspace Add a section to ai_settings.html that shows:
┌────────────────────────────────────────┐
│ LLM Configuration Status               │
│ ○ Ollama: NOT CONFIGURED               │
│   [Test Connection]                    │
│                                        │
│ ○ OpenAI: NOT CONFIGURED               │
│   API Key: [__________] [Test]        │
│                                        │
│ ○ Anthropic Claude: NOT CONFIGURED     │
│   API Key: [__________] [Test]        │
│                                        │
│ ✓ Fallback (Deterministic): ACTIVE    │
│   Note: Using rule-based summaries    │
│                                        │
│ [Save Configuration]                   │
└────────────────────────────────────────┘
```

---

## 📁 Summary: Files to Change

| File | Purpose | Priority |
|------|---------|----------|
| `frontend/static/js/csv_analyzer.js` | Fix SELECTED_ROWS scope, add batch processing | 🔴 Critical |
| `frontend/static/csv_analyzer.html` | Fix script loading order, add batch UI | 🔴 Critical |
| `src/api/deep_analyze_endpoints.py` | Accept batch_meta, add batch endpoints | 🟡 High |
| `src/integrations/llm_client.py` | Priority-based LLM routing | 🟡 High |
| `frontend/static/ai_settings.html` | LLM config status page | 🟢 Medium |

---

## 🎯 Step-by-Step Implementation Plan

### Phase 1: Fix Current Bug (1-2 hours)
1. ✅ Expose SELECTED_ROWS on window object or pass as parameter
2. ✅ Add error handling for undefined variables
3. ✅ Test Deep Analyze with Auto-LLM enabled
4. ✅ Verify LLM summaries appear in drawer

### Phase 2: Add Batch Processing (4-6 hours)
1. ✅ Create pre-analysis risk scoring function
2. ✅ Build batch creation logic (4 priority levels)
3. ✅ Add batch UI with progress tracking
4. ✅ Implement sequential batch processing
5. ✅ Test with 500+ row dataset

### Phase 3: Enhance Fallback & Settings (2-3 hours)
1. ✅ Add LLM status warnings in UI
2. ✅ Create ai_settings.html configuration page
3. ✅ Add connection testing for Ollama/OpenAI/Claude
4. ✅ Document setup instructions

### Phase 4: Human Review Workflow (3-4 hours)
1. ✅ Add row-level review controls (Triage/Escalate/Dismiss)
2. ✅ Track review progress per batch
3. ✅ Export reviewed rows with analyst notes
4. ✅ Add "Review Coverage" metrics

---

## 🔍 How to Read LLM Summary in the UI

### Current Implementation (After Fix)

1. **In Assessment Drawer** (Right side panel after Deep Analyze):
   ```
   Row #1: fsagentcrash7-6-2021...
   Risk: 9.2 (CRITICAL)
   LLM Summary: [Text appears here if Auto-LLM enabled]
   MITRE: T1036 (Masquerading)
   [Triage] [Escalate] [Dismiss]
   ```

2. **Via API** (Polling endpoint):
   ```bash
   GET /api/v1/assessments/{assessment_id}/rows
   ```
   **Response:**
   ```json
   {
     "rows": [
       {
         "row_index": 0,
         "process_name": "unknown",
         "file_path": "c:\\windows\\temp\\fsagentcrash7...",
         "llm_summary": "Mock summary for unknown: likely suspicious...",
         "risk_level": {"label": "High", "numeric": 9.2},
         "classification": "Unknown",
         "recommendation": {"action": "Quarantine"}
       }
     ]
   }
   ```

3. **In Exported Report**:
   - Click [Export Report] button
   - Select persona (CISO, Analyst, Compliance)
   - LLM summaries included in row sections

---

## 📊 Expected LLM Summary Format

### Example Output (from `build_llm_row()`)

```json
{
  "row_index": 0,
  "process_name": "fsagentcrash7-6-2021...",
  "file_path": "c:\\windows\\temp\\fsagentcrash7-6-2021...",
  "llm_summary": "Unsigned executable in sensitive temp directory with rare global signature. Multiple factors indicate potential unauthorized software or malware. High confidence match with T1036 (Masquerading) technique.",
  "risk_level": {
    "label": "High",
    "numeric": 9.2,
    "rationale": "Derived from DREAD-like scoring"
  },
  "mitre_techniques": [
    {"id": "T1036", "why": "Associated factor: unsigned_sensitive_path"}
  ],
  "recommendation": {
    "action": "Quarantine",
    "playbook": "04_isolate_host"
  },
  "source": "llm",  // or "heuristic" if LLM unavailable
  "fingerprint": "a3f7e2b4c5d6..."
}
```

---

## 🚨 Common Issues & Fixes

| Issue | Cause | Fix |
|-------|-------|-----|
| "SELECTED_ROWS is not defined" | Script loading order | Use prompts above to fix scoping |
| No LLM summaries appear | Auto-LLM not enabled | Check ☑ Auto-LLM in modal |
| "LLM not available" | No Ollama/API configured | Check `src/integrations/llm_client.py` |
| Drawer shows empty | Assessment not polled | Check browser console for polling errors |
| Batch processing missing | Not implemented yet | Follow Phase 2 plan above |

---

## 💡 Quick Test Commands

### Test LLM Summary Generation
```bash
# Backend test
curl -X POST http://localhost:8080/api/v1/assessments/deep_analyze \
  -H "Content-Type: application/json" \
  -d '{
    "rows": [{"process_name": "test.exe", "factors": ["lolbin", "unsigned"]}],
    "options": {"auto_llm": true}
  }'
```

### Check Assessment Status
```bash
curl http://localhost:8080/api/v1/assessments/{assessment_id}/rows
```

### View Full Assessment
```bash
curl http://localhost:8080/api/v1/assessments/{assessment_id}
```

---

## 📚 Related Documentation

- **LLM Configuration**: `src/integrations/llm_client.py`
- **Auto LLM Logic**: `src/analysis/auto_llm.py`
- **Deep Analyze Pipeline**: `src/pipeline/deep_analyze_pipeline.py`
- **Frontend CSV Logic**: `frontend/static/js/csv_analyzer.js`
- **Risk Scoring**: `src/explain/dread.py`

---

## 📞 Need Help?

If you encounter issues:
1. Check browser console (F12) for JavaScript errors
2. Check backend logs for LLM client errors
3. Verify API endpoint is running: `curl http://localhost:8080/health`
4. Test with small dataset first (10-20 rows)

---

**Generated:** 2025-01-19
**Version:** 1.0
**Platform:** JanuSec Threat Triage Platform
