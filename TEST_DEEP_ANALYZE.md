# Quick Test: Deep Analyze with Cyberstash_csv2.xlsx

## Pre-Flight Check

### 1. Start the Server
```bash
cd D:\AI\Threat_thy_sniffer
python run_platform.py
```

### 2. Verify Server is Running
Open browser: `http://localhost:8000/health`
Should see: `{"status": "healthy"}`

## Test Steps

### Step 1: Load CSV Analyzer
1. Go to: `http://localhost:8000/static/csv_analyzer.html`
2. Page should load with dark theme

### Step 2: Upload File
1. Click file input at top
2. Select: `D:\AI\Threat_thy_sniffer\dump\Cyberstash_csv2.xlsx`
3. Click "Load" button
4. **Expected**: Table populates with rows from Excel

### Step 3: Trigger Deep Analyze
1. Click "Deep Analyze" button (middle of controls row)
2. **Expected**: Modal pops up titled "Deep Analyze Options"

![Modal should look like this]
```
┌──────────────────────────────────────┐
│ Deep Analyze Options           [X]   │
├──────────────────────────────────────┤
│ ○ Basic  ○ Advanced                  │
│ ☐ Auto-LLM                           │
│                                      │
│ Detected Columns & Mapping Preview  │
│ ┌─────────────────────────────────┐ │
│ │ (auto-detected columns shown)   │ │
│ └─────────────────────────────────┘ │
│                                      │
│        [Cancel] [Run Deep Analyze]  │
└──────────────────────────────────────┘
```

3. **Check the "Auto-LLM" checkbox** (IMPORTANT!)
4. Select "Advanced" if you want eBPF/PCAP stages
5. Click "Run Deep Analyze" (blue button)

### Step 4: Monitor Progress
1. **Expected**: A drawer/panel slides in from right side
2. Shows:
   - Assessment ID (e.g., `assessment-1234567890-abc123`)
   - Status: "pending" → "completed"
   - Pipeline stages with checkmarks:
     - ✓ GeoIP
     - ✓ ThreatIntel
     - ✓ GraphTraversal
     - ✓ LLMSummary

### Step 5: View LLM Output

**Option A: Via Drawer**
- Click "View Rows" button in drawer
- See per-row cards with:
  - Verdict badge (PASS/SUSPICIOUS/FAIL)
  - Risk level (LOW/MEDIUM/HIGH)
  - LLM summary (natural language)
  - Recommendations
  - Review controls (Good/Review/Threat buttons)
  - Analyst notes textarea

**Option B: Via API**
```bash
# Copy the assessment_id from drawer
curl -X GET "http://localhost:8000/api/v1/assessments/assessment-1234567890-abc123/rows" \
  -H "x-api-key: devkey123"
```

Expected JSON:
```json
{
  "assessment_id": "assessment-...",
  "row_count": 100,
  "rows": [
    {
      "row_index": 0,
      "verdict": "suspicious",
      "risk_level": "high",
      "llm_summary": "Process powershell.exe with encoded command...",
      "recommendation": "1. Isolate host\n2. Collect memory dump\n3. Review parent process",
      "classification": "potential_malware",
      "process_name": "powershell.exe",
      "factors": ["lolbin", "unsigned_sensitive_path"]
    }
  ]
}
```

**Option C: Browser Console**
```javascript
// Open DevTools (F12) → Console
window.LAST_DEEP_ANALYZE
// Should show assessment object

// Fetch rows programmatically
fetch('/api/v1/assessments/' + window.currentAssessmentId + '/rows', {
  headers: {'x-api-key': 'devkey123'}
})
.then(r => r.json())
.then(data => console.table(data.rows))
```

### Step 6: Generate Persona Report

1. Fill in fields above table:
   - **Company**: `Cyberstash`
   - **Recipients**: `analyst@cyberstash.com, ciso@cyberstash.com`
   - **Persona**: Select `CISO` (or SOC/Hunter/Forensics)
   - **☑ Include Model Summary** (check this box)

2. Click "Export Report" button

3. **Expected**: New browser tab opens with HTML report showing:
   - Company header
   - Executive summary
   - MITRE Technique Heatmap (table with technique → count)
   - Per-row DREAD Summary (visual bars, 0-10 scale)
   - Playbook Suggestions (remediation steps)
   - Copy buttons per row

### Step 7: Switch Personas

1. In the report panel (below controls), click persona tabs:
   - CISO → Executive language, business impact
   - SOC → Tactical indicators, hunt queries
   - Hunter → Threat hypotheses, analytics
   - Forensics → Timeline, artifacts, evidence

2. Each persona shows different phrasing/focus in the report

---

## Troubleshooting

### Issue: "Nothing happens when I click Deep Analyze"

**Diagnosis:**
1. Open browser DevTools (F12) → Console tab
2. Look for errors (red text)
3. Check:
   ```javascript
   window.LAST_RESULTS  // Should be an array of row objects
   typeof window.initiateDeepAnalyze  // Should be "function"
   ```

**Fixes:**
- If `LAST_RESULTS` is empty → Click "Load" button first
- If `initiateDeepAnalyze` is undefined → Check if `csv_analyzer.js` loaded (Network tab)
- If modal doesn't appear → Check for `display:none` on `#deepAnalyzeModal` element

### Issue: "Modal appears but nothing happens after clicking Run Deep Analyze"

**Diagnosis:**
```javascript
// In Console, manually trigger:
window.initiateDeepAnalyze({auto_llm: true, analyze_mode: 'basic'})
```

**Check Network tab (F12):**
- Look for POST to `/api/v1/assessments/deep_analyze`
- Status should be 200
- Response should have `assessment_id`

**If 4xx/5xx error:**
- Check server logs in terminal
- Verify API key in request headers

### Issue: "Status stuck on 'pending'"

**Diagnosis:**
```bash
# Check if assessment file was created
dir /s data\assessments\*assessment*.json
```

**Fixes:**
- Worker may not be running → Check `src/pipeline/deep_analyze_pipeline.py`
- Check server logs for errors
- Manually check status:
  ```bash
  curl http://localhost:8000/api/v1/assessments/{assessment_id}
  ```

### Issue: "No LLM summaries in output"

**Diagnosis:**
1. Verify Auto-LLM was checked in modal
2. Check assessment object:
   ```javascript
   fetch('/api/v1/assessments/' + window.currentAssessmentId)
     .then(r => r.json())
     .then(d => console.log('auto_llm:', d.options.auto_llm))
   ```

**Fixes:**
- If `auto_llm: false`, re-run with checkbox enabled
- Check `src/analysis/auto_llm.py` is imported correctly
- Verify `LLM_MOCK=1` in env (for testing without real LLM)

---

## Expected Performance

- **100 rows**: ~2-5 seconds (basic mode)
- **100 rows**: ~5-10 seconds (advanced mode with eBPF/PCAP)
- **400 rows** (max): ~10-20 seconds

## Verification Checklist

After completing test:

- [ ] Modal appeared when clicking "Deep Analyze"
- [ ] Drawer showed pipeline progress
- [ ] Status changed from "pending" to "completed"
- [ ] GET /rows returned array with `llm_summary` field
- [ ] Each row has `verdict`, `risk_level`, `recommendation`
- [ ] Report exported to new tab
- [ ] Report includes MITRE heatmap
- [ ] Report includes DREAD bars
- [ ] Persona tabs change report content
- [ ] Copy buttons work

---

## API Testing (Alternative to UI)

If UI troubleshooting is difficult, test via API directly:

### 1. Start Analysis
```bash
curl -X POST http://localhost:8000/api/v1/assessments/deep_analyze \
  -H "Content-Type: application/json" \
  -H "x-api-key: devkey123" \
  -d '{
    "rows": [
      {
        "row_index": 0,
        "raw": {
          "process_name": "powershell.exe",
          "file_path": "C:\\Windows\\System32\\powershell.exe",
          "host": "workstation-1",
          "user": "admin",
          "sha256": "abc123def456"
        }
      }
    ],
    "options": {"auto_llm": true},
    "analyze_mode": "basic",
    "org": "cyberstash"
  }'
```

Save the `assessment_id` from response.

### 2. Poll Status
```bash
curl http://localhost:8000/api/v1/assessments/{assessment_id} \
  -H "x-api-key: devkey123"
```

### 3. Get LLM Rows
```bash
curl http://localhost:8000/api/v1/assessments/{assessment_id}/rows \
  -H "x-api-key: devkey123"
```

### 4. Export Report
```bash
curl -X POST http://localhost:8000/api/v1/assessments/{assessment_id}/report \
  -H "Content-Type: application/json" \
  -H "x-api-key: devkey123" \
  -d '{
    "persona": "ciso",
    "company": "Cyberstash",
    "recipients": ["analyst@cyberstash.com"],
    "include_model": true,
    "max_rows": 50
  }'
```

---

## Success Criteria

✓ Deep Analyze completes without errors
✓ Per-row LLM output includes structured schema (verdict, risk_level, llm_summary, recommendation)
✓ Persona reports generate with MITRE/DREAD/Playbook sections
✓ API endpoints return expected JSON structure
✓ Frontend drawer updates in real-time
✓ Reports open in new tab with formatted HTML

---

## Next Actions

1. Complete this test with Cyberstash_csv2.xlsx
2. Document any issues in browser console / server logs
3. Share assessment_id and sample LLM row output
4. Review report HTML for persona tailoring
5. Consider integrating with CI/CD for automated analysis
