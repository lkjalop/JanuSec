# LLM Triage Implementation - Quick Status Report

**Date:** 2025-01-21
**Status:** ❌ **NOT IMPLEMENTED**

---

## 🎯 Bottom Line

**The 30-45 line LLM triage schema from `LLM_TRIAGE_SUMMARY_IMPLEMENTATION.md` is NOT yet implemented.**

Current implementation uses this basic prompt (line 24 in `auto_llm.py`):
```python
system = 'You are a concise security analyst. Summarize this single row for triage.'
```

This generates **unstructured, vague summaries** like:
> "Mock summary for solarwinds tftp server.exe: likely suspicious based on hashes and factors."

**Not actionable for SOC analysts.**

---

## 📊 Test Results: 3 Suspicious Rows from Cyberstash

**Dataset:** `dump/Cyberstash_csv2.xlsx`
- **Total rows:** 572
- **Suspicious rows:** 130
- **Selected for testing:** 3 high-interest artifacts

### Row 1: snippingtool.exe
- **Type:** Signed Microsoft binary (Windows Snipping Tool)
- **Risk:** LOW (false positive - 1/78 AV detections)
- **Priority:** DREAD 2.1

### Row 2: tmrestoreapp.exe
- **Type:** Unsigned Epson printer utility
- **Risk:** MEDIUM (unsigned third-party software, 1/69 AV detections)
- **Priority:** DREAD 5.4

### Row 3: solarwinds tftp server.exe ⚠️
- **Type:** SolarWinds TFTP Server (unsigned)
- **Risk:** HIGH (supply chain concern - SolarWinds involved in 2020 SUNBURST attack)
- **ThreatScore:** 4 (vs 0 for others)
- **Priority:** DREAD 8.7

---

## 📋 What SHOULD Happen (Mock Output)

**For Row 3: solarwinds tftp server.exe**

### Current Output (What You Get Now):
```
Mock summary for solarwinds tftp server.exe: likely suspicious based on hashes and factors.
```

**Lines:** 1
**Actionable?** ❌ No
**Analyst decision time:** 20 minutes (manual investigation)

---

### Proposed Output (After Implementation):
```
╔═══════════════════════════════════════════════════════════════════╗
║ Row 3: solarwinds tftp server.exe (DREAD 8.7) - HIGH RISK        ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║ 📌 WHAT IS IT?                                                    ║
║ SolarWinds TFTP Server (Trivial File Transfer Protocol daemon).  ║
║ Unsigned binary. Company involved in 2020 SUNBURST supply chain  ║
║ attack. ThreatScore=4 + 1 AV detection warrants investigation.   ║
║                                                                   ║
║ 💥 EXPLOITABILITY                                                 ║
║ Attacker can use this to:                                        ║
║ • Exfiltrate files via TFTP (UDP port 69, often bypasses FW)     ║
║ • Upload malicious payloads to other network devices             ║
║ • Supply chain risk: If compromised variant, C2 communication    ║
║                                                                   ║
║ ⚡ WHAT TO DO?                                                    ║
║ 1. URGENT: Verify SHA256 against SolarWinds official hash        ║
║ 2. Check network logs for TFTP traffic (UDP 69) to external IPs  ║
║ 3. Review process lineage: Who installed? When? Authorized?      ║
║ 4. If unverified, isolate host + forensic analysis               ║
║                                                                   ║
║ 📋 CONCISE PLAYBOOK                                               ║
║ Step 1: Get-FileHash -Algorithm SHA256 "C:\...\tftp server.exe"  ║
║         Compare to: https://support.solarwinds.com/sha256-hashes ║
║ Step 2: Get-WinEvent -FilterHashtable @{LogName='Security';      ║
║         Id=4688} | Where {$_.Message -like '*solarwinds*'}       ║
║ Step 3: netstat -ano | findstr :69  # Check if TFTP port active  ║
║ Step 4: If hash mismatch OR unexpected network activity →        ║
║         Isolate host + escalate to IR team                       ║
║                                                                   ║
║ ⚠️ MISSING LOGS (IF suspected)                                   ║
║ [21-stage pipeline detected supply chain risk + threatScore=4]   ║
║ • No EDR/Sysmon logs - can't see parent process or install time  ║
║ • No firewall logs - can't confirm if TFTP is actively used      ║
║ • No hash validation baseline - can't auto-confirm legitimacy    ║
║ Collecting these would CONFIRM/DENY if backdoored or legit.      ║
║                                                                   ║
║ [🔍 Investigate Further - Open New Tab]                          ║
╚═══════════════════════════════════════════════════════════════════╝
```

**Lines:** 38
**Actionable?** ✅ YES
**Analyst decision time:** 30 seconds (glance → escalate)

---

## 📂 Implementation Status by File

### ❌ `src/analysis/auto_llm.py`
**Current (Line 24):**
```python
system = 'You are a concise security analyst. Summarize this single row for triage.'
user_prompt = f"{system}\nRow: {_json.dumps(row, default=str)}"
```

**Needed:**
- 30-45 line structured prompt template
- `should_include_missing_logs()` function (conditional logic)
- Metadata tracking: `_llm_processed`, `_llm_timestamp`, `_llm_model`, `_llm_cost`

**Estimated Time:** 1-2 hours

---

### ❌ `src/api/deep_analyze_endpoints.py`
**Current:**
- Has basic `_llm_processed` flag
- No prioritization logic

**Needed:**
- `prioritize_rows_for_llm(rows, limit=25)` function (sort by DREAD)
- `/api/v1/assessments/generate_llm_summaries` endpoint
- Batch processing with progress callback

**Estimated Time:** 2-3 hours

---

### ❌ `frontend/static/csv_analyzer.html`
**Current:**
- Has Deep Analyze modal
- No LLM-specific controls

**Needed:**
- `<select id="llmLimit">` dropdown (Top 25/50/75/All)
- `<span id="llmCostEstimate">` cost display
- `<button id="btnGenerateMore">` on-demand summaries
- ✅/⏸️ visual indicators in table

**Estimated Time:** 2-3 hours

---

### ⚠️ `frontend/static/csv_deep_analysis.html`
**Current:**
- EXISTS (basic page with DREAD/MITRE frameworks)
- Shows row data

**Needed:**
- Redesign for progressive disclosure (free sections + paid AI insights)
- AI-powered insights section with on-demand LLM calls
- Running cost tracker per row
- Analyst notes + Save/Escalate/FalsePositive buttons

**Estimated Time:** 3-4 hours

---

### ❌ `src/analysis/cost_tracker.py`
**Current:**
- DOES NOT EXIST

**Needed:**
- `ExternalLLMCostTracker` class (track tokens + $$)
- `LocalLLMTracker` class (track GPU time, no $$)
- `/api/v1/metrics/llm_costs` endpoint

**Estimated Time:** 2-3 hours

---

## ⏱️ Total Implementation Time

**10-15 hours** (can be split across multiple sessions)

---

## 🚀 Priority Order

### Phase 1 (CRITICAL): Core LLM Prompt
**File:** `src/analysis/auto_llm.py`
**Time:** 1-2 hours
**Impact:** Foundation for all other features

**GitHub Copilot Prompt:**
```
Update src/analysis/auto_llm.py line 24 to implement 30-45 line structured prompt.

Replace:
  system = 'You are a concise security analyst. Summarize this single row for triage.'

With:
  system = '''You are a SOC analyst performing FAST TRIAGE. Analyze this artifact and provide a 30-45 line summary.

OUTPUT FORMAT:
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

⚠️ MISSING LOGS (3-5 lines - IF suspected):
[Only if correlation_score > 0.5 or attack patterns detected]
• [Missing log 1] - would confirm/deny [specific suspicion]
'''

Add function should_include_missing_logs(row, pipeline_context):
  - Check correlation_score > 0.5
  - Check attack_patterns for ['c2', 'lateral_movement', 'persistence']
  - Return bool

Add metadata after LLM call:
  row['_llm_processed'] = True
  row['_llm_timestamp'] = datetime.utcnow().isoformat()
  row['_llm_model'] = model_name
  row['_llm_cost'] = cost (or 0 for local GPU)
```

---

### Phase 2 (HIGH): Prioritization Logic
**File:** `src/api/deep_analyze_endpoints.py`
**Time:** 2-3 hours
**Impact:** Cost control (process Top 25 instead of all 150)

**GitHub Copilot Prompt:**
```
Add to src/api/deep_analyze_endpoints.py:

Function prioritize_rows_for_llm(rows, limit=25):
  1. Filter suspicious rows (verdict in ['SUSPICIOUS', 'CRITICAL', 'HIGH'])
  2. Sort by DREAD score (descending)
  3. Return top N rows

Endpoint POST /api/v1/assessments/generate_llm_summaries:
  Request: { row_indices: [0, 1, 2, ...], limit: 25 }
  Response: { rows: [...with llm_summary], count: 25 }

Logic:
  1. Filter rows without _llm_processed flag
  2. Call prioritize_rows_for_llm()
  3. Generate summaries for top N (call auto_llm.py)
  4. Mark _llm_processed = True
  5. Return updated rows
```

---

### Phase 3 (MEDIUM): Frontend UI
**Files:** `csv_analyzer.html`, `csv_deep_analysis.html`
**Time:** 5-7 hours
**Impact:** User experience improvements

**GitHub Copilot Prompt:**
```
Update frontend/static/csv_analyzer.html:

1. Add LLM controls after "Deep Analyze Options":
   <select id="llmLimit">
     <option value="25">Top 25 (DREAD sorted)</option>
     <option value="50">Top 50</option>
     <option value="75">Top 75</option>
     <option value="0">All suspicious rows</option>
   </select>
   <span id="llmCostEstimate">Est. cost: $0.075</span>

2. Add button:
   <button id="btnGenerateMore" style="display:none;">
     Generate Next 25 LLM Summaries
   </button>

3. Update table rendering:
   - Add ✅ icon if row._llm_processed
   - Add ⏸️ icon if pending
   - Tooltip: "LLM summary generated at [timestamp]" or "No LLM summary yet"

4. Wire btnGenerateMore to POST /api/v1/assessments/generate_llm_summaries
```

---

### Phase 4 (LOW): Cost Tracking
**File:** `src/analysis/cost_tracker.py`
**Time:** 2-3 hours
**Impact:** Visibility into LLM costs

**GitHub Copilot Prompt:**
```
Create src/analysis/cost_tracker.py with:

1. ExternalLLMCostTracker class:
   - track_call(row_index, model, input_tokens, output_tokens, cost)
   - get_summary() → {total_calls, total_cost, models: {...}}
   - export_csv(filepath)

2. LocalLLMTracker class:
   - track_call(row_index, model, input_tokens, output_tokens, gpu_time_ms)
   - get_summary() → {total_calls, total_gpu_time_sec}
   - NOTE: cost always 0 for local

3. Integrate with auto_llm.py:
   - After LLM call, check if external API or local
   - Track accordingly

4. Add endpoint GET /api/v1/metrics/llm_costs
```

---

## 💰 Expected ROI

### Before (Current State)
- ❌ Vague summaries: "likely suspicious based on hashes and factors"
- ❌ Analyst spends 20 minutes per alert (manual investigation)
- ❌ Processes all 150 alerts upfront ($0.45, 5 min latency)
- ❌ No cost visibility

### After (Fully Implemented)
- ✅ Structured 30-45 line summaries with actionable playbooks
- ✅ Analyst spends 30 seconds per alert (glance → decide)
- ✅ Processes Top 25 by default ($0.075, 50s latency) - **83% cost savings**
- ✅ "Generate More" on-demand for remaining alerts
- ✅ Cost tracking (external API vs local GPU)

### Business Impact
- **Triage speed:** 20 min/alert → 30 sec/alert (**40x faster**)
- **Cost reduction:** $0.45 → $0.075 for 150 alerts (**83% savings**)
- **Analyst throughput:** 3 alerts/hour → 120 alerts/hour
- **Escalation quality:** Clear playbooks reduce guesswork

---

## 📄 Full Details

See **`LLM_IMPLEMENTATION_VERIFICATION_REPORT.md`** for:
- Complete mock outputs (3 example rows)
- 200+ line "Investigate Further" tab mockup
- Detailed testing checklist
- File-by-file implementation status

---

## ✅ Next Steps

1. **Review this summary + detailed report**
2. **Approve Phase 1** (Core LLM Prompt) - 1-2 hours
3. **Use GitHub Copilot prompts** from this doc to implement
4. **Test with 3 suspicious rows** from Cyberstash file
5. **Verify no hallucinations** in LLM output
6. **Get CEO approval:** "Is this what you wanted?"
7. **Roll out Phases 2-4** (prioritization + UI + cost tracking)

---

**Report Generated:** 2025-01-21
**Test Dataset:** `dump/Cyberstash_csv2.xlsx` (572 rows, 130 suspicious)
**Status:** ❌ NOT IMPLEMENTED (10-15 hours remaining)
