# Where Are the LLM Summaries? - Visual Guide

**Problem:** You clicked "Run Deep Analyze" or "Generate Next 25 LLM Summaries" but don't see any LLM summaries in the table.

**Root Cause:** The current CSV Analyzer UI does NOT show inline LLM summaries in the table. The "LLM" column only shows a checkmark (X) if a summary EXISTS, but doesn't display the actual text.

---

## 📊 CURRENT UI (What You're Seeing)

```
┌─────────────────────────────────────────────────────────────────┐
│  CSV Analyzer                                                    │
├─────────────────────────────────────────────────────────────────┤
│  [Choose file: Cyberslash_csv2.xlsx]  [Load]  [Deep Analyze]   │
│  [LLM Summaries: Top 25 ▼]  Est. cost: $0.075                  │
├─────────────────────────────────────────────────────────────────┤
│  Table:                                                          │
│                                                                  │
│  ┌───┬─────────┬──────────────┬─────────┬────────┬──────────┐  │
│  │LLM│ Process │ Path         │ SHA256  │Verdict │ Domain   │  │
│  ├───┼─────────┼──────────────┼─────────┼────────┼──────────┤  │
│  │   │ unknown │ c:\windows\..│ 6307... │SUSPICIO│ GENERIC  │  │ ← LLM column EMPTY
│  │   │         │              │         │        │ (30%)    │  │
│  └───┴─────────┴──────────────┴─────────┴────────┴──────────┘  │
│  │                                                             │  │
│  │  ▼ Expanded row details:                                   │  │
│  │     signals: novel_global                                  │  │
│  │     DREAD: 9                                               │  │
│  │                                                            │  │
│  │     [Fetch Explain] [Open Full Details]                   │  │
│  │     [Per-row Deep Explain] [View Attack Path]             │  │ ← These buttons
│  │     [Copy Summary]                          │  │
│  │                                                            │  │
│  │     Threat Intel: [VT Portal] • [OTX]                      │  │
│  └────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

**THE PROBLEM:**
- ❌ No LLM summary text visible in the table
- ❌ No obvious place to VIEW the summary after it's generated
- ❌ "LLM" column is always empty (should show X if summary exists)

---

## ✅ WHERE LLM SUMMARIES ACTUALLY GO (2 Places)

### Option 1: Per-Row Deep Explain Button (RECOMMENDED)

**What happens:**
1. Click **[Per-row Deep Explain]** button on an expanded row
2. Opens **csv_deep_analysis.html** in a new tab
3. Shows full Tier 2 analysis (60-147 lines) with LLM summary

```
After clicking [Per-row Deep Explain]:

┌────────────────────────────────────────────────────────┐
│  New Tab: csv_deep_analysis.html                       │
├────────────────────────────────────────────────────────┤
│                                                        │
│  🔴 SUSPICIOUS ARTIFACT DETECTED                       │
│                                                        │
│  Process: unknown                                      │
│  Host: N/A                                             │
│  SHA256: 6307543ad5664c3ba03c417c34471ce738bbc2ebe7940bf7│
│                                                        │
│  Verdict: SUSPICIOUS | DREAD: 9/10 | Factors: 1       │
│                                                        │
├────────────────────────────────────────────────────────┤
│                                                        │
│  📄 TIER 2 DEEP ANALYSIS                               │
│                                                        │
│  FOR: THREAT HUNTER | FORENSIC ANALYST                 │
│  DOMAIN: GENERIC (Confidence: 0.30)                    │
│                                                        │
│  ─────────────────────────────────────────────────     │
│                                                        │
│  SECTION 1: WHAT IS IT? WHY SUSPICIOUS?                │
│                                                        │
│  This is an unknown process with a novel_global signal │
│  detected. The process path suggests it may be...      │
│  [... continues for 60-147 lines ...]                  │
│                                                        │
│  SECTION 2: HISTORICAL CONTEXT ⚠️ CRITICAL!            │
│  ...                                                   │
│                                                        │
│  SECTION 3: ATTACK SCENARIO & BUSINESS IMPACT          │
│  ...                                                   │
│                                                        │
├────────────────────────────────────────────────────────┤
│                                                        │
│  🕸️ ATTACK CHAIN RECONSTRUCTION (HopGraph)             │
│  [Shows attack chain visualization]                    │
│                                                        │
├────────────────────────────────────────────────────────┤
│                                                        │
│  🤖 AI-POWERED INSIGHTS (On-Demand)                    │
│                                                        │
│  [Generate DREAD Scenarios]  [Generate Playbook]       │
│  [Generate Hunt Query]       [Generate Exec Summary]   │
│                                                        │
└────────────────────────────────────────────────────────┘

Cost shown: $0.003 (or $0.00 if using Ollama)
```

**This is where you SEE the full LLM-generated Tier 2 summary!**

---

### Option 2: Copy Summary Button

**What happens:**
1. Click **[Copy Summary]** button on an expanded row
2. Copies a pre-generated analyst summary to clipboard
3. Paste into notepad/email to view

**Example output:**
```
ANALYST SUMMARY:
Artifact: unknown (c:\windows\temp\isagentcrash7-6-2021 12-44-15.pm\isagenttr...)
SHA256: 6307543ad5664c3ba03c417c34471ce738bbc2ebe7940bf76af804...
Verdict: SUSPICIOUS
DREAD: 9
Signals: novel_global

This artifact exhibits suspicious characteristics and warrants investigation...
```

**Note:** This is NOT an LLM summary - it's a templated summary built from pipeline data.

---

## 🔧 HOW TO ACTUALLY GET LLM SUMMARIES

### Step-by-Step Flow:

```
┌─────────────────────────────────────────────────────────────┐
│  1. UPLOAD CSV                                              │
│     [Choose file] → Select Cyberslash_csv2.xlsx             │
│     [Load] ← Click                                          │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ↓
┌─────────────────────────────────────────────────────────────┐
│  2. WAIT FOR PIPELINE PROCESSING (10-30 seconds)            │
│     Status: "Showing 135 of 572 rows"                       │
│     Table populates with verdicts, DREAD scores, domains    │
│     LLM column: STILL EMPTY (no summaries yet)              │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ↓
┌─────────────────────────────────────────────────────────────┐
│  3. CLICK "Deep Analyze" BUTTON (Top toolbar)               │
│                                                             │
│     This opens "Deep Analyze Options" modal                 │
│                                                             │
│     ┌───────────────────────────────────────────────────┐  │
│     │ Deep Analyze Options                              │  │
│     │                                                   │  │
│     │ ⦿ Basic  ○ Advanced                               │  │
│     │ ☑ Auto-LLM                                        │  │
│     │                                                   │  │
│     │ LLM Summaries: Top 25 (DREAD-sorted) ▼           │  │
│     │ Est. cost: $0.075                                 │  │
│     │                                                   │  │
│     │ [Detected Columns & Mapping Preview]              │  │
│     │                                                   │  │
│     │              [Cancel]  [Run Deep Analyze]         │  │
│     └───────────────────────────────────────────────────┘  │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ↓
┌─────────────────────────────────────────────────────────────┐
│  4. CLICK "Run Deep Analyze" (Blue button)                  │
│                                                             │
│     Processing starts in right panel:                       │
│     • Telemetry pending...                                  │
│     • Stage timeline not started.                           │
│     • Canonical signals pending.                            │
│                                                             │
│     WAIT: 30-60 seconds for processing                      │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ↓
┌─────────────────────────────────────────────────────────────┐
│  5. DEEP ANALYZE COMPLETES                                  │
│                                                             │
│     Right panel shows:                                      │
│     • Provider: Detecting... ✓ Re-check                     │
│     • Telemetry pending... → DONE                           │
│     • Stage timeline not started → DONE                     │
│     • All Sanitized Rows → Green checkmark                  │
│     • [Export Report] button appears                        │
│                                                             │
│     BUT: LLM column STILL EMPTY in table!                   │
│          (This is normal - summaries not shown inline)      │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ↓
┌─────────────────────────────────────────────────────────────┐
│  6. TO VIEW LLM SUMMARY: Click on a Row                     │
│                                                             │
│     Click the ► arrow to expand any row                     │
│                                                             │
│     ┌───────────────────────────────────────────────────┐  │
│     │  signals: novel_global                            │  │
│     │  DREAD: 9 ▼                                        │  │
│     │                                                   │  │
│     │  [Fetch Explain] [Open Full Details]              │  │
│     │  [Per-row Deep Explain] ← CLICK THIS              │  │
│     │  [View Attack Path] [Copy Summary]                │  │
│     └───────────────────────────────────────────────────┘  │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ↓
┌─────────────────────────────────────────────────────────────┐
│  7. NEW TAB OPENS: csv_deep_analysis.html                   │
│                                                             │
│     THIS IS WHERE YOU SEE THE LLM SUMMARY!                  │
│                                                             │
│     • Full Tier 2 analysis (60-147 lines)                   │
│     • Domain detection results                              │
│     • Historical context (if available)                     │
│     • HopGraph attack chain                                 │
│     • AI Insights buttons                                   │
│                                                             │
│     Processing time:                                        │
│     • Cloud API (Claude/GPT): 1-3 seconds                   │
│     • Ollama (CPU): 30-90 seconds  ← YOU'RE USING THIS      │
│                                                             │
│     IF OLLAMA: WAIT PATIENTLY! (30-90 sec first time)       │
└─────────────────────────────────────────────────────────────┘
```

---

## ❌ WHY "LLM" COLUMN IS EMPTY

The "LLM" column in csv_analyzer.html is SUPPOSED to show:
- **X** (or checkmark) if an LLM summary exists for that row
- **Empty** if no LLM summary has been generated yet

**Current Status:** The LLM summary generation is NOT integrated with the table display.

**What Should Happen:**
```
After Deep Analyze completes:

┌───┬─────────┬──────────────┬─────────┬────────┐
│LLM│ Process │ Path         │ SHA256  │Verdict │
├───┼─────────┼──────────────┼─────────┼────────┤
│ X │ unknown │ c:\windows\..│ 6307... │SUSPICIO│ ← X means summary exists
│ X │ unknown │ c:\windows\..│ aa2fa1..│SUSPICIO│ ← X means summary exists
│   │ svchost │ c:\windows\..│ bba3f2..│PASS    │ ← Empty (not in Top 25)
└───┴─────────┴──────────────┴─────────┴────────┘
```

**Current Behavior:**
```
After Deep Analyze completes:

┌───┬─────────┬──────────────┬─────────┬────────┐
│LLM│ Process │ Path         │ SHA256  │Verdict │
├───┼─────────┼──────────────┼─────────┼────────┤
│   │ unknown │ c:\windows\..│ 6307... │SUSPICIO│ ← Empty (even though summary exists!)
│   │ unknown │ c:\windows\..│ aa2fa1..│SUSPICIO│ ← Empty
│   │ svchost │ c:\windows\..│ bba3f2..│PASS    │ ← Empty
└───┴─────────┴──────────────┴─────────┴────────┘
```

**Why:** The LLM summaries are generated and stored server-side, but the table doesn't refresh to show the X indicator.

---

## 🎯 CORRECT USER FLOW (Working Method)

### For Ollama (What You're Using):

```
STEP 1: Upload CSV
↓
STEP 2: Click [Deep Analyze] (top toolbar)
↓
STEP 3: In modal:
        - Select "Basic" mode
        - Check ☑ Auto-LLM
        - Select "Top 25 (DREAD-sorted)"
        - Click [Run Deep Analyze]
↓
STEP 4: Wait 30-60 seconds for processing
        (Right panel shows "Sanitized Rows" when done)
↓
STEP 5: Click on a row to expand it (click ► arrow)
↓
STEP 6: Click [Per-row Deep Explain] button
↓
STEP 7: NEW TAB OPENS
        ⏱️ WAIT 30-90 SECONDS (Ollama is slow on CPU!)
        Browser shows "Loading..." or spinner
        DO NOT REFRESH OR CLOSE TAB!
↓
STEP 8: After 30-90 seconds, LLM summary appears:
        ┌─────────────────────────────────────────┐
        │ FOR: THREAT HUNTER | FORENSIC ANALYST   │
        │ DOMAIN: GENERIC (Confidence: 0.30)      │
        │                                         │
        │ SECTION 1: WHAT IS IT? WHY SUSPICIOUS?  │
        │ This is an unknown process with...      │
        │ [... 60-147 lines of analysis ...]      │
        │                                         │
        │ Cost: $0.00 (using Ollama - FREE!)      │
        └─────────────────────────────────────────┘
```

---

## 🐛 TROUBLESHOOTING

### Issue: "Per-row Deep Explain" Opens But Shows "Loading..." Forever

**Cause:** Ollama is taking too long (>60 seconds) or timed out

**Fix:**
1. Open browser console (F12)
2. Look for error messages
3. If timeout error, the model needs to be pre-warmed:

```bash
# In separate terminal:
curl -X POST http://127.0.0.1:11434/api/generate -d '{
  "model": "llama3:8b",
  "prompt": "Hello",
  "stream": false
}'

# Wait 60-90 seconds for first response
# Then try "Per-row Deep Explain" again
```

---

### Issue: "LLM" Column Never Shows X

**Cause:** Frontend not updated after Deep Analyze completes

**Workaround:**
1. Don't rely on the LLM column indicator
2. Just click [Per-row Deep Explain] on any row
3. If a summary was generated, it will load
4. If not, it will generate on-demand

---

### Issue: Button Says "Generate Next 25 LLM Summaries" But Where Are They?

**Answer:** This button is for BATCH generation. After clicking:
1. Summaries are generated server-side for Top 25 rows
2. They are NOT displayed in the table
3. You must click [Per-row Deep Explain] on each row to VIEW them
4. The LLM column SHOULD show X for rows with summaries (but currently doesn't)

---

## 📋 SUMMARY

**Where are LLM summaries?**
→ In **csv_deep_analysis.html** (new tab) after clicking **[Per-row Deep Explain]**

**Why aren't they in the table?**
→ Design decision: Summaries are 60-147 lines - too long for table cells

**What's the "LLM" column for?**
→ SUPPOSED to show X if summary exists, but currently broken/not updating

**How to see summaries?**
→ Expand row → Click **[Per-row Deep Explain]** → Wait 30-90 sec (Ollama)

**Cost?**
→ $0.00 (using Ollama local LLM - no API charges!)

---

## 🚀 QUICK TEST GUIDE

**Want to see an LLM summary RIGHT NOW?**

```bash
1. Open: http://localhost:8000/static/csv_analyzer.html
2. Upload: Cyberslash_csv2.xlsx
3. Wait: 30 seconds (table populates)
4. Click: Any row's ► arrow to expand
5. Click: [Per-row Deep Explain] button
6. WAIT: 30-90 seconds (Ollama is generating on CPU)
7. SUCCESS: Full LLM summary appears!
```

**Expected Output:**
- 60-147 lines of security analysis
- Domain classification (NETWORK/ENDPOINT/GENERIC)
- Attack scenarios
- Investigation playbook
- MITRE mapping
- Cost: $0.00

---

**The LLM summaries ARE working - they're just in a separate page, not in the table!**
