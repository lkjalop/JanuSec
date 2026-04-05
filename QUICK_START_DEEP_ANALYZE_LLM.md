# 🚀 Quick Start: Get LLM Summary in 3 Steps

## The Modal That's Confusing You

When you click **"Deep Analyze"**, this modal pops up:

```
┌─────────────────────────────────────────────────────────────┐
│  Deep Analyze Options                          [Close]      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Mode: ◉ Basic    ○ Advanced                                │
│  ☐ Auto-LLM  ← ⚠️ YOU MUST CHECK THIS BOX FOR LLM!        │
│                                                              │
│  Basic: 20 signals; Advanced: full set (+eBPF/PCAP)        │
│                                                              │
│  Detected Columns:                                          │
│  ┌────────────────────────────────────────────────────┐    │
│  │ ☑ process_name → [--none--      ▼]                │    │
│  │ ☑ file_path    → [--none--      ▼]                │    │
│  │ ☑ sha256       → [--none--      ▼]                │    │
│  │ ☑ host         → [--none--      ▼]                │    │
│  └────────────────────────────────────────────────────┘    │
│                                                              │
│  [Cancel]  [Run Deep Analyze]                               │
└─────────────────────────────────────────────────────────────┘
```

---

## ⚡ STEP-BY-STEP: What to Do

### Step 1: Check "Auto-LLM" Box ✅
**THIS IS THE MOST IMPORTANT STEP!**

```
☑ Auto-LLM  ← Click this checkbox!
```

**Why?** Without this checked, you get NO LLM summaries. Just basic analysis.

---

### Step 2: Leave Mode as "Basic" (Default) ✅

```
◉ Basic    ○ Advanced
```

**What's the difference?**
- **Basic**: Fast, 20 core signals (Good for most cases)
- **Advanced**: Slower, includes eBPF + PCAP analysis (Only if you have those sensors)

**For your first test: Use Basic**

---

### Step 3: Map Your Columns (The Confusing Part!)

You'll see dropdowns like this:

```
☑ process_name → [--none-- ▼]
```

**What this means:**
- Your CSV has a column called "process_name"
- You need to tell the system what type of data this is
- Click the dropdown and select the matching type

---

## 📋 Column Mapping Cheat Sheet

### Common CSV Column → What to Select in Dropdown

| Your CSV Column Name | Select in Dropdown | Why |
|---------------------|-------------------|-----|
| `process_name` | → **process** | Executable name |
| `process` | → **process** | Executable name |
| `file_path` | → **file_path** | Full path to file |
| `path` | → **file_path** | Full path to file |
| `sha256` | → **file_hash** | File hash/signature |
| `hash` | → **file_hash** | File hash/signature |
| `md5` | → **file_hash** | File hash/signature |
| `host` | → **host** | Computer/machine name |
| `hostname` | → **host** | Computer/machine name |
| `computer` | → **host** | Computer/machine name |
| `user` | → **user** | Username/account |
| `username` | → **user** | Username/account |
| `account` | → **user** | Username/account |
| `ip` | → **ip** | IP address |
| `ip_address` | → **ip** | IP address |
| `dns_query` | → **dns_query** | DNS lookup |
| `http_user_agent` | → **http_user_agent** | Browser string |
| Anything else | → **--none--** | Skip this column |

---

## 🎯 Example: Your Cyberstash CSV

Based on your screenshot, you have:

```
┌─────────────────────────────────────────────────────────────┐
│  Detected Columns:                                          │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ ☑ process_name → [process       ▼]  ← Select "process" │ │
│  │ ☑ file_path    → [file_path     ▼]  ← Select "file_path"│ │
│  │ ☑ sha256       → [file_hash     ▼]  ← Select "file_hash"│ │
│  │ ☑ host         → [host          ▼]  ← Select "host"    │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**Good news!** The system auto-detects these. If it already shows the right value, **leave it as-is**.

---

## ✅ Final Checklist Before Clicking "Run Deep Analyze"

```
[✓] Auto-LLM is CHECKED ☑
[✓] Mode is "Basic" (or Advanced if you need it)
[✓] Columns are mapped correctly:
    - process_name → process
    - file_path → file_path
    - sha256 → file_hash
    - host → host
```

**Now click: [Run Deep Analyze]**

---

## 🎬 What Happens Next?

### 1. Right Drawer Opens (Processing)
```
┌──────────────────────────────────────┐
│ Deep Analyze Progress                │
│ ━━━━━━━━━━━━━━━━░░░░  45%          │
│                                      │
│ Started - assessment-1732024089...  │
│ Status: Processing rows...           │
│                                      │
│ Stages Complete:                     │
│ ✓ GeoIP                             │
│ ✓ ThreatIntel                       │
│ ⏳ LLMSummary (Running...)           │
│                                      │
│ Rows Processed: 67 / 135            │
└──────────────────────────────────────┘
```

**Wait time:**
- Without LLM: ~10-30 seconds
- **With LLM (Auto-LLM checked)**: ~2-5 minutes for 100 rows

---

### 2. LLM Summaries Appear (SUCCESS!)
```
┌──────────────────────────────────────────────────────────────┐
│ 🎯 PRIORITY ROWS - Review Critical First                    │
│                                                              │
│ ┌──────────────────────────────────────────────────────┐   │
│ │ #1  CRITICAL | Risk: 9.2                             │   │
│ │ Process: unknown                                     │   │
│ │ Path: c:\windows\temp\fsagentcrash7-6-2021...       │   │
│ │                                                      │   │
│ │ 🤖 LLM SUMMARY:                                      │   │
│ │ "Unsigned executable in sensitive temp directory    │   │
│ │  with rare global signature. Multiple factors       │   │
│ │  indicate potential unauthorized software or        │   │
│ │  malware. High confidence match with T1036          │   │
│ │  (Masquerading) technique. Recommend immediate      │   │
│ │  quarantine and forensic analysis."                 │   │
│ │                                                      │   │
│ │ MITRE: T1036 (Masquerading)                         │   │
│ │ Recommendation: Quarantine                           │   │
│ │                                                      │   │
│ │ [Triage] [Escalate] [Dismiss] [Investigated]        │   │
│ │ Notes: ___________________________________           │   │
│ └──────────────────────────────────────────────────────┘   │
│                                                              │
│ ┌──────────────────────────────────────────────────────┐   │
│ │ #2  HIGH | Risk: 7.8                                 │   │
│ │ Process: msiezec.exe                                 │   │
│ │                                                      │   │
│ │ 🤖 LLM SUMMARY:                                      │   │
│ │ "System32 process with unsigned signature..."       │   │
│ └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

**That's your LLM summary!** ☝️ The text that starts with "🤖 LLM SUMMARY:"

---

## ❌ If You DON'T See LLM Summaries

### Problem 1: You Forgot to Check Auto-LLM
**Solution:** Close drawer, click "Deep Analyze" again, **CHECK ☑ Auto-LLM**, run again

### Problem 2: LLM Service Not Running
Check browser console (F12) for errors like:
```
"LLM not available"
"Connection refused to localhost:11434"  ← Ollama not running
```

**Solution:** Start Ollama or configure external AI API

### Problem 3: You See "Mock Summary" Instead of Real Analysis
Example:
```
LLM Summary: "Mock summary for unknown: likely suspicious based on hashes and factors."
```

**This means:** LLM is in fallback mode. Check:
```bash
# In your .env file or environment:
LLM_MOCK=0  ← Should be 0 or false, not 1
```

**Or in src/api/deep_analyze_endpoints.py line 108:**
```python
if os.getenv('LLM_MOCK','1') in {'1','true','yes'}:  # ← This is set to mock!
```

---

## 🔧 Quick Fix: Enable Real LLM

### Option A: Use Ollama (Local, Free)
```bash
# Install Ollama
https://ollama.ai/download

# Start Ollama
ollama serve

# Pull a model
ollama pull llama3.2
```

Then set in `.env`:
```bash
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
LLM_MOCK=0
```

### Option B: Use OpenAI API
In `.env`:
```bash
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-your-key-here
LLM_MOCK=0
```

### Option C: Use Claude API
In `.env`:
```bash
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-your-key-here
LLM_MOCK=0
```

---

## 📊 Visual Summary

```
┌─────────────────────────────────────────────────────────────┐
│                    THE 3 THINGS YOU NEED                    │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. ☑ Auto-LLM checkbox CHECKED                             │
│     └─ Without this: NO LLM summaries!                      │
│                                                              │
│  2. 📋 Columns mapped correctly                             │
│     └─ Usually auto-detected, just verify                   │
│                                                              │
│  3. 🔌 LLM service running (Ollama/OpenAI/Claude)           │
│     └─ Or accept "Mock" fallback summaries                  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎯 TL;DR - Absolute Minimum Steps

1. Click **"Deep Analyze"** button
2. **CHECK the ☑ Auto-LLM box** (THIS IS CRITICAL!)
3. Verify column mappings look reasonable
4. Click **"Run Deep Analyze"**
5. Wait 2-5 minutes
6. Look for "🤖 LLM SUMMARY:" in the drawer

**If you don't check Auto-LLM, you'll NEVER see LLM summaries!**

---

## 🆘 Still Stuck?

### Test if LLM is Working
Open browser console (F12) and run:
```javascript
fetch('/api/v1/assessments/deep_analyze', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    rows: [{process_name: 'test.exe', factors: ['lolbin']}],
    options: {auto_llm: true}
  })
})
.then(r => r.json())
.then(j => console.log('Assessment ID:', j.assessment_id))
```

Then check:
```javascript
fetch('/api/v1/assessments/{assessment_id}/rows')
.then(r => r.json())
.then(j => console.log('LLM Summary:', j.rows[0].llm_summary))
```

If you see `llm_summary` field, it's working!

---

**Updated:** 2025-01-19
**Your Next Step:** Click Deep Analyze → Check Auto-LLM → Run → Wait → See Summaries!
