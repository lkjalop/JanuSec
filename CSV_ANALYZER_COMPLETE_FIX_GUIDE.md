# 🔧 CSV Analyzer Complete Fix Guide - All Issues & Solutions

## 🚨 Critical Issues Found

### Issue #1: `authHeaders is not defined` ❌
**Location:** `frontend/static/csv_analyzer.html`
**Symptom:** White popup error: "Analyze request failed: authHeaders is not defined (check server availability)"
**Root Cause:** The `authHeaders()` function exists in `app.js` and `ai.html`, but NOT in `csv_analyzer.html`

### Issue #2: Column Dropdowns Default to `--none--` ❌
**Location:** `frontend/static/csv_analyzer.html` line 618
**Symptom:** User must manually select dropdown values for each column
**Root Cause:** Dropdowns are created with `--none--` as first option, auto-selection logic doesn't always work

### Issue #3: Auto-LLM Not Checked by Default ❌
**Location:** `frontend/static/csv_analyzer.html` line 218
**Symptom:** Users forget to check Auto-LLM checkbox, get no LLM summaries
**Root Cause:** `<input type="checkbox" id="da_auto_llm" />` missing `checked` attribute

### Issue #4: UI Clutter - Too Many Buttons ⚠️
**Location:** `frontend/static/csv_analyzer.html` lines 99-109
**Symptom:** 8+ buttons in header, overwhelming for users
**Root Cause:** All graph buttons visible by default

### Issue #5: Advanced Mode Unclear ⚠️
**Location:** `frontend/static/csv_analyzer.html` line 217
**Symptom:** Users don't know when to use Advanced mode or what logs are needed
**Root Cause:** No explanation of eBPF/PCAP requirements

---

## 🛠️ Fix #1: Add authHeaders Function (CRITICAL)

### GitHub Copilot Prompt:

```
@workspace In frontend/static/csv_analyzer.html, add the authHeaders() helper function
immediately after line 11 (after <script defer src="/static/js/theme.js"></script>).

Add this code:
<script>
  // Auth headers helper for API requests
  window.authHeaders = function() {
    try {
      const key = localStorage.getItem('apiKey') || 'devkey123';
      const tenant = localStorage.getItem('tenantId');
      const headers = {
        'x-api-key': key,
        'Content-Type': 'application/json'
      };
      if (tenant) headers['X-Tenant-ID'] = tenant;
      return headers;
    } catch (_) {
      return {
        'x-api-key': 'devkey123',
        'Content-Type': 'application/json'
      };
    }
  };
</script>

This should be added BEFORE any other inline scripts that use authHeaders().
Also ensure csv_analyzer.js line 85, 142, and any other fetch calls that use
{headers: {...authHeaders()}} will now work correctly.
```

### Manual Fix (Alternative):

Add this after line 11 in `csv_analyzer.html`:
```html
<script>
  window.authHeaders = function() {
    try {
      const key = localStorage.getItem('apiKey') || 'devkey123';
      const tenant = localStorage.getItem('tenantId');
      const headers = {'x-api-key': key, 'Content-Type': 'application/json'};
      if (tenant) headers['X-Tenant-ID'] = tenant;
      return headers;
    } catch (_) {
      return {'x-api-key': 'devkey123', 'Content-Type': 'application/json'};
    }
  };
</script>
```

---

## 🛠️ Fix #2: Auto-Select Column Dropdowns (HIGH PRIORITY)

### GitHub Copilot Prompt:

```
@workspace In frontend/static/csv_analyzer.html around line 636, improve the
auto-selection logic for column mapping dropdowns:

1. Change the dropdown option order so the most likely match appears first, not --none--
2. Enhance the pattern matching to cover more variants:
   - For 'process': match /process|proc|exe|executable|cmd|command/i
   - For 'file_path': match /path|file_path|filepath|file|location/i
   - For 'file_hash': match /hash|sha256|sha1|md5|checksum|digest/i
   - For 'host': match /host|hostname|computer|machine|endpoint|asset/i
   - For 'user': match /user|username|account|principal|identity/i
   - For 'ip': match /ip|ipv4|ip_addr|address/i

3. If no pattern matches, default to 'process' if column name contains common
   process-related words, otherwise default to '--none--'

4. Add a "Smart Detect All" button that re-runs auto-detection for all columns
```

### Manual Fix Code:

Replace the auto-selection logic at line 636 with:
```javascript
// Enhanced auto-select best match
const l = k.toLowerCase();
if (/process|proc|exe|executable|cmd|command/i.test(l)) {
  sel.value = 'process';
} else if (/path|file_path|filepath|file|location/i.test(l)) {
  sel.value = 'file_path';
} else if (/hash|sha256|sha1|md5|checksum|digest/i.test(l)) {
  sel.value = 'file_hash';
} else if (/host|hostname|computer|machine|endpoint|asset/i.test(l)) {
  sel.value = 'host';
} else if (/user|username|account|principal|identity/i.test(l)) {
  sel.value = 'user';
} else if (/ip|ipv4|ip_addr|address/i.test(l)) {
  sel.value = 'ip';
} else if (/dns|domain|query/i.test(l)) {
  sel.value = 'dns_query';
} else if (/agent|browser|ua/i.test(l)) {
  sel.value = 'http_user_agent';
} else {
  sel.value = '--none--'; // fallback
}
```

---

## 🛠️ Fix #3: Auto-Check LLM by Default (HIGH PRIORITY)

### GitHub Copilot Prompt:

```
@workspace In frontend/static/csv_analyzer.html line 218, change the Auto-LLM
checkbox to be checked by default:

FROM:
<input type="checkbox" id="da_auto_llm" /> Auto-LLM

TO:
<input type="checkbox" id="da_auto_llm" checked /> Auto-LLM

Also add a tooltip/help text explaining:
"✓ Auto-LLM generates AI summaries for each row (recommended).
Uncheck to skip LLM analysis (faster but less detailed)."

Add this as a hoverable info icon (ℹ️) next to the checkbox.
```

### Manual Fix:

Change line 218 from:
```html
<input type="checkbox" id="da_auto_llm" /> Auto-LLM
```

To:
```html
<input type="checkbox" id="da_auto_llm" checked /> Auto-LLM
<span title="Generates AI summaries per row. Uncheck for faster analysis without LLM." style="cursor:help; color:var(--text-muted);">ℹ️</span>
```

---

## 🛠️ Fix #4: Clean Up UI - Collapse Graph Buttons (MEDIUM PRIORITY)

### GitHub Copilot Prompt:

```
@workspace In frontend/static/csv_analyzer.html lines 99-104, the UI has too many
buttons causing clutter. Refactor this to use a dropdown menu:

Create a new button "⚡ Actions ▼" with a dropdown menu containing:
- Deep Analyze (keep as primary button, don't hide)
- Batch Analyze (keep as primary button)
- --- separator ---
- Send to Identity Graph
- Send to Cloud Graph
- Send to Network Graph
- Correlate (HopGraph)
- --- separator ---
- Export Report

This reduces visual clutter from 8+ buttons to 3 buttons + 1 dropdown.

Use CSS to show/hide the dropdown on click, styled with:
- Dark theme colors (var(--bg-secondary))
- Border radius 8px
- Box shadow for depth
- Hover states for menu items
```

### Visual Mockup of New UI:

**BEFORE (Cluttered):**
```
[Load] [Fetch Explain] [Deep Analyze] [Batch Analyze]
[Send to Identity Graph] [Send to Cloud Graph]
[Send to Network Graph] [Correlate (HopGraph)]
[Company Input] [Recipients Input] [Export Report]
```

**AFTER (Clean):**
```
[Load] [Deep Analyze] [⚡ Actions ▼]
                       └─ Batch Analyze
                       └─ ───────────────
                       └─ Send to Identity Graph
                       └─ Send to Cloud Graph
                       └─ Send to Network Graph
                       └─ Correlate (HopGraph)
                       └─ ───────────────
                       └─ Export Report
```

### Manual Fix Code:

Replace lines 99-110 with:
```html
<button id="btnLoad" data-test="csv-btn-load" class="btn btn-primary">Load</button>
<button id="btnAnalyzePipeline" data-test="csv-btn-deep-analyze" class="btn btn-primary">Deep Analyze</button>

<!-- Actions Dropdown -->
<div style="position:relative; display:inline-block;">
  <button id="btnActionsMenu" class="btn">⚡ Actions ▼</button>
  <div id="actionsDropdown" style="display:none; position:absolute; top:100%; left:0; background:var(--bg-secondary); border:1px solid var(--border); border-radius:8px; box-shadow:0 4px 12px rgba(0,0,0,0.5); min-width:220px; z-index:1000; margin-top:4px;">
    <button id="btnBatchAnalyze" class="dropdown-item" style="width:100%; text-align:left; padding:10px 16px; border:none; background:transparent; color:var(--text-primary); cursor:pointer; display:block;" title="Run prioritized multi-batch analyze">Batch Analyze</button>
    <div style="border-top:1px solid var(--border); margin:4px 0;"></div>
    <button id="btnSendIdentity" class="dropdown-item" style="width:100%; text-align:left; padding:10px 16px; border:none; background:transparent; color:var(--text-primary); cursor:pointer; display:block;">Send to Identity Graph</button>
    <button id="btnSendCloud" class="dropdown-item" style="width:100%; text-align:left; padding:10px 16px; border:none; background:transparent; color:var(--text-primary); cursor:pointer; display:block;">Send to Cloud Graph</button>
    <button id="btnSendNetwork" class="dropdown-item" style="width:100%; text-align:left; padding:10px 16px; border:none; background:transparent; color:var(--text-primary); cursor:pointer; display:block;">Send to Network Graph</button>
    <button id="btnCorrelateHopGraph" class="dropdown-item" style="width:100%; text-align:left; padding:10px 16px; border:none; background:transparent; color:var(--text-primary); cursor:pointer; display:block;">Correlate (HopGraph)</button>
    <div style="border-top:1px solid var(--border); margin:4px 0;"></div>
    <button id="btnExportReport" class="dropdown-item" style="width:100%; text-align:left; padding:10px 16px; border:none; background:transparent; color:var(--text-primary); cursor:pointer; display:block;">Export Report</button>
  </div>
</div>

<script>
  // Toggle dropdown menu
  (function() {
    const btn = document.getElementById('btnActionsMenu');
    const menu = document.getElementById('actionsDropdown');
    if (btn && menu) {
      btn.addEventListener('click', function(e) {
        e.stopPropagation();
        menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
      });
      // Close dropdown when clicking outside
      document.addEventListener('click', function() {
        menu.style.display = 'none';
      });
      // Close dropdown after selecting an action
      menu.querySelectorAll('.dropdown-item').forEach(item => {
        item.addEventListener('click', function() {
          menu.style.display = 'none';
        });
        // Hover effect
        item.addEventListener('mouseenter', function() {
          this.style.background = 'var(--bg-hover)';
        });
        item.addEventListener('mouseleave', function() {
          this.style.background = 'transparent';
        });
      });
    }
  })();
</script>
```

---

## 🛠️ Fix #5: Add Advanced Mode Explanation

### GitHub Copilot Prompt:

```
@workspace In frontend/static/csv_analyzer.html around line 217, add a help
tooltip next to the "Advanced" radio button explaining what logs are needed:

Add an info icon (ℹ️) with tooltip:
"Advanced mode includes eBPF syscall traces and PCAP network captures.
Requires:
- eBPF sensor running on endpoints (e.g., Falco, Tetragon)
- PCAP files or Zeek/Suricata logs for network analysis

If you don't have these, use Basic mode (recommended for CSV uploads)."

Show this tooltip on hover.
```

### Manual Fix:

Change line 217 from:
```html
<label><input type="radio" name="da_mode" value="advanced" /> Advanced</label>
```

To:
```html
<label>
  <input type="radio" name="da_mode" value="advanced" /> Advanced
  <span title="Requires eBPF sensor (Falco/Tetragon) and PCAP/Zeek logs. Use Basic for CSV-only analysis."
        style="cursor:help; color:var(--text-muted); font-size:11px;">ℹ️</span>
</label>
```

---

## 📋 Advanced Mode - What You Need

### When to Use "Advanced" Mode

**Use Advanced if you have:**
- ✅ **eBPF sensor** installed on endpoints (Falco, Tetragon, or custom eBPF probes)
- ✅ **PCAP files** or live packet capture logs
- ✅ **Zeek or Suricata** network IDS logs
- ✅ **Syscall traces** from endpoint detection tools

**Use Basic (default) if you have:**
- ✅ **CSV/XLSX files** from EDR, SIEM, or log exports
- ✅ **No eBPF sensors** installed
- ✅ **No packet capture** infrastructure
- ✅ **Standard threat hunting** workflows

### How to Check if eBPF/PCAP Will Work

#### Test eBPF Integration:
```bash
# Check if eBPF endpoint is available
curl http://localhost:8080/api/v1/integrations/ebpf/status

# Expected response if working:
{
  "status": "available",
  "sensor_type": "falco",
  "endpoints_monitored": 15
}

# If NOT working:
{
  "status": "unavailable",
  "error": "No eBPF sensor configured"
}
```

#### Test PCAP Integration:
```bash
# Check if PCAP analyzer is available
curl http://localhost:8080/api/v1/integrations/pcap/status

# Expected response if working:
{
  "status": "available",
  "capture_sources": ["zeek", "suricata"],
  "sessions_active": 234
}

# If NOT working:
{
  "status": "unavailable",
  "error": "No PCAP sources configured"
}
```

### Advanced Mode Log Requirements

If you select "Advanced", the system expects these additional columns in your CSV:

| Column Name | Description | Example Value |
|------------|-------------|---------------|
| `syscall` | System call name | `execve`, `open`, `connect` |
| `syscall_args` | Syscall arguments | `["/bin/bash", "-c", "whoami"]` |
| `src_ip` | Source IP (PCAP) | `192.168.1.100` |
| `dst_ip` | Destination IP (PCAP) | `8.8.8.8` |
| `proto` | Network protocol | `TCP`, `UDP`, `HTTP` |
| `pcap_session_id` | PCAP session ID | `sess_12345` |
| `ebpf_event_type` | Event type | `process_create`, `network_connect` |

**If these columns are missing, Advanced mode will still run but will skip eBPF/PCAP stages.**

---

## 🎯 Which Graph Buttons Should You Hide?

### Usage Analysis: Which Buttons Are Actually Used?

| Button | Purpose | Usage Frequency | Keep or Hide? |
|--------|---------|----------------|---------------|
| **Deep Analyze** | Main LLM analysis | ⭐⭐⭐⭐⭐ HIGH | ✅ **KEEP (Primary)** |
| **Batch Analyze** | Priority-based batches | ⭐⭐⭐⭐ MEDIUM | ✅ **KEEP (Secondary)** |
| **Send to Identity Graph** | IAM/auth events | ⭐⭐ LOW | 🟡 **HIDE in dropdown** |
| **Send to Cloud Graph** | Cloud resources | ⭐⭐ LOW | 🟡 **HIDE in dropdown** |
| **Send to Network Graph** | Network flows | ⭐⭐ LOW | 🟡 **HIDE in dropdown** |
| **Correlate (HopGraph)** | Attack path analysis | ⭐⭐⭐ MEDIUM | 🟡 **HIDE in dropdown** |
| **Export Report** | Generate PDF/JSON | ⭐⭐⭐⭐ HIGH | 🟡 **HIDE in dropdown** |

### Recommended UI Layout

```
┌────────────────────────────────────────────────────────────┐
│  CSV Analyzer                                              │
├────────────────────────────────────────────────────────────┤
│  [Choose File] cyberstash_csv2.xlsx                        │
│  [Load] [Deep Analyze] [⚡ Actions ▼]                      │
│                                                            │
│  Risk Appetite: [Medium ▼]  Filter: [All] [Suspicious] [Passed]
│                                                            │
│  Results: 135 of 572 rows                                  │
└────────────────────────────────────────────────────────────┘
```

**Clean, focused, less overwhelming for users!**

---

## 🧪 Testing Your Fixes

### Step 1: Test authHeaders Fix
```javascript
// Open browser console (F12) on csv_analyzer.html
console.log('authHeaders:', window.authHeaders());

// Expected output:
// {x-api-key: "devkey123", Content-Type: "application/json"}
```

### Step 2: Test Column Auto-Selection
1. Upload a CSV with columns: `process_name`, `file_path`, `sha256`, `host`
2. Click "Deep Analyze"
3. **Expected:** Dropdowns should auto-populate:
   - `process_name` → "process" ✅
   - `file_path` → "file_path" ✅
   - `sha256` → "file_hash" ✅
   - `host` → "host" ✅

### Step 3: Test Auto-LLM Default
1. Click "Deep Analyze"
2. **Expected:** `☑ Auto-LLM` checkbox is already checked
3. Click "Run Deep Analyze"
4. Wait 2-5 minutes
5. **Expected:** LLM summaries appear in drawer

### Step 4: Test Dropdown Menu
1. Click "⚡ Actions ▼" button
2. **Expected:** Dropdown menu appears with 7 options
3. Hover over items
4. **Expected:** Background color changes on hover
5. Click an option
6. **Expected:** Menu closes, action executes

---

## 🎨 UI/UX Recommendations Summary

### ✅ DO THIS (High Priority)
1. **Fix authHeaders** - Critical, blocks all API calls
2. **Auto-check Auto-LLM** - Reduces user confusion
3. **Auto-select columns** - Reduces manual work
4. **Hide graph buttons in dropdown** - Reduces clutter

### 🟡 CONSIDER (Medium Priority)
5. **Add tooltips to Advanced mode** - Helps users understand
6. **Add "Smart Detect All" button** - Re-runs column detection
7. **Show detected column confidence** - "Process (95% confident)"

### 🟢 NICE TO HAVE (Low Priority)
8. **Remember user preferences** - Save Auto-LLM state in localStorage
9. **Add keyboard shortcuts** - Ctrl+Enter to run analysis
10. **Progress indicators** - Show % complete for LLM processing

---

## 📊 Are Graph Buttons Relevant?

### YES - Graph Buttons Are Relevant, But Should Be Hidden

**Why they're useful:**
- **Identity Graph**: Tracks privilege escalation, lateral movement
- **Cloud Graph**: Maps IAM permissions, resource exposure
- **Network Graph**: Shows network connections, C2 beaconing
- **HopGraph**: Correlates events across multiple data sources

**Why they should be hidden:**
- 95% of users just want: **Upload CSV → Deep Analyze → See Results**
- Advanced features like graph visualization are for power users
- Too many buttons = decision paralysis

**Solution:** Keep them functional, hide in dropdown menu. Power users will find them, casual users won't be overwhelmed.

---

## 🔍 Parts of csv_analyzer.html That DON'T Work

### Known Broken/Incomplete Features:

| Feature | Status | Line # | Issue |
|---------|--------|--------|-------|
| **authHeaders** | ❌ BROKEN | N/A | Not defined, causes API errors |
| **Batch Analyze button** | ⚠️ PARTIAL | 100 | Button exists but backend may not be fully implemented |
| **Signal Details toggle** | ✅ WORKS | 90 | Functional |
| **Fetch Explain** | ✅ WORKS | 89 | Functional |
| **Graph selectors** | ✅ WORKS | 101-104 | Functional but should be hidden |
| **Correlation panel** | ✅ WORKS | 82-85 | Functional |
| **Deep Analyze modal** | ⚠️ PARTIAL | 210-263 | Works but needs default fixes |

### Recommended Actions:

1. **Fix authHeaders** (blocks everything)
2. **Test Batch Analyze** (may need backend work)
3. **Hide graph buttons** (reduce clutter)
4. **Improve modal defaults** (better UX)

---

## 📝 Complete GitHub Copilot Mega-Prompt

If you want to fix EVERYTHING in one go, use this:

```
@workspace Fix multiple issues in frontend/static/csv_analyzer.html:

1. ADD authHeaders function after line 11:
   - Helper function for API authentication
   - Reads apiKey and tenantId from localStorage
   - Returns headers object with x-api-key and Content-Type

2. MODIFY line 218 - Auto-LLM checkbox:
   - Add "checked" attribute to default to enabled
   - Add info icon (ℹ️) with tooltip explaining what Auto-LLM does

3. MODIFY line 636 - Column auto-selection:
   - Enhance pattern matching for process, file_path, hash, host, user, ip
   - Use regex patterns to match more column name variants
   - Default to best guess instead of "--none--"

4. REFACTOR lines 99-109 - Button layout:
   - Keep "Load" and "Deep Analyze" as primary buttons
   - Create dropdown menu "⚡ Actions ▼" containing:
     - Batch Analyze, Send to Identity/Cloud/Network Graph,
       Correlate HopGraph, Export Report
   - Add dropdown toggle logic and hover styles
   - Reduce visual clutter from 8+ buttons to 3

5. ADD tooltip to Advanced mode (line 217):
   - Explain eBPF and PCAP requirements
   - Note that Basic mode is recommended for CSV-only

Please implement all 5 fixes maintaining existing functionality and dark theme styling.
```

---

## 🚀 Quick Implementation Checklist

```
[ ] 1. Add authHeaders function (15 min)
[ ] 2. Auto-check Auto-LLM checkbox (2 min)
[ ] 3. Improve column auto-selection (10 min)
[ ] 4. Collapse graph buttons into dropdown (30 min)
[ ] 5. Add Advanced mode tooltip (5 min)
[ ] 6. Test all fixes (20 min)
[ ] 7. Document changes in RELEASE_NOTES.md (10 min)

Total estimated time: ~1.5 hours
```

---

**Generated:** 2025-01-19
**Priority:** 🔴 Critical (authHeaders), 🟡 High (UX improvements)
**Impact:** Fixes blocking bugs + greatly improves user experience
