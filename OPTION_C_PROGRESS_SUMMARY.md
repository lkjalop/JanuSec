# Option C - Progress Summary

**Date:** 2025-01-22
**Status:** Phase 1 Complete (60% overall)
**Next:** Phase 2 - Frontend & API Integration

---

## ✅ COMPLETED (Phase 1A-1C - 3.5 hours)

### 1. Domain Detection Function ✅
**File:** `src/analysis/auto_llm.py` (lines 57-148)
- `detect_domain_with_confidence()` function added
- Detects network vs endpoint with confidence scoring
- **Tested:** network (0.7), endpoint (0.85), generic (0.3)

### 2. Tier 2 Prompt Builder ✅
**File:** `src/analysis/auto_llm.py` (lines 151-398)
- `build_tier2_prompt()` function added (247 lines)
- Generates 60-147 line prompts with 8 sections:
  1. What is it? Why suspicious?
  2. Historical context (with past incidents)
  3. Attack scenario & business impact
  4. Step-by-step forensic collection playbook
  5. Required logs (MITRE-mapped)
  6. Decision criteria
  7. Full artifact data
  8. Pipeline enrichment
- **Integrations:**
  - ✅ Historical incidents repo (queries past 90 days)
  - ✅ Domain-specific tools (KAPE, Volatility, Wireshark, Zeek)
  - ✅ MITRE → logs mapping (T1055 → Sysmon Event 10)
  - ✅ Correlation context enrichment

### 3. Dual-Tier Support ✅
**File:** `src/analysis/auto_llm.py` (lines 406-417)
- Updated `summarize_row()` method
- **Tier 1:** Default, 30-45 lines, fast triage
- **Tier 2:** `context['tier'] = 'tier2'`, 60-100+ lines, deep investigation
- Automatic routing based on context parameter

### 4. Historical Incidents Database ✅
**File:** `scripts/seed_historical_incidents.py` (168 lines)
- Script created and successfully executed
- **Database:** `janusec_dev.db` table `historical_incidents`
- **5 incidents seeded:**
  1. powershell.exe (14 days ago) - **confirmed_malicious** - Emotet dropper
  2. svchost.exe (28 days ago) - false_positive - Windows Update
  3. chrome.exe (45 days ago) - confirmed_malicious - Malvertising
  4. mimikatz.exe (7 days ago) - confirmed_malicious - Credential dumping
  5. taskmgr.exe (60 days ago) - benign - Helpdesk session
- **Verified:** Query test successful, found 1 match for powershell.exe SHA256

---

## 🎯 TIER 2 PROMPT DEMO OUTPUT

**Test Case:** powershell.exe with process_injection on WORKSTATION-042

**Generated Prompt Stats:**
- **Total Lines:** 147 (target: 60-100, acceptable with JSON data)
- **Sections:** 8 complete sections
- **Domain Detection:** ENDPOINT (confidence: 0.85) ✅
- **Historical Match:** Found Emotet incident from 14 days ago ✅
- **Auto-Escalation:** "CRITICAL: Previous instance was CONFIRMED MALICIOUS" ✅
- **Tools Provided:** KAPE, RegRipper, Volatility, FTK Imager ✅
- **Logs Mapped:** T1055 → Sysmon 10, T1059.001 → PowerShell 4104 ✅

**Key Output Snippet:**
```
SECTION 2: HISTORICAL CONTEXT (CRITICAL!)
⚠️ WARNING: Similar incidents detected in past 90 days:

  Incident #1 (14 days ago):
    - Outcome: CONFIRMED_MALICIOUS
    - Process: powershell.exe
    - Host: WORKSTATION-042
    - Notes: Emotet dropper. Injected into explorer.exe, established C2...

DECISION IMPACT:
  ⛔ CRITICAL: Previous instance was CONFIRMED MALICIOUS
  ⛔ Recommendation: Auto-escalate to Tier 3, isolate host immediately
```

---

## 📋 REMAINING WORK (8 hours)

### Phase 1D: Add Domain Badges to UI (30 min)
**File to Modify:** `frontend/static/csv_analyzer.html`
- [ ] Add `detectDomainFrontend()` JavaScript function
- [ ] Add domain column to table header
- [ ] Add badge rendering in table body
- [ ] Add CSS styling for badges

**Visual Output:**
```
| Process Name    | Verdict    | Domain          |
|----------------|------------|-----------------|
| powershell.exe | suspicious | ENDPOINT (85%)  | <- Green badge
| svchost.exe    | suspicious | NETWORK (70%)   | <- Blue badge
| taskmgr.exe    | benign     | GENERIC (30%)   | <- Gray badge
```

### Phase 2A: HopGraph Integration (1.5 hours)
**File to Create:** `src/core/graph/hopgraph_integration.py` (NEW - 250 lines)
- [ ] Implement `query_attack_graph()` function
- [ ] Implement `_generate_fallback_graph()` for demo
- [ ] Returns: nodes, edges, paths, timeline, correlation_explanation

**Output Format:**
```json
{
  "nodes": [
    {"id": "n1", "type": "process", "label": "explorer.exe", "risk_score": 2.0},
    {"id": "n2", "type": "process", "label": "powershell.exe", "risk_score": 8.5},
    {"id": "n3", "type": "network", "label": "185.220.101.45:443", "risk_score": 9.0}
  ],
  "edges": [
    {"source": "n1", "target": "n2", "type": "spawned"},
    {"source": "n2", "target": "n3", "type": "connected"}
  ],
  "paths": [{"nodes": ["n1", "n2", "n3"], "description": "Initial access → Execution → C2"}]
}
```

### Phase 2B: Graph API Endpoint (30 min)
**File to Create:** `src/api/graph_endpoints.py` (NEW - 100 lines)
- [ ] Create POST `/api/v1/graph/attack_reconstruction` endpoint
- [ ] Create GET `/api/v1/graph/health` endpoint
- [ ] Register router in `src/api/server.py`

### Phase 2C: AI Insights Endpoints (1 hour)
**File to Create:** `src/api/insights_endpoints.py` (NEW - 200 lines)
- [ ] Create POST `/api/v1/insights/generate` endpoint
- [ ] Implement 4 insight types:
  - `dread`: DREAD scenario analysis ($0.001)
  - `playbook`: Investigation playbook ($0, uses domain_tools)
  - `hunt`: Threat hunting queries KQL/SPL/Sigma ($0.0008)
  - `executive`: Executive summary for CISO ($0.0005)
- [ ] Register router in `src/api/server.py`

### Phase 2D: Wire Frontend to APIs (1 hour)
**File to Modify:** `frontend/static/csv_deep_analysis.html`
- [ ] Update `loadAttackGraph()` to call `/api/v1/graph/attack_reconstruction`
- [ ] Add `renderHopGraph()` function to visualize graph data
- [ ] Update `generateInsight()` to call `/api/v1/insights/generate`
- [ ] Add `updateRunningCost()` function for cost tracking

### Phase 3: Testing (2 hours)
**Files to Create:**
- [ ] `tests/test_data/option_c_demo.csv` (10 diverse artifacts)
- [ ] `tests/test_option_c_integration.py` (6 test cases)

**Test Coverage:**
- [ ] Domain detection (network vs endpoint)
- [ ] Tier 2 prompt generation (60+ lines)
- [ ] Historical incidents query
- [ ] HopGraph integration
- [ ] Tier 2 with historical context included

### Phase 4: Demo Preparation (1.5 hours)
**Files to Create:**
- [ ] `docs/CEO_DEMO_SCRIPT.md` (comprehensive 15-20 min script)
- [ ] `docs/screenshots/` (5+ images)

**Demo Components:**
- [ ] Rehearse demo flow (time to 15-20 minutes)
- [ ] Prepare Q&A responses
- [ ] Create backup plan (screenshots if live demo fails)
- [ ] Test fallback scenarios

---

## 📊 COMPLETION METRICS

### Files Created/Modified So Far: 2
- ✅ `src/analysis/auto_llm.py` (modified - added 350+ lines)
- ✅ `scripts/seed_historical_incidents.py` (created - 168 lines)

### Files Remaining: 7
- `frontend/static/csv_analyzer.html` (modify)
- `src/core/graph/hopgraph_integration.py` (create - 250 lines)
- `src/api/graph_endpoints.py` (create - 100 lines)
- `src/api/insights_endpoints.py` (create - 200 lines)
- `frontend/static/csv_deep_analysis.html` (modify)
- `tests/test_data/option_c_demo.csv` (create)
- `tests/test_option_c_integration.py` (create)
- `docs/CEO_DEMO_SCRIPT.md` (create)

### Code Stats:
- **Written:** ~600 lines
- **Remaining:** ~800 lines
- **Total Project:** ~1,400 lines

### Time Investment:
- **Completed:** 3.5 hours (Phase 1)
- **Remaining:** 8 hours (Phases 2-4)
- **Total:** 11.5 hours

---

## 🎯 WHAT YOU CAN DEMO RIGHT NOW

Even without Phase 2-4, you can demonstrate:

### 1. Domain Detection (Backend Working)
```python
from src.analysis.auto_llm import detect_domain_with_confidence

# Test network artifact
network_row = {'factors': ['port_scan', 'beaconing'], 'src_ip': '10.0.0.5'}
print(detect_domain_with_confidence(network_row))
# Output: ('network', 0.7)

# Test endpoint artifact
endpoint_row = {'factors': ['process_injection'], 'process_name': 'malware.exe'}
print(detect_domain_with_confidence(endpoint_row))
# Output: ('endpoint', 0.85)
```

### 2. Tier 2 Prompts with Historical Context
```python
from src.analysis.auto_llm import build_tier2_prompt

test_row = {
    'process_name': 'powershell.exe',
    'sha256': '9bf41199f05fa1de8be5b84c6ef6e0a37f7b3d3f7a6e5d4c3b2a1f0e9d8c7b6a',
    'host': 'WORKSTATION-042',
    'factors': ['process_injection', 'unsigned_binary']
}

context = {
    'pipeline_context': {
        'dread_score': 8.5,
        'mitre_tags': ['T1055', 'T1059.001']
    }
}

prompt = build_tier2_prompt(test_row, context)
# Generates 147-line prompt with:
# - Domain detection (ENDPOINT)
# - Historical match (Emotet 14 days ago)
# - Auto-escalation recommendation
# - Domain-specific tools (KAPE, Volatility)
# - MITRE-mapped logs
```

### 3. Historical Incident Queries
```python
from src.repositories.historical_incidents_repo import HistoricalIncidentsRepo

repo = HistoricalIncidentsRepo()
results = repo.query_similar_incidents(
    {'sha256': '9bf41199f05fa1de8be5b84c6ef6e0a37f7b3d3f7a6e5d4c3b2a1f0e9d8c7b6a'},
    lookback_days=90
)
# Returns: [{'outcome': 'confirmed_malicious', 'analyst_notes': 'Emotet dropper...'}]
```

### 4. Show Saved Prompt Output
```bash
# Full 147-line Tier 2 prompt saved to:
cat tier2_prompt_demo.txt
```

---

## 🚀 RECOMMENDED NEXT STEPS

### Option A: Quick Visual Win (30 min)
**Do:** Phase 1D - Add domain badges to CSV Analyzer UI
**Benefit:** Immediate visual proof, impressive screenshots
**Result:** Can show CEO domain detection working in browser

### Option B: Complete Backend (3 hours)
**Do:** Phases 2A-2C (HopGraph + Graph API + Insights API)
**Benefit:** All backend features working, can test via curl/Postman
**Result:** Ready for frontend integration

### Option C: Full Implementation (8 hours)
**Do:** Phases 1D, 2A-2D, 3, 4
**Benefit:** Complete end-to-end demo with UI
**Result:** CEO-ready demo with screenshots and script

---

## 💡 RECOMMENDATION

**Start with Phase 1D (domain badges)** - it's only 30 minutes and gives you visual proof of domain detection working. Then decide:

- **If CEO is impatient:** Show screenshots of Tier 2 prompts + domain badges, schedule full demo for next week
- **If you have 1-2 days:** Complete Phases 2A-2D for full visual demo
- **If CEO can wait 1 week:** Complete all phases for polished demo with testing

---

**All implementation code is in OPTION_C_REMAINING_PHASES.md - ready to copy/paste!**
