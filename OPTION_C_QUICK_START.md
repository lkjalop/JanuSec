# Option C - Quick Start Guide

**Goal:** Get started on Option C implementation immediately
**Time to First Working Feature:** 1-2 hours

---

## 🚀 FASTEST PATH TO PROGRESS

### Step 0: Verify Current State (5 minutes)

```bash
# Check what files already exist
ls src/analysis/domain_tools.py           # ✅ Should exist
ls src/analysis/correlation_context.py    # ✅ Should exist
ls src/repositories/historical_incidents_repo.py  # ✅ Should exist
ls frontend/static/csv_deep_analysis.html # ✅ Should exist

# Check what's missing
grep -n "detect_domain" src/analysis/auto_llm.py  # ❌ Should return nothing
grep -n "build_tier2" src/analysis/auto_llm.py    # ❌ Should return nothing
```

**Expected Result:**
- ✅ 4 files exist (domain_tools, correlation_context, historical_repo, deep_analysis UI)
- ❌ Functions NOT in auto_llm.py yet (need to add them)

---

## 🎯 RECOMMENDED EXECUTION ORDER

### Phase 1A: Wire Domain Detection (1 hour) - HIGHEST VALUE

**Why Start Here:**
- Small, self-contained task
- Immediate visible impact (domain badges in UI)
- No dependencies on other systems
- Easy to test

**Steps:**

1. **Add detect_domain_with_confidence() to auto_llm.py** (20 min)
   ```bash
   # Open file
   code src/analysis/auto_llm.py

   # Add function after line 54 (after build_llm_prompt)
   # Copy code from OPTION_C_COMPLETE_IMPLEMENTATION_GUIDE.md Task 1.1
   ```

2. **Test domain detection** (10 min)
   ```python
   # In Python console
   from src.analysis.auto_llm import detect_domain_with_confidence

   # Test network
   test_network = {'factors': ['port_scan'], 'src_ip': '10.0.0.5'}
   print(detect_domain_with_confidence(test_network))
   # Expected: ('network', 1.0)

   # Test endpoint
   test_endpoint = {'factors': ['process_injection'], 'process_name': 'powershell.exe'}
   print(detect_domain_with_confidence(test_endpoint))
   # Expected: ('endpoint', 1.0)
   ```

3. **Add domain badges to UI** (30 min)
   ```bash
   # Open CSV Analyzer
   code frontend/static/csv_analyzer.html

   # Find renderTableFromResults() function
   # Add domain detection logic + badge column
   # Copy code from OPTION_C_COMPLETE_IMPLEMENTATION_GUIDE.md Task 1.5
   ```

4. **Visual Test** (5 min)
   ```bash
   # Start platform
   python run_platform.py

   # Open browser: http://localhost:8000/static/csv_analyzer.html
   # Upload any CSV
   # Verify domain badges appear (NETWORK / ENDPOINT / GENERIC)
   ```

**✅ Success Criteria:**
- Domain badges visible in table
- Blue badge for network artifacts
- Green badge for endpoint artifacts
- No console errors

---

### Phase 1B: Seed Historical Data (30 min) - QUICK WIN

**Why Do This Next:**
- Unlocks historical context feature
- Simple script (no complex integration)
- Impressive for demo ("platform remembers past incidents!")

**Steps:**

1. **Create seed script** (10 min)
   ```bash
   # Create file
   code scripts/seed_historical_incidents.py

   # Copy code from OPTION_C_COMPLETE_IMPLEMENTATION_GUIDE.md Task 1.4
   ```

2. **Run script** (2 min)
   ```bash
   python scripts/seed_historical_incidents.py
   ```

   **Expected Output:**
   ```
   Seeding historical incidents database...
     ✅ Incident 1: powershell.exe on WORKSTATION-042 (confirmed_malicious)
     ✅ Incident 2: svchost.exe on SERVER-087 (false_positive)
     ✅ Incident 3: chrome.exe on LAPTOP-055 (confirmed_malicious)
     ✅ Incident 4: mimikatz.exe on WORKSTATION-042 (confirmed_malicious)
     ✅ Incident 5: taskmgr.exe on WORKSTATION-099 (benign)

   ✅ Seeded 5 historical incidents

   Testing historical query...
     Found 1 similar incidents for SHA256 9bf41199...
     Match: powershell.exe - confirmed_malicious
   ```

3. **Verify database** (5 min)
   ```bash
   sqlite3 janusec_dev.db
   ```
   ```sql
   SELECT COUNT(*) FROM historical_incidents;
   -- Should return: 5

   SELECT process_name, outcome FROM historical_incidents;
   -- Should show 5 rows

   .quit
   ```

**✅ Success Criteria:**
- Script runs without errors
- 5 incidents inserted
- Query returns results

---

### Phase 1C: Build Tier 2 Prompt (2 hours) - CORE FEATURE

**Why Do This Third:**
- Most complex task (needs all other pieces)
- Integrates domain_tools, correlation_context, historical_repo
- Enables full "Investigate Further" experience

**Steps:**

1. **Add build_tier2_prompt() function** (45 min)
   ```bash
   code src/analysis/auto_llm.py

   # Add after detect_domain_with_confidence()
   # Copy code from OPTION_C_COMPLETE_IMPLEMENTATION_GUIDE.md Task 1.2
   ```

2. **Update summarize_row() to support tiers** (15 min)
   ```bash
   # In same file, find summarize_row() method (line ~68)
   # Add tier detection logic
   # Copy code from OPTION_C_COMPLETE_IMPLEMENTATION_GUIDE.md Task 1.3
   ```

3. **Test Tier 2 prompt generation** (30 min)
   ```python
   from src.analysis.auto_llm import build_tier2_prompt, LLMAssessmentClient

   test_row = {
       'process_name': 'powershell.exe',
       'host': 'WORKSTATION-042',
       'sha256': '9bf41199f05fa1de8be5b84c6ef6e0a37f7b3d3f7a6e5d4c3b2a1f0e9d8c7b6a',
       'factors': ['process_injection', 'unsigned_binary']
   }

   test_context = {
       'pipeline_context': {
           'dread_score': 8.5,
           'mitre_tags': ['T1055', 'T1059.001'],
           'correlation': {'score': 0.73}
       }
   }

   # Test prompt generation
   prompt = build_tier2_prompt(test_row, test_context)

   # Verify sections
   assert 'THREAT HUNTER' in prompt
   assert 'HISTORICAL CONTEXT' in prompt
   assert 'ATTACK CONTEXT' in prompt
   assert 'COLLECTION PLAYBOOK' in prompt

   # Check length
   lines = prompt.splitlines()
   print(f"Prompt length: {len(lines)} lines")
   assert 60 <= len(lines) <= 100

   # Test LLM client
   client = LLMAssessmentClient()
   result = client.summarize_row(test_row, {'tier': 'tier2', **test_context})

   print("Tier 2 Summary Generated:")
   print(result['text'][:500] + "...")
   ```

4. **Visual test in UI** (30 min)
   ```bash
   # Start platform
   python run_platform.py

   # Open browser: http://localhost:8000/static/csv_analyzer.html
   # Upload CSV with powershell.exe row
   # Click "Investigate Further"
   # Verify Tier 2 summary appears in csv_deep_analysis.html
   ```

**✅ Success Criteria:**
- Tier 2 prompt is 60-100 lines
- Includes historical context ("Similar incident 14 days ago...")
- Includes correlation enrichment
- Includes domain-specific playbook
- No crashes when historical repo unavailable

---

## ⏸️ PAUSE POINT #1 (After Phase 1: 3.5 hours)

**What You Have Now:**
- ✅ Domain detection working
- ✅ Domain badges in UI
- ✅ Historical incidents seeded
- ✅ Tier 2 prompts generating with full context

**Demo-able Features:**
- Upload CSV → see domain badges
- Click "Investigate Further" → see rich 60-100 line summary
- See historical context if SHA256 matches seed data

**Decision Point:**
- **Option A:** Show CEO now (screenshots + partial demo)
- **Option B:** Continue to Phase 2 (HopGraph + AI Insights)

**Recommendation:** If CEO is impatient, demo now. If you have 1-2 more days, continue to Phase 2.

---

## 🎯 Phase 2A: HopGraph Integration (2 hours)

**Why Do This:**
- Impressive visual feature (graphs sell!)
- Shows attack chain reconstruction
- Differentiator vs competitors

**Steps:**

1. **Create hopgraph_integration.py** (1 hour)
   ```bash
   code src/core/graph/hopgraph_integration.py

   # Copy full code from OPTION_C_COMPLETE_IMPLEMENTATION_GUIDE.md Task 2.1
   ```

2. **Create graph_endpoints.py** (30 min)
   ```bash
   code src/api/graph_endpoints.py

   # Copy code from OPTION_C_COMPLETE_IMPLEMENTATION_GUIDE.md Task 2.2
   ```

3. **Wire up in server.py** (5 min)
   ```bash
   code src/api/server.py

   # Add import:
   from src.api import graph_endpoints

   # Add router:
   app.include_router(graph_endpoints.router)
   ```

4. **Test API endpoint** (15 min)
   ```bash
   # Start platform
   python run_platform.py

   # In another terminal, test API:
   curl -X POST http://localhost:8000/api/v1/graph/attack_reconstruction \
     -H "Content-Type: application/json" \
     -d '{
       "row": {
         "process_name": "powershell.exe",
         "sha256": "abc123",
         "host": "TEST-HOST"
       },
       "max_hops": 3
     }'

   # Should return JSON with nodes, edges, timeline
   ```

5. **Update frontend to load graph** (10 min)
   ```bash
   code frontend/static/csv_deep_analysis.html

   # Find loadAttackGraph() function
   # Update to call /api/v1/graph/attack_reconstruction
   # Copy code from OPTION_C_COMPLETE_IMPLEMENTATION_GUIDE.md Task 2.4
   ```

**✅ Success Criteria:**
- API endpoint returns graph data
- Frontend calls API when page loads
- Graph canvas shows "Loading..." or actual graph
- No 404/500 errors

---

## 🎯 Phase 2B: AI Insights (2 hours)

**Why Do This:**
- Shows on-demand LLM capabilities
- Cost tracking demo (transparency)
- Multiple use cases (DREAD, playbook, hunt, executive)

**Steps:**

1. **Create insights_endpoints.py** (1 hour)
   ```bash
   code src/api/insights_endpoints.py

   # Copy full code from OPTION_C_COMPLETE_IMPLEMENTATION_GUIDE.md Task 2.3
   ```

2. **Wire up in server.py** (5 min)
   ```bash
   code src/api/server.py

   # Add import:
   from src.api import insights_endpoints

   # Add router:
   app.include_router(insights_endpoints.router)
   ```

3. **Test API endpoints** (20 min)
   ```bash
   # Test DREAD scenarios
   curl -X POST http://localhost:8000/api/v1/insights/generate \
     -H "Content-Type: application/json" \
     -d '{
       "row": {"process_name": "powershell.exe", "host": "TEST"},
       "insight_type": "dread",
       "pipeline_context": {"dread_score": 8.5, "mitre_tags": ["T1055"]}
     }'

   # Test playbook
   curl -X POST http://localhost:8000/api/v1/insights/generate \
     -H "Content-Type: application/json" \
     -d '{
       "row": {"process_name": "powershell.exe"},
       "insight_type": "playbook",
       "pipeline_context": {"mitre_tags": ["T1055"]}
     }'

   # Should return insight text + cost estimate
   ```

4. **Update frontend generateInsight()** (35 min)
   ```bash
   code frontend/static/csv_deep_analysis.html

   # Find generateInsight() function
   # Update to call /api/v1/insights/generate
   # Copy code from OPTION_C_COMPLETE_IMPLEMENTATION_GUIDE.md Task 2.4
   ```

**✅ Success Criteria:**
- All 4 insight types return text
- Cost tracking updates on frontend
- No errors in console
- Playbook type uses domain_tools (no LLM needed)

---

## ⏸️ PAUSE POINT #2 (After Phase 2: 7.5 hours total)

**What You Have Now:**
- ✅ Everything from Phase 1
- ✅ HopGraph attack reconstruction
- ✅ AI Insights (DREAD, playbook, hunt, executive)

**Demo-able Features:**
- Full end-to-end workflow
- Visual attack graphs
- On-demand insights with cost tracking
- Historical context

**CEO Demo:** READY for impressive demo!

---

## 🧪 Phase 3: Testing (2 hours)

**Why Do This:**
- Catch bugs before CEO demo
- Ensure reproducibility
- Build confidence

**Steps:**

1. **Create test data CSV** (30 min)
   ```bash
   code tests/test_data/option_c_demo_data.csv

   # Create 10 rows:
   # - 5 network artifacts
   # - 5 endpoint artifacts
   # - Mix of verdicts
   # Use realistic process names, IPs, SHA256s
   ```

2. **Run integration tests** (30 min)
   ```bash
   # Create test file
   code tests/test_option_c_integration.py

   # Copy code from OPTION_C_COMPLETE_IMPLEMENTATION_GUIDE.md Task 3.2

   # Run tests
   pytest tests/test_option_c_integration.py -v

   # All tests should pass
   ```

3. **Manual UI walkthrough** (1 hour)
   ```bash
   # Follow checklist from OPTION_C_COMPLETE_IMPLEMENTATION_GUIDE.md Task 3.3

   # Test:
   # - Upload CSV
   # - Domain badges display
   # - Investigate Further (network)
   # - Investigate Further (endpoint)
   # - HopGraph loads
   # - AI Insights generate
   # - Historical context appears
   # - Cost tracking updates
   ```

**✅ Success Criteria:**
- All automated tests pass
- Manual walkthrough completes without errors
- Test data works end-to-end

---

## 🎬 Phase 4: Demo Prep (1 hour)

**Steps:**

1. **Write demo script** (20 min)
   - Copy template from OPTION_C_COMPLETE_IMPLEMENTATION_GUIDE.md Task 4.1
   - Customize for your CEO's style

2. **Take screenshots** (20 min)
   - CSV Analyzer with domain badges
   - Tier 2 summary (network)
   - Tier 2 summary (endpoint)
   - HopGraph visualization
   - AI Insights section
   - Historical context
   - Cost tracking

3. **Rehearse** (20 min)
   - Time yourself (15-20 min target)
   - Practice Q&A
   - Test backup plans

---

## 📊 CUMULATIVE PROGRESS TRACKER

| Milestone | Time | Cumulative | Demo-Ready? |
|-----------|------|------------|-------------|
| Domain Detection + UI | 1 hr | 1 hr | 40% |
| Historical Data Seed | 0.5 hr | 1.5 hr | 50% |
| Tier 2 Prompts | 2 hr | 3.5 hr | 70% ✅ |
| HopGraph Integration | 2 hr | 5.5 hr | 85% ✅✅ |
| AI Insights | 2 hr | 7.5 hr | 95% ✅✅✅ |
| Testing | 2 hr | 9.5 hr | 98% |
| Demo Prep | 1 hr | 10.5 hr | 100% 🎉 |

---

## 🚨 TROUBLESHOOTING

### Issue: "ModuleNotFoundError: No module named 'src.analysis.domain_tools'"

**Fix:**
```bash
# Verify file exists
ls src/analysis/domain_tools.py

# Check Python path
python -c "import sys; print('\n'.join(sys.path))"

# Add to PYTHONPATH if needed
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

---

### Issue: "Table historical_incidents doesn't exist"

**Fix:**
```bash
# Run seed script (creates table automatically)
python scripts/seed_historical_incidents.py

# Verify
sqlite3 janusec_dev.db "SELECT COUNT(*) FROM historical_incidents;"
```

---

### Issue: "HopGraph integration fails"

**Fix:**
```bash
# Check if HopGraphLite exists
ls src/core/graph/hopgraph_lite.py

# If missing, hopgraph_integration.py will use fallback
# Verify fallback works:
python -c "from src.core.graph.hopgraph_integration import query_attack_graph; print(query_attack_graph({'process_name': 'test'}))"
```

---

### Issue: "Frontend shows 404 for /api/v1/graph/attack_reconstruction"

**Fix:**
```bash
# Check router is registered
grep -n "graph_endpoints" src/api/server.py

# Should see:
# from src.api import graph_endpoints
# app.include_router(graph_endpoints.router)

# If missing, add to server.py
```

---

## 🎯 SUCCESS METRICS

**After 10.5 hours, you should have:**

✅ **Functional Features:**
- Domain detection (network vs endpoint)
- Tier 2 prompts (60-100 lines with context)
- Historical incident queries
- HopGraph attack reconstruction
- AI Insights (DREAD, playbook, hunt, executive)
- Cost tracking

✅ **Demo-Ready:**
- CSV uploads work
- UI looks professional
- No console errors
- Screenshots captured
- Demo script written
- Rehearsed and timed

✅ **CEO Pitch:**
- "40x faster triage"
- "Learns from past incidents"
- "Attack graph reconstruction"
- "Domain-specific playbooks"
- "$0.003 per alert vs $20 analyst time"

---

**START WITH PHASE 1A (Domain Detection) - HIGHEST IMMEDIATE VALUE!**
