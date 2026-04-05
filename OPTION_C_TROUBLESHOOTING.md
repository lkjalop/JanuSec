# Option C - Troubleshooting Guide

**Common Issues and Solutions During Implementation**

---

## 🔧 IMPORT ERRORS

### Error: `ModuleNotFoundError: No module named 'src.analysis.domain_tools'`

**Symptoms:**
```python
ModuleNotFoundError: No module named 'src.analysis.domain_tools'
```

**Root Cause:**
- File exists but Python can't find it
- PYTHONPATH not set correctly
- Running from wrong directory

**Solution:**
```bash
# 1. Verify file exists
ls -la src/analysis/domain_tools.py  # Should show file

# 2. Check current directory
pwd  # Should be: D:\AI\Threat_thy_sniffer

# 3. Add to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# 4. Test import
python -c "from src.analysis.domain_tools import get_tools_for_domain; print('Success!')"

# 5. If still fails, try absolute import in code:
import sys
sys.path.insert(0, 'D:\\AI\\Threat_thy_sniffer')
from src.analysis.domain_tools import get_tools_for_domain
```

---

### Error: `ImportError: cannot import name 'detect_domain_with_confidence'`

**Symptoms:**
```python
ImportError: cannot import name 'detect_domain_with_confidence' from 'src.analysis.auto_llm'
```

**Root Cause:**
- Function not added to auto_llm.py yet
- Function name typo
- Indentation error (function inside class when should be module-level)

**Solution:**
```bash
# 1. Check if function exists
grep -n "def detect_domain_with_confidence" src/analysis/auto_llm.py

# 2. If not found, add it:
code src/analysis/auto_llm.py
# Copy function from OPTION_C_COMPLETE_IMPLEMENTATION_GUIDE.md Task 1.1

# 3. Verify indentation (should be at module level, not inside class):
# CORRECT:
# def build_llm_prompt(...):
#     pass
#
# def detect_domain_with_confidence(...):  # <- Same indentation as build_llm_prompt
#     pass
#
# class LLMAssessmentClient:
#     pass

# 4. Test import
python -c "from src.analysis.auto_llm import detect_domain_with_confidence; print('Success!')"
```

---

## 💾 DATABASE ERRORS

### Error: `sqlite3.OperationalError: no such table: historical_incidents`

**Symptoms:**
```
sqlite3.OperationalError: no such table: historical_incidents
```

**Root Cause:**
- Historical incidents table not created
- Wrong database file
- Seed script not run

**Solution:**
```bash
# 1. Check which database is being used
python -c "from src.repositories.historical_incidents_repo import HistoricalIncidentsRepo; r = HistoricalIncidentsRepo(); print(r.db_path)"

# 2. Check if table exists
sqlite3 janusec_dev.db ".tables"
# Should include: historical_incidents

# 3. If missing, run seed script (creates table):
python scripts/seed_historical_incidents.py

# 4. Verify table created:
sqlite3 janusec_dev.db "SELECT COUNT(*) FROM historical_incidents;"
# Should return: 5

# 5. If still fails, manually create table:
sqlite3 janusec_dev.db < migrations/014_historical_incidents.sql
```

---

### Error: `Historical query returns empty results`

**Symptoms:**
```python
similar_incidents = repo.query_similar_incidents(row, lookback_days=90)
print(len(similar_incidents))  # Prints: 0
```

**Root Cause:**
- No data in database
- SHA256/process_name doesn't match seed data
- Lookback window too short

**Solution:**
```bash
# 1. Check data exists
sqlite3 janusec_dev.db "SELECT COUNT(*) FROM historical_incidents;"
# Should be > 0

# 2. Check what data exists
sqlite3 janusec_dev.db "SELECT sha256, process_name, outcome FROM historical_incidents;"

# 3. Test with known SHA256 from seed data:
python -c "
from src.repositories.historical_incidents_repo import HistoricalIncidentsRepo
repo = HistoricalIncidentsRepo()
results = repo.query_similar_incidents({'sha256': '9bf41199f05fa1de8be5b84c6ef6e0a37f7b3d3f7a6e5d4c3b2a1f0e9d8c7b6a'}, lookback_days=365)
print(f'Found {len(results)} results')
print(results[0] if results else 'No results')
"

# 4. If still empty, re-run seed script:
python scripts/seed_historical_incidents.py
```

---

## 🌐 API ERRORS

### Error: `404 Not Found: /api/v1/graph/attack_reconstruction`

**Symptoms:**
```
POST http://localhost:8000/api/v1/graph/attack_reconstruction
Response: 404 Not Found
```

**Root Cause:**
- graph_endpoints.py not created
- Router not registered in server.py
- Typo in endpoint path

**Solution:**
```bash
# 1. Verify file exists
ls -la src/api/graph_endpoints.py

# 2. Check router is registered
grep -n "graph_endpoints" src/api/server.py
# Should see:
# from src.api import graph_endpoints
# app.include_router(graph_endpoints.router)

# 3. If missing, add to server.py:
code src/api/server.py

# Add after other imports:
from src.api import graph_endpoints

# Add after other routers:
app.include_router(graph_endpoints.router)

# 4. Restart server
pkill -f "python run_platform.py"
python run_platform.py

# 5. Test endpoint
curl http://localhost:8000/api/v1/graph/attack_reconstruction
# Should return: {"detail":"Method Not Allowed"}  (POST required, not GET)
```

---

### Error: `500 Internal Server Error` on AI Insights

**Symptoms:**
```
POST /api/v1/insights/generate
Response: 500 Internal Server Error
{"detail": "Insight generation failed: ..."}
```

**Root Cause:**
- LLM client not available
- Missing dependencies (src.integrations.llm_client)
- Invalid request body

**Solution:**
```bash
# 1. Check LLM client exists
python -c "from src.integrations.llm_client import DEFAULT_CLIENT; print(DEFAULT_CLIENT)"

# 2. Test insight generation directly
python -c "
from src.api.insights_endpoints import _generate_dread_scenarios
result = _generate_dread_scenarios(
    {'process_name': 'powershell.exe', 'host': 'TEST'},
    {'dread_score': 8.5, 'mitre_tags': ['T1055']}
)
print(result[:200])
"

# 3. Check server logs for detailed error:
tail -f logs/platform.log

# 4. If LLM unavailable, insight will use fallback (acceptable for demo)
```

---

## 🎨 UI ERRORS

### Error: Domain badges not appearing in table

**Symptoms:**
- CSV uploads successfully
- Table shows rows
- But no domain badges (NETWORK/ENDPOINT) visible

**Root Cause:**
- Frontend code not updated
- JavaScript error preventing rendering
- Domain detection logic not added

**Solution:**
```bash
# 1. Open browser console (F12)
# Look for JavaScript errors

# 2. Check if renderTableFromResults() updated
grep -n "_domain" frontend/static/csv_analyzer.html
# Should find code that sets row._domain

# 3. If missing, update csv_analyzer.html:
code frontend/static/csv_analyzer.html
# Add domain detection + badge column
# See OPTION_C_COMPLETE_IMPLEMENTATION_GUIDE.md Task 1.5

# 4. Hard refresh browser
# Ctrl+Shift+R (Windows) or Cmd+Shift+R (Mac)

# 5. Verify badge appears:
# Upload test CSV
# Check table has "Domain" column
# Check rows have colored badges
```

---

### Error: "Investigate Further" button does nothing

**Symptoms:**
- Click "Investigate Further" button
- Nothing happens
- No new tab opens

**Root Cause:**
- investigateFurther() function not defined
- localStorage not set
- csv_deep_analysis.html not accessible

**Solution:**
```bash
# 1. Open browser console (F12)
# Click "Investigate Further"
# Look for error message

# 2. Check if function exists
grep -n "function investigateFurther" frontend/static/csv_analyzer.html

# 3. Verify csv_deep_analysis.html exists
ls -la frontend/static/csv_deep_analysis.html

# 4. Test localStorage manually
# In browser console:
localStorage.setItem('csv_deep_row', '0');
localStorage.setItem('csv_last_results', JSON.stringify([{process_name: 'test'}]));
window.open('/static/csv_deep_analysis.html', '_blank');

# 5. If still fails, check investigateFurther() implementation:
function investigateFurther(rowIndex) {
  localStorage.setItem('csv_deep_row', rowIndex.toString());
  localStorage.setItem('csv_last_results', JSON.stringify(window.LAST_RESULTS || []));
  window.open('/static/csv_deep_analysis.html', '_blank');
}
```

---

### Error: HopGraph shows "Loading..." forever

**Symptoms:**
- Investigate Further tab opens
- HopGraph section shows "Loading attack graph..."
- Never renders (waits forever)

**Root Cause:**
- API endpoint not responding
- CORS error
- JavaScript fetch error

**Solution:**
```bash
# 1. Open browser console (F12)
# Look for network errors

# 2. Test API directly
curl -X POST http://localhost:8000/api/v1/graph/attack_reconstruction \
  -H "Content-Type: application/json" \
  -d '{"row": {"process_name": "test"}}'

# 3. Check if fetch call is correct
grep -A 10 "loadAttackGraph" frontend/static/csv_deep_analysis.html

# 4. Verify authHeaders() function exists
grep -n "authHeaders" frontend/static/csv_deep_analysis.html

# 5. If API fails, check server logs:
tail -f logs/platform.log

# 6. Fallback: HopGraph should show error message, not hang
# Update loadAttackGraph() to have timeout:
setTimeout(() => {
  if (canvas.textContent === 'Loading...') {
    canvas.textContent = 'HopGraph unavailable (timeout)';
  }
}, 5000);
```

---

## 🧪 TESTING ERRORS

### Error: Pytest can't find tests

**Symptoms:**
```bash
pytest tests/test_option_c_integration.py
# Output: collected 0 items
```

**Root Cause:**
- File doesn't exist
- Test functions don't start with `test_`
- PYTHONPATH issue

**Solution:**
```bash
# 1. Verify file exists
ls -la tests/test_option_c_integration.py

# 2. Check test function names
grep "^def " tests/test_option_c_integration.py
# All should start with "test_"

# 3. Run with verbose output
pytest tests/test_option_c_integration.py -v

# 4. If still not found, run from project root:
cd D:\AI\Threat_thy_sniffer
PYTHONPATH=. pytest tests/test_option_c_integration.py -v
```

---

### Error: Tests fail with "Historical repo unavailable"

**Symptoms:**
```bash
pytest tests/test_option_c_integration.py::test_historical_incidents_query
# FAILED: Historical query returned 0 results
```

**Root Cause:**
- Database not seeded
- Test using wrong SHA256

**Solution:**
```bash
# 1. Seed database before running tests
python scripts/seed_historical_incidents.py

# 2. Use exact SHA256 from seed data in test
# Update test to use: '9bf41199f05fa1de8be5b84c6ef6e0a37f7b3d3f7a6e5d4c3b2a1f0e9d8c7b6a'

# 3. Or skip historical tests if not critical:
pytest tests/test_option_c_integration.py -v -k "not historical"
```

---

## 🚀 PERFORMANCE ISSUES

### Issue: Tier 2 prompt generation is slow (>5 seconds)

**Symptoms:**
- Clicking "Investigate Further" takes 5-10 seconds to load
- Console shows long wait time

**Root Cause:**
- Historical query scanning entire database
- LLM call taking too long
- No caching

**Solution:**
```bash
# 1. Add index on historical_incidents table:
sqlite3 janusec_dev.db "CREATE INDEX IF NOT EXISTS idx_hist_sha256 ON historical_incidents(sha256);"

# 2. Limit historical query results:
# In build_tier2_prompt(), change:
similar_incidents = repo.query_similar_incidents(row, lookback_days=90, limit=3)
# to:
similar_incidents = repo.query_similar_incidents(row, lookback_days=90, limit=1)

# 3. Cache Tier 2 prompts:
# Add to row after generation:
row['_tier2_cached'] = True
row['_tier2_text'] = result['text']

# 4. Skip LLM call if cached:
if row.get('_tier2_cached'):
    return row['_tier2_text']
```

---

### Issue: Browser becomes unresponsive with large CSV

**Symptoms:**
- Upload CSV with 500+ rows
- Browser freezes or becomes very slow
- UI doesn't respond to clicks

**Root Cause:**
- Rendering too many DOM elements at once
- No pagination
- JavaScript blocking main thread

**Solution:**
```bash
# 1. Add pagination to table:
# In renderTableFromResults(), only render first 100 rows:
const pageSize = 100;
const page = 0;
const start = page * pageSize;
const end = start + pageSize;
const pageRows = results.slice(start, end);

# 2. Add virtual scrolling (advanced):
# Use library like react-window or ag-grid

# 3. For demo, limit CSV to 50 rows max:
# "For demo purposes, we recommend CSVs under 50 rows"
```

---

## 🎯 DEMO DAY EMERGENCIES

### Emergency: LLM API is down during demo

**Backup Plan:**
```bash
# 1. LLM client should use fallback deterministic summary
# Verify fallback works:
python -c "
from src.analysis.auto_llm import LLMAssessmentClient
client = LLMAssessmentClient()
client._client = None  # Simulate LLM unavailable
result = client.summarize_row({'process_name': 'test'}, {})
print(result['text'])
"

# 2. During demo, explain:
# "LLM is optional - platform generates deterministic summaries as fallback"
# "In production, you'd use your own LLM or our API"

# 3. Show screenshots instead of live LLM
```

---

### Emergency: HopGraph doesn't render during demo

**Backup Plan:**
```bash
# 1. Check if fallback message shows:
# "HopGraph unavailable: [error]"

# 2. Have backup screenshot ready:
# Show: docs/demo_screenshots/hopgraph_example.png

# 3. During demo, explain:
# "Graph requires full telemetry data"
# "Here's what it looks like with complete data [show screenshot]"
```

---

### Emergency: Historical query returns nothing during demo

**Backup Plan:**
```bash
# 1. Use specific row from seed data:
# SHA256: 9bf41199f05fa1de8be5b84c6ef6e0a37f7b3d3f7a6e5d4c3b2a1f0e9d8c7b6a
# Process: powershell.exe

# 2. Pre-load this row in CSV before demo

# 3. If still fails, explain:
# "Historical context requires past incidents in database"
# "Once deployed, learns from every investigation"
```

---

## 📞 GETTING HELP

If you encounter an issue not covered here:

1. **Check logs:**
   ```bash
   tail -f logs/platform.log
   tail -f logs/error.log
   ```

2. **Check browser console:**
   - F12 → Console tab
   - Look for red error messages

3. **Minimal reproduction:**
   ```bash
   # Create minimal test case
   python -c "
   # Simplest possible code that reproduces issue
   from src.analysis.auto_llm import detect_domain_with_confidence
   print(detect_domain_with_confidence({'factors': ['test']}))
   "
   ```

4. **Fallback to working state:**
   ```bash
   # If all else fails, show what DOES work
   # Focus on domain badges + Tier 1 summaries
   # Mention Tier 2 / HopGraph as "coming soon"
   ```

---

## ✅ PRE-DEMO CHECKLIST

Run through this checklist 1 hour before CEO demo:

```bash
# 1. Platform starts without errors
python run_platform.py
# Wait 10 seconds, check for errors

# 2. Database has data
sqlite3 janusec_dev.db "SELECT COUNT(*) FROM historical_incidents;"
# Should return: 5

# 3. API endpoints respond
curl http://localhost:8000/api/v1/graph/attack_reconstruction
# Should return: Method Not Allowed (expected, needs POST)

curl -X POST http://localhost:8000/api/v1/insights/generate \
  -H "Content-Type: application/json" \
  -d '{"row": {"process_name": "test"}, "insight_type": "dread"}'
# Should return JSON with insight

# 4. Frontend loads
curl http://localhost:8000/static/csv_analyzer.html
# Should return HTML (not 404)

curl http://localhost:8000/static/csv_deep_analysis.html
# Should return HTML (not 404)

# 5. Upload test CSV
# Open browser: http://localhost:8000/static/csv_analyzer.html
# Upload: tests/test_data/option_c_demo_data.csv
# Verify: Domain badges appear

# 6. Test "Investigate Further"
# Click on network artifact
# Verify: New tab opens with Tier 2 summary

# 7. Test AI Insights
# Click "Generate DREAD Scenarios"
# Verify: Text appears, cost updates

# 8. Have backup screenshots ready
ls docs/demo_screenshots/
# Should have 7+ PNG files
```

**If all checks pass → You're ready! 🎉**

**If any fail → Use this troubleshooting guide to fix before demo**
