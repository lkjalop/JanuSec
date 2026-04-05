# Pre-Demo Startup Guide

**For JanuSec CEO Demo**
**Time required**: 2 minutes
**Mode**: Simple (SQLite + no Redis)

---

## Quick Start (Recommended for Demo)

### Option A: Use Quick-Start Batch File (Easiest)

```batch
# Double-click or run from terminal:
quick-start.bat

# Platform will start on: http://localhost:8080
```

**This automatically:**
- Sets environment variables
- Starts FastAPI server on port 8080
- Enables CSV upload
- No Redis required (uses SQLite database)

---

### Option B: Manual Start with Port Control

```batch
# Start on port 8080 (default):
python start_simple.py

# OR start on port 8000 (if demo scripts expect this):
python start_simple.py --port 8000

# OR start without auto-reload (more stable on Windows):
python start_simple.py --port 8000 --no-reload
```

---

## Verify Platform is Running

Once started, you should see:

```
==================================================
Starting JanuSec Platform
==================================================

Server: http://0.0.0.0:8080
Console: http://0.0.0.0:8080/console
CSV Upload: http://0.0.0.0:8080/api/v1/csv/upload-page
API Docs: http://0.0.0.0:8080/docs

Press Ctrl+C to stop
==================================================
```

**Test in browser:**
- Main console: `http://localhost:8080/static/janusec-platform-complete-LIVE.html`
- CSV Analyzer: `http://localhost:8080/static/csv_analyzer.html`
- API Health: `http://localhost:8080/api/v1/dashboard/status`

---

## Pre-Demo Checklist (30 minutes before)

### Step 1: Validate Files (2 minutes)

```bash
python scripts/validate_demo_readiness.py
```

**Expected**: All files should pass. Redis/Platform NOT running is OK.

### Step 2: Start Platform (1 minute)

**Choose port based on your demo scripts:**

```batch
# If demo scripts use port 8000:
python start_simple.py --port 8000 --no-reload

# If demo scripts use port 8080:
quick-start.bat
```

**Wait for**: Console shows "Uvicorn running on..."

### Step 3: Populate Attack Scenario (1 minute)

```bash
# Update API_BASE if needed (8000 vs 8080)
# Edit demo_scenario_2_attack_reconstruction.py line 27:
# API_BASE = "http://localhost:8000"  # or 8080

python scripts/demo_scenario_2_attack_reconstruction.py
```

**Expected output:**
```
✅ Event 1/9: email - T1566.001
✅ Event 2/9: process - T1059.001
...
✅ Correlation successful!
```

### Step 4: Open Browser Tabs (1 minute)

Open these in separate tabs (adjust port 8000/8080 as needed):

- Main Console: `http://localhost:8080/static/janusec-platform-complete-LIVE.html`
- CSV Analyzer: `http://localhost:8080/static/csv_analyzer.html`
- HopGraph: `http://localhost:8080/static/graph_explain.html`
- Compliance: `http://localhost:8080/static/compliance.html`
- MITRE: `http://localhost:8080/static/mitre.html`

### Step 5: Close Distractions (2 minutes)

- Close Slack, email, notifications
- Close unused apps (free RAM)
- Disable Windows notifications
- Start screen recording (backup)

### Step 6: Quick Smoke Test (3 minutes)

**Test 1: CSV Upload**
1. Go to CSV Analyzer
2. Choose File → `dump/cybstash csv1.xlsx`
3. Click "Load" → Should see rows populate
4. Click "Deep Analyze" on first row → Should show DREAD scores

**Test 2: Decisions API**
1. Open: `http://localhost:8080/api/v1/decisions/recent?limit=5&tenant_id=demo`
2. Should see JSON with correlated threats

**Test 3: Graph Viz**
1. Open HopGraph page
2. Should see D3.js visualization render

**If all 3 pass: YOU ARE READY TO DEMO!**

---

## Troubleshooting

### Platform won't start

**Error**: `Address already in use`
**Fix**: Change port
```bash
python start_simple.py --port 8001
```

**Error**: `ModuleNotFoundError`
**Fix**: Ensure PYTHONPATH is set
```bash
set PYTHONPATH=D:\AI\Threat_thy_sniffer
python start_simple.py
```

### Demo script fails with connection error

**Error**: `Connection refused to localhost:8000`
**Fix**: Update demo script API_BASE to match running port

Edit `scripts/demo_scenario_2_attack_reconstruction.py`:
```python
API_BASE = "http://localhost:8080"  # Match your server port
```

### CSV Analyzer shows blank page

**Fix**: Ensure frontend files exist
```bash
dir frontend\static\csv_analyzer.html
```

Should show file. If missing, check git status.

---

## Docker Alternative (If Simple Mode Fails)

If Python setup is problematic, use Docker:

```bash
# Start Redis + API + Worker
docker-compose -f docker-compose.redis.yml up

# Platform will be on: http://localhost:8000
```

**Note**: Demo scripts already expect port 8000 for Docker mode.

---

## Post-Demo Shutdown

```bash
# Simple mode: Press Ctrl+C in terminal

# Docker mode:
docker-compose -f docker-compose.redis.yml down
```

---

## Summary: Fastest Path to Demo-Ready

```batch
# 1. Validate (optional but recommended)
python scripts/validate_demo_readiness.py

# 2. Start platform
python start_simple.py --port 8000 --no-reload

# 3. Populate demo data
python scripts/demo_scenario_2_attack_reconstruction.py

# 4. Open browser to http://localhost:8000/static/janusec-platform-complete-LIVE.html

# 5. GO DEMO!
```

**Total time**: 5 minutes
**Confidence level**: High (all files validated, real data, tested flow)

---

**You've got this!** The platform is built, tested, and ready. Just follow these steps and you'll nail the demo.
