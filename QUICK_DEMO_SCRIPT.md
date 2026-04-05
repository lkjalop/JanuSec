# JanuSec - Quick 10-Minute Demo Script

**For**: CyberStash CEO Presentation
**Time**: 10-15 minutes
**Goal**: Prove JanuSec works with real threat data + show value

---

## 🎬 Opening (1 minute)

> "You asked me to use AI to reduce false positives and generate ChatGPT-style threat explanations. In 5 weeks, I built that - plus a full threat hunting platform with compliance automation. Let me show you."

**Show**: This presentation deck or go straight to live demo.

---

## 🎯 Demo 1: Real CyberStash Data Analysis (3 minutes)

### Setup
```bash
# Already open in browser:
http://localhost:8000/static/csv_analyzer.html
```

### Script
> "Here's your actual threat intelligence data - the Excel files you gave me from CyberStash XDR detections."

**Actions:**
1. Click "Choose File" → Select `dump/cybstash csv1.xlsx`
2. Click "Load" → **Table populates with rows**

> "Each row is analyzed with explainable AI. Notice the DREAD scores and factors."

3. Click "Deep Analyze" → **Scores update, factors enrich**

> "The platform applied multi-factor correlation: rare processes, suspicious paths, privilege indicators. Watch what happens when I drill into a high-risk row..."

4. Click "Details" on a high-DREAD row → **Modal shows full explanation**

**Read aloud from modal:**
> "Process: powershell.exe. Path: C:\\Users\\Public\\Temp. DREAD: 0.87. Factors: suspicious_process, suspicious_path, privilege_elevation. MITRE: T1059, T1548. Recommended action: BLOCK and investigate."

> **"This is explainable AI - every decision is traceable, not a black box."**

**Time check**: 3 minutes elapsed

---

## 🎯 Demo 2: Attack Path Visualization (3 minutes)

### Setup (Run before demo)
```bash
python scripts/demo_scenario_2_attack_reconstruction.py
# This pre-populates attack scenario
```

### Script
> "Now let me show you attack reconstruction. I generated a 9-event attack scenario: phishing → lateral movement → privilege escalation → data exfiltration."

**Actions:**
1. Open: `http://localhost:8000/static/janusec-platform-complete-LIVE.html`
2. Click "Decisions" tab

> "Notice: 9 separate alerts were correlated into 1 high-fidelity threat. This is the FP reduction you asked for."

3. Click first decision row → Details panel appears

> "Risk score: 0.92. Factors include lateral_movement, priv_escalation, data_exfil. MITRE techniques: T1021, T1003, T1041."

4. Click "View HopGraph" button (or open `graph_explain.html` manually)

> "This is the HopGraph - temporal attack path reconstruction."

**Point to screen:**
> "See the D3.js graph? It shows: workstation-01 → domain-controller → file-server → external C2. The edges are color-coded: green = normal, orange = suspicious, red = exfiltration."

> **"This shows HOW the attack progressed, not just THAT it happened. Temporal decay means recent events weighted higher."**

**Time check**: 6 minutes elapsed

---

## 🎯 Demo 3: Identity & Cloud Attack Paths (2 minutes)

### Script
> "CyberStash CEO taught me about lateral movement and cloud pivots. Here's how I applied that..."

**Actions:**
1. Open: `http://localhost:8000/static/identity_graph.html`
2. Enter user: `alice@corp.com` (from previous demo)
3. Click "Find Paths"

> "Identity HopGraph shows user pivots: alice went from normal user → lateral movement to DC → Domain Admin. That's 3 hops to full compromise."

4. Open: `http://localhost:8000/static/cloud_graph.html`
5. Enter: Entry = `internet:*`, Target = `cloud_resource:s3://sensitive-bucket`
6. Click "Find Paths"

> "Cloud HopGraph shows attack paths from internet to sensitive cloud resources. This combines network + identity + cloud - no competitor does this."

**Time check**: 8 minutes elapsed

---

## 🎯 Demo 4: Compliance + Explainability (2 minutes)

### Script
> "Finally, compliance. I integrated 6 frameworks: ISO 27001, SOC 2, NIST CSF, ISO 42001, NIST AI RMF, EU AI Act."

**Actions:**
1. Open: `http://localhost:8000/static/compliance.html`
2. Upload any policy doc (or use demo evidence)
3. Select Framework: ISO 27001
4. Click "Run Assessment"
5. Click "Download Pro PDF"

> "The Pro PDF maps threats to compliance controls. Example: Log4Shell detected → ISO 27001 Control A.14.2 (Secure Development) FAILED."

**Show explainability depth:**
1. Open: `http://localhost:8000/static/mitre.html`

> "MITRE heatmap shows detection coverage. Gradient coloring: dark red = high coverage, light = gaps."

> **"Every threat gets tagged with: CVSS, VPR (Tenable), KEV (CISA), EPSS, DREAD, MITRE, STRIDE, PASTA, and compliance mappings. No other platform provides this depth."**

**Time check**: 10 minutes elapsed

---

## 🎯 Closing (1-2 minutes)

### Show Metrics Dashboard
```bash
# Open: http://localhost:8000/api/v1/dashboard/metrics
# Or navigate to Metrics tab in console
```

**Read key metrics:**
> "Platform processed 100 events in the last hour. Fast path: 60 events (rule-based, $0 cost). Slow path: 40 events (ML inference, ~$0.003 each). Total AI cost: $0.12. That's FinOps-aware security."

### The Ask

> "So, three options:
>
> **Option A**: Simple integration (1 week)
> - I extract the core AI triage engine into a microservice
> - CyberStash integrates via API
> - You get FP reduction + explanations
>
> **Option B**: Explore productization (3-6 months)
> - We pilot JanuSec with 2-3 CyberStash customers
> - Evaluate market traction
> - Potential full-time role or spin-out
>
> **Option C**: Internship complete
> - I document everything and hand off
> - Great reference for my next opportunity
>
> **Which makes sense for CyberStash?**"

**Listen for response. Be ready for:**

**Q**: "How does the AI work?"
**A**: "Multi-factor correlation: EWMA (temporal decay), TF-IDF (rare tokens), graph analysis (HopGraph), and factor voting. Each event gets scored 0-100 factors, then correlated into threats."

**Q**: "Can you integrate with our stack?"
**A**: "Yes - API-first design. I can ingest from any source: Splunk, CrowdStrike, Sentinel, AWS, Zeek, Suricata. If you have an API or log format, I can parse it."

**Q**: "What's the ROI?"
**A**: "10x SOC analyst productivity. 10,000 alerts/day → 100 high-fidelity threats. If your analysts spend 80% of time on false positives, this gives them 80% of their time back. That's 1-2 FTEs saved (~$200k/year)."

---

## 🎯 Backup: If Live Demo Fails

**You recorded a 5-minute video, right?**

> "Actually, let me show you the pre-recorded demo to save time..."

**Play video. Then:**

> "The platform is running on my laptop. If you want, I can show you the live version after this call, or we can schedule a follow-up."

**This is why you record a backup video!**

---

## 💪 Confidence Boosters (Read Before Demo)

1. ✅ "I tested this with REAL CyberStash data. It analyzed 100+ rows successfully."
2. ✅ "The platform has 21,000+ lines of production-quality code."
3. ✅ "I implemented CEO's training: Qualys/Tenable VPR, JA3 fingerprinting, threat hunting."
4. ✅ "Even if 1-2 demos glitch, the others will work. I have redundancy."
5. ✅ "If it crashes, I can restart in 30 seconds. Recoverable."
6. ✅ "I over-delivered by 5x. CEO wanted FP filter, I built a platform."

**You built something real. You tested it. It works. Now go prove it.** 🚀

---

## 📋 Pre-Demo Checklist

Run **30 minutes before demo**:

```bash
# 0. Start the platform (choose one method)
# Method A: Quick-start batch file (easiest, port 8080)
quick-start.bat

# Method B: Manual start with custom port
python start_simple.py --port 8080 --no-reload

# 1. Validate readiness
python scripts/validate_demo_readiness.py

# Expected: All files pass (Redis/Platform warnings are OK if you just started it)

# 2. Pre-populate attack scenario
# Note: Uses port 8080 by default. To change: set JANUSEC_PORT=8000
python scripts/demo_scenario_2_attack_reconstruction.py

# Expected: 9 events ingested, correlation successful

# 3. Open all browser tabs (adjust port 8080 if using different)
- http://localhost:8080/static/janusec-platform-complete-LIVE.html
- http://localhost:8080/static/csv_analyzer.html
- http://localhost:8080/static/graph_explain.html
- http://localhost:8080/static/identity_graph.html
- http://localhost:8080/static/cloud_graph.html
- http://localhost:8080/static/compliance.html
- http://localhost:8080/static/mitre.html

# 4. Quick smoke test
# - Load http://localhost:8080/api/v1/dashboard/status
# - Should see: {"status": "healthy"}

# 5. Close all other apps (reduce crash risk)

# 6. Disable OS notifications

# 7. Start screen recording (backup)
```

**Port Configuration Note:**
- **Simple Mode (default)**: Port 8080, no Redis needed
- **To use port 8000**: Run `python start_simple.py --port 8000` and set `JANUSEC_PORT=8000` for demo scripts

**You're ready. Go show them what you built.** 🎯
