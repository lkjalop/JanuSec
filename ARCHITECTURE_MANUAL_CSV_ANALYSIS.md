# JanuSec Platform: Manual CSV Analysis Flow
**Complete User Journey from Upload → Deep Analyze → LLM Summaries → Report → HopGraph**

*Last Updated: 2025-01-24*
*Version: 2.0 - Comprehensive Edition*

---

## 🎯 Overview: What is Manual CSV Analysis?

**Business Problem**: Security analysts receive log exports (CSV, Excel) from various sources:
- Firewall logs that don't have API integration yet
- EDR exports from customer environments (can't install agent)
- Forensic artifact collections (KAPE, Velociraptor outputs)
- Historical data for breach investigation ("what happened last month?")

**Solution**: Upload-and-analyze workflow with same detection power as live processing, but optimized for batch analysis of thousands of rows at once.

---

## 📊 Complete User Flow Diagram (ASCII)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    👤 USER: SECURITY ANALYST                             │
│  Browser: csv_analyzer.html (frontend/static/csv_analyzer.html)         │
└─────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  STEP 1: FILE UPLOAD                                                     │
│  ────────────────────────────────────────────────────────────────────   │
│  🎯 Business: "I have 5,000 rows of firewall logs. Are any malicious?"  │
│  🔧 Technical: Client-side parsing (no upload size limits)               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  User Actions:                                                           │
│  1. Click "Choose File" button                                          │
│  2. Select: firewall_logs.csv (or .xlsx, .json, .txt)                   │
│  3. Click "Load" button                                                 │
│                                                                          │
│  Browser JavaScript (parse_tabular.js):                                 │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  function parseCSV(file) {                                       │   │
│  │    // Papa Parse library: handles CSV, TSV, pipes, etc.          │   │
│  │    return PapaParse.parse(file, {                                │   │
│  │      header: true,  // First row = column names                  │   │
│  │      dynamicTyping: true,  // Auto-detect numbers                │   │
│  │      skipEmptyLines: true                                        │   │
│  │    });                                                            │   │
│  │  }                                                                │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Result: 5,000 rows parsed into JavaScript array of objects:            │
│  [                                                                       │
│    { timestamp: "2025-01-20 14:32:10",                                  │
│      src_ip: "10.0.50.42",                                              │
│      dst_ip: "203.0.113.66",                                            │
│      dst_port: 443,                                                     │
│      process_name: "powershell.exe",                                    │
│      user: "alice",                                                     │
│      host: "ws-alice-01" },                                             │
│    ...4,999 more...                                                     │
│  ]                                                                       │
│                                                                          │
│  💡 Why Client-Side Parsing?                                            │
│     - No 10 MB upload limits (can handle 100 MB+ files)                 │
│     - Instant preview (no wait for server)                              │
│     - Works offline (great for air-gapped environments)                 │
│  ⚠️ Limitation: Browser may crash on >500k rows (RAM limit)             │
└─────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  STEP 2: INITIAL CLIENT-SIDE TRIAGE (Quick Filters)                     │
│  ────────────────────────────────────────────────────────────────────   │
│  🎯 Business: "Show me the suspicious stuff FIRST"                      │
│  🔧 Technical: Lightweight heuristics (no server call yet)              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Browser JavaScript (threat_ranking.js):                                │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  function quickTriage(rows) {                                     │   │
│  │    rows.forEach(row => {                                          │   │
│  │      let suspicionScore = 0;                                      │   │
│  │                                                                   │   │
│  │      // Heuristic 1: PowerShell with encoding                    │   │
│  │      if (row.process_name?.includes('powershell') &&             │   │
│  │          row.cmdline?.includes('-enc')) {                        │   │
│  │        suspicionScore += 0.3;                                    │   │
│  │        row._signals = (row._signals || []).concat('ps_encoded'); │   │
│  │      }                                                            │   │
│  │                                                                   │   │
│  │      // Heuristic 2: Office apps spawning unusual children       │   │
│  │      if (/WINWORD|EXCEL|OUTLOOK/.test(row.parent_process) &&     │   │
│  │          /cmd|powershell|wscript/.test(row.process_name)) {      │   │
│  │        suspicionScore += 0.4;                                    │   │
│  │        row._signals.push('office_spawn_script');                 │   │
│  │      }                                                            │   │
│  │                                                                   │   │
│  │      // Heuristic 3: Rare destination IPs (not RFC1918)          │   │
│  │      if (row.dst_ip && !isPrivateIP(row.dst_ip)) {               │   │
│  │        suspicionScore += 0.2;                                    │   │
│  │        row._signals.push('public_ip_egress');                    │   │
│  │      }                                                            │   │
│  │                                                                   │   │
│  │      row._quick_risk = suspicionScore;                           │   │
│  │      row.verdict = suspicionScore > 0.5 ? 'SUSPICIOUS' :         │   │
│  │                    'PASSED';                                     │   │
│  │    });                                                            │   │
│  │    return rows.sort((a,b) => b._quick_risk - a._quick_risk);     │   │
│  │  }                                                                │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Display Results in HTML Table:                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Row | Verdict      | Process          | Signals                 │   │
│  │  ────|─────────────|──────────────────|─────────────────────    │   │
│  │  1   | SUSPICIOUS  | powershell.exe    | ps_encoded, public_ip   │   │
│  │  2   | SUSPICIOUS  | cmd.exe           | office_spawn_script     │   │
│  │  3   | PASSED      | chrome.exe        | —                       │   │
│  │  ...                                                              │   │
│  │  4998 PASSED rows hidden (click "Show All" to expand)            │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  💡 Business Value: Analyst sees top 50 suspicious rows immediately     │
│     (latency: <1 second for 5k rows)                                    │
└─────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  STEP 3: ANALYST SELECTS ROWS FOR DEEP ANALYSIS                         │
│  ────────────────────────────────────────────────────────────────────   │
│  🎯 Business: "Run the full pipeline on these 100 suspicious rows"      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  User Actions:                                                           │
│  Option A: Click "Select All Suspicious" (auto-selects verdict=SUSP)    │
│  Option B: Manually check boxes for specific rows                       │
│  Option C: Keep default (top 25 by DREAD score)                         │
│                                                                          │
│  Result: 100 rows selected                                              │
│                                                                          │
│  Click Button: "Deep Analyze" (btnAnalyzePipeline)                      │
└─────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  STEP 4: DEEP ANALYZE MODAL (Column Mapping + Options)                  │
│  ────────────────────────────────────────────────────────────────────   │
│  🎯 Business: "My CSV columns have weird names, map them to your schema"│
│  🔧 Technical: Canonical field mapping + analysis mode selection        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Modal Popup (deepAnalyzeModal):                                        │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  ╔════════════════════════════════════════════════════════════╗  │   │
│  │  ║  Deep Analyze Options                               [Close]  ║  │   │
│  │  ╠════════════════════════════════════════════════════════════╣  │   │
│  │  ║                                                             ║  │   │
│  │  ║  Analysis Mode:  ⚪ Basic  ⚫ Advanced                       ║  │   │
│  │  ║  Auto-LLM:       ☑ Enabled                                 ║  │   │
│  │  ║  LLM Summaries:  [Top 25 (DREAD sorted) ▾]                 ║  │   │
│  │  ║  Est. Cost: $0.075                                          ║  │   │
│  │  ║                                                             ║  │   │
│  │  ║  ──────────────────────────────────────────────────────    ║  │   │
│  │  ║  Detected Columns & Mapping:                                ║  │   │
│  │  ║                                                             ║  │   │
│  │  ║  ☑ "TimeGenerated" → [timestamp       ▾]                   ║  │   │
│  │  ║  ☑ "ProcessName"   → [process          ▾]                  ║  │   │
│  │  ║  ☑ "FilePath"      → [file_path        ▾]                  ║  │   │
│  │  ║  ☑ "SHA256Hash"    → [file_hash        ▾]                  ║  │   │
│  │  ║  ☑ "ComputerName"  → [host             ▾]                  ║  │   │
│  │  ║  ☑ "AccountName"   → [user             ▾]                  ║  │   │
│  │  ║  ☑ "SourceIP"      → [ip               ▾]                  ║  │   │
│  │  ║  ☑ "CommandLine"   → [--none--         ▾] (not mapped)     ║  │   │
│  │  ║                                                             ║  │   │
│  │  ║  [Smart Detect All] [Save Preset] [Load Preset: ____ ▾]   ║  │   │
│  │  ║                                                             ║  │   │
│  │  ║  ──────────────────────────────────────────────────────────║  │   │
│  │  ║                                                             ║  │   │
│  │  ║              [Cancel]  [Run Deep Analyze]                   ║  │   │
│  │  ╚════════════════════════════════════════════════════════════╝  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Column Mapping Explained:                                              │
│  - User CSV has "ProcessName" column                                    │
│  - System needs "process" field for stages to work                      │
│  - Modal auto-detects likely matches (regex patterns)                   │
│  - User confirms or adjusts dropdown                                    │
│                                                                          │
│  Analysis Modes:                                                         │
│  • Basic (20 signals):                                                  │
│      - Core detection stages (1-20 from live pipeline)                  │
│      - Fast (avg 50ms per row)                                          │
│      - Sufficient for 90% of use cases                                  │
│  • Advanced (full signal set):                                          │
│      - Includes eBPF/syscall analysis (if data present)                 │
│      - PCAP artifact extraction (if network capture columns)            │
│      - Slower (avg 150ms per row) but more thorough                     │
│                                                                          │
│  User Clicks: "Run Deep Analyze"                                        │
└─────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  STEP 5: SERVER-SIDE DEEP ANALYZE (21-STAGE PIPELINE)                   │
│  ────────────────────────────────────────────────────────────────────   │
│  🎯 Business: "Run the FULL analysis (same as live events)"             │
│  🔧 Technical: POST /api/v1/assessments/deep_analyze                    │
│  📂 Code: src/api/deep_analyze_endpoints.py                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Request Payload:                                                        │
│  {                                                                       │
│    "rows": [ {100 selected rows} ],                                     │
│    "mapping": {                                                          │
│      "process": "ProcessName",                                          │
│      "file_hash": "SHA256Hash",                                         │
│      "host": "ComputerName",                                            │
│      ...                                                                 │
│    },                                                                    │
│    "analyze_mode": "basic",  // or "advanced"                           │
│    "auto_llm": true,                                                    │
│    "llm_limit": 25                                                      │
│  }                                                                       │
│                                                                          │
│  ──────────────────────────────────────────────────────────────────────│
│  21-STAGE PIPELINE EXECUTION (Async Processing)                         │
│  ──────────────────────────────────────────────────────────────────────│
│                                                                          │
│  Progress Bar (Updates via Server-Sent Events):                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Deep Analyze Progress                                   15%     │   │
│  │  ▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░      │   │
│  │  Stage 3/21: Baseline Drift... (elapsed: 2.3s)                   │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  *** STAGES 1-21 (Detailed Breakdown) ***                               │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  STAGE 1: Field Normalization                          (5ms)     │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  Apply user's mapping:                                           │   │
│  │    row["process"] = row["ProcessName"]                           │   │
│  │    row["file_hash"] = row["SHA256Hash"]                          │   │
│  │  Validate required fields exist (process, host, timestamp)       │   │
│  │  Convert timestamps to Unix epoch                                │   │
│  │  Output: Canonical row format                                    │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  STAGE 2: GeoIP Enrichment                             (8ms)     │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  For each IP field (src_ip, dst_ip):                             │   │
│  │    - Lookup in MaxMind GeoIP2 database                           │   │
│  │    - Add fields: country, city, asn, lat, lon                    │   │
│  │  Example:                                                         │   │
│  │    dst_ip: "203.0.113.66" → country: "RU", asn: "AS12345"        │   │
│  │  Factors added:                                                   │   │
│  │    - "geoip_russia" (if country=RU)                              │   │
│  │    - "geoip_high_risk_asn" (if ASN in watchlist)                 │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  STAGE 3: Threat Intel IOC Lookup                      (12ms)    │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  Check file_hash, IPs, domains against:                          │   │
│  │    - Local threat feed cache (Redis)                             │   │
│  │    - VirusTotal API (if hash not in cache)                       │   │
│  │    - AlienVault OTX                                              │   │
│  │  Example:                                                         │   │
│  │    file_hash: "d41d8cd..." → VT score: 45/70 engines flagged     │   │
│  │  Factors added:                                                   │   │
│  │    - "threat_intel_vt_malicious" (+0.30)                         │   │
│  │    - "threat_intel_otx_pulse" (+0.15)                            │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  STAGE 4: HopGraph Ingestion                           (15ms)    │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  Build temporal entity graph:                                    │   │
│  │    - Create nodes: user, host, process, ip                       │   │
│  │    - Create edges: auth, spawn, connect                          │   │
│  │    - Time-weight edges (recent = higher importance)              │   │
│  │  Example:                                                         │   │
│  │    [User:alice] --spawn(ts:1000)--> [Process:powershell]         │   │
│  │    [Process:powershell] --connect(ts:1002)--> [IP:203.0.113.66]  │   │
│  │  Graph stored in-memory (NetworkX) + SQLite persistence          │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  STAGE 5-8: Primitive Checks (see live architecture doc)         │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  (Allowlist, Dedup, Baseline, User Role, Time Window, Asset)     │   │
│  │  Total: 20ms                                                      │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  STAGE 9-14: Network Analysis                          (35ms)    │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  (JA3/JA3S, DNS Tunnel, Beaconing, HTTP Anomaly, Port Scan,      │   │
│  │   Lateral Movement detection)                                    │   │
│  │  Example factor: "ssl:ja3_rare" if JA3 hash seen <100 times      │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  STAGE 15-20: Behavioral Analysis                      (45ms)    │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  (Process Lineage, LOLBin, Persistence, Priv Esc, Cred Access,   │   │
│  │   Data Staging detection)                                        │   │
│  │  Example: "office_macro_spawn_powershell" (+0.18 risk)           │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  STAGE 21: Advanced Signals (if mode=advanced)        (60ms)     │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  • eBPF Syscall Analysis:                                        │   │
│  │      - If CSV contains syscall column (from Falco/Tetragon)      │   │
│  │      - Detect: execve to sensitive paths, ptrace abuse, etc.     │   │
│  │      - Factors: "ebpf_suspicious_execve", "ebpf_ptrace_inject"   │   │
│  │                                                                   │   │
│  │  • PCAP Artifact Extraction:                                     │   │
│  │      - If CSV contains pcap_file column or network bytes         │   │
│  │      - Parse protocol headers, extract payloads                  │   │
│  │      - Factors: "pcap_cleartext_creds", "pcap_malformed_packet"  │   │
│  │                                                                   │   │
│  │  Note: Skipped if data not present (graceful degradation)        │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Total Pipeline Time: ~200ms per row × 100 rows = 20 seconds            │
│  (Parallelized with ThreadPoolExecutor, actual wall time: ~8 seconds)   │
│                                                                          │
│  ──────────────────────────────────────────────────────────────────────│
│  CORRELATION & RISK SYNTHESIS (Post-Pipeline)                           │
│  ──────────────────────────────────────────────────────────────────────│
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Cross-Row Correlation (HopGraph Motif Detection)                │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  Now that all 100 rows are in graph, run global analysis:        │   │
│  │                                                                   │   │
│  │  Motif 1: Multi-host lateral spread                              │   │
│  │    IF same user appears on >3 hosts within 15 minutes            │   │
│  │    THEN add factor "lateral_velocity_hph" to ALL related rows    │   │
│  │                                                                   │   │
│  │  Motif 2: Credential theft → lateral movement chain              │   │
│  │    IF (credential_lsass_dump on host A) AND                      │   │
│  │       (lateral_rdp to host B within 10 min) AND                  │   │
│  │       (same user on both)                                        │   │
│  │    THEN add "CORR_CRED_THEFT_LATERAL" (+0.25 to all 3 events)    │   │
│  │                                                                   │   │
│  │  Example Attack Path Detected:                                   │   │
│  │    Row 15: alice @ ws-01 → lsass dump                            │   │
│  │    Row 23: alice @ ws-01 → RDP to ws-02                          │   │
│  │    Row 31: alice @ ws-02 → RDP to dc-prod                        │   │
│  │    Row 42: alice @ dc-prod → DCSync replication                  │   │
│  │    → Factor "graph_attack_path_dc_compromise" added to all 4     │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Final Risk & Confidence Scores (per row)                        │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  For each row:                                                    │   │
│  │    base_risk = Σ(factor_weights)                                 │   │
│  │    temporal_boost = rarity × 0.1                                 │   │
│  │    correlation_bonus = Σ(correlation_factors)                    │   │
│  │    final_risk = base + temporal + correlation                    │   │
│  │    confidence = f(factor_count, consensus, rarity)               │   │
│  │                                                                   │   │
│  │  Example Row Result:                                              │   │
│  │    {                                                              │   │
│  │      "row_id": 15,                                               │   │
│  │      "verdict": "MALICIOUS",                                     │   │
│  │      "risk": 0.92,                                               │   │
│  │      "confidence": 0.88,                                         │   │
│  │      "factors": [                                                │   │
│  │        "credential_lsass_dump",                                  │   │
│  │        "privilege_escalation",                                   │   │
│  │        "CORR_CRED_THEFT_LATERAL",                                │   │
│  │        "graph_attack_path_dc_compromise"                         │   │
│  │      ],                                                           │   │
│  │      "mitre": ["T1003.001", "T1078", "T1558.003"],               │   │
│  │      "narrative": null  // Will be filled by LLM in next step    │   │
│  │    }                                                              │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Server Response (after 21 stages complete):                            │
│  {                                                                       │
│    "assessment_id": "assess_abc123",                                    │
│    "total_rows": 100,                                                   │
│    "malicious": 8,                                                      │
│    "suspicious": 22,                                                    │
│    "passed": 70,                                                        │
│    "stage_status": [                                                    │
│      {"stage": "GeoIP", "status": "done", "elapsed_ms": 8.2},          │
│      {"stage": "ThreatIntel", "status": "done", "elapsed_ms": 12.5},   │
│      ...                                                                │
│    ],                                                                   │
│    "rows": [ {100 enriched rows with factors, risk, verdict} ]         │
│  }                                                                       │
└─────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
                              *** (Continued in Part 2) ***
