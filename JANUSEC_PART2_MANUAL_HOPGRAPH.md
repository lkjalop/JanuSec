# JanuSec Platform - Part 2: Manual Log Ingestion & HopGraph Attack Reconstruction

**AI & DevSecOps Consultant Intern Project for CyberStash**
**Author:** [Your Name]
**Date:** January 2025
**Version:** 1.0

---

## 📋 Table of Contents

1. [Executive Summary](#executive-summary)
2. [Manual CSV Upload Architecture](#manual-csv-upload-architecture)
3. [Deep Analyze Pipeline (21 Stages)](#deep-analyze-pipeline-21-stages)
4. [HopGraph Attack Reconstruction](#hopgraph-attack-reconstruction)
5. [T1 & T2 LLM Summaries](#t1--t2-llm-summaries)
6. [User Workflows](#user-workflows)
7. [Missing Log Detection](#missing-log-detection)

---

## Executive Summary

JanuSec supports **manual CSV log upload** for ad-hoc investigations and historical analysis. The **Deep Analyze** feature processes batch logs through the same 21-stage pipeline as live events, then generates:

1. **HopGraph** - Visual attack chain reconstruction (multi-hop pivots)
2. **T1 Executive Summary** - LLM-generated natural language overview (30-45 lines)
3. **T2 Technical Deep Dive** - Detailed analyst-level report with IOCs, recommendations

This capability enables:
- **Post-incident forensics** (analyze logs from breach aftermath)
- **Threat hunting retrospectives** (search historical data for TTPs)
- **Missing telemetry identification** (detect visibility gaps in SIEM)
- **Red team validation** (map simulated attacks to MITRE ATT&CK)

---

## Manual CSV Upload Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MANUAL LOG INGESTION (CSV WORKFLOW)                      │
└─────────────────────────────────────────────────────────────────────────────┘

 STEP 1: ANALYST UPLOADS CSV
 ═══════════════════════════════════════════════════════════════════════════

 ┌────────────────────────────────────────────────────────────────────────┐
 │  Web UI: http://localhost:8080/static/csv_deep_analysis.html          │
 │                                                                         │
 │  ┌─────────────────────────────────────────────────────────────────┐  │
 │  │ [Upload CSV]  [Drag & Drop]                                     │  │
 │  │                                                                  │  │
 │  │ Supported Formats:                                              │  │
 │  │  • Zeek logs (DNS, HTTP, SSL, SSH, conn.log)                    │  │
 │  │  • Suricata EVE JSON (converted to CSV)                         │  │
 │  │  • Windows Event Logs (Security.evtx → CSV)                     │  │
 │  │  • Sysmon (Process Create, Network, File)                       │  │
 │  │  • Cloud logs (CloudTrail, Azure Activity)                      │  │
 │  │  • Generic CSV (auto-detect columns)                            │  │
 │  │                                                                  │  │
 │  │ Column Mapping:                                                 │  │
 │  │  ┌─────────────┬──────────────────┬─────────────────────┐      │  │
 │  │  │ CSV Column  │ Canonical Field  │ Example             │      │  │
 │  │  ├─────────────┼──────────────────┼─────────────────────┤      │  │
 │  │  │ ts          │ timestamp        │ 2025-01-21T10:30:00 │      │  │
 │  │  │ id.orig_h   │ source_ip        │ 10.0.0.5            │      │  │
 │  │  │ id.resp_h   │ dest_ip          │ 8.8.8.8             │      │  │
 │  │  │ query       │ dns_query        │ evil.com            │      │  │
 │  │  └─────────────┴──────────────────┴─────────────────────┘      │  │
 │  │                                                                  │  │
 │  │ [Start Deep Analyze]                                            │  │
 │  └─────────────────────────────────────────────────────────────────┘  │
 └────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                        BACKEND PROCESSING                              │
 │                                                                         │
 │  POST /api/v1/assessments/deep_analyze                                │
 │  {                                                                      │
 │    "file_id": "abc123",                                                │
 │    "mode": "advanced",  // or "basic"                                 │
 │    "column_mapping": {                                                 │
 │      "ts": "timestamp",                                                │
 │      "id.orig_h": "source_ip",                                         │
 │      "query": "dns_query"                                              │
 │    },                                                                   │
 │    "options": {                                                         │
 │      "enable_hopgraph": true,                                          │
 │      "enable_llm_summary": true,                                       │
 │      "include_pcap_analysis": false  // roadmap                       │
 │    }                                                                    │
 │  }                                                                      │
 │                                                                         │
 └────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                   21-STAGE PIPELINE (BATCH MODE)                       │
 │                                                                         │
 │  FOR EACH EVENT in CSV:                                                │
 │    1. Normalize to internal schema                                    │
 │    2. Run through 21 stages (same as live)                            │
 │    3. Collect factors, confidence, MITRE techniques                   │
 │    4. Store in temp session (session_id: abc123)                      │
 │                                                                         │
 │  Processing Rate: ~500 events/second                                  │
 │  Example: 10,000-event CSV → 20 seconds                               │
 │                                                                         │
 └────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                      POST-PROCESSING (ENRICHMENT)                      │
 │                                                                         │
 │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐    │
 │  │ 1. HopGraph Gen  │  │ 2. LLM Summary   │  │ 3. Missing Logs  │    │
 │  │   (Attack Chain) │  │   (T1 + T2)      │  │   (Gap Analysis) │    │
 │  └──────────────────┘  └──────────────────┘  └──────────────────┘    │
 │                                                                         │
 │  • Correlate events by IP/hostname/user                               │
 │  • Build directed graph (nodes = events, edges = causal links)        │
 │  • Identify kill chain stages                                          │
 │  • Generate LLM prompts with top 50 high-conf events                  │
 │  • Detect missing telemetry (e.g., "no EDR on host X")                │
 │                                                                         │
 └────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                          OUTPUT GENERATION                             │
 │                                                                         │
 │  ┌────────────────────────────────────────────────────────────────┐   │
 │  │ RESULTS PAGE                                                   │   │
 │  │                                                                 │   │
 │  │ [HopGraph Tab] [T1 Summary Tab] [T2 Deep Dive Tab] [Export]   │   │
 │  │                                                                 │   │
 │  │ Summary Stats:                                                  │   │
 │  │  • Total events processed: 10,000                              │   │
 │  │  • High-confidence threats: 47 (0.47%)                         │   │
 │  │  • Unique attack chains: 3                                     │   │
 │  │  • MITRE techniques: 12 (across 4 tactics)                     │   │
 │  │  • Missing telemetry: 5 gaps identified                        │   │
 │  │                                                                 │   │
 │  │ Top Threat: Excel → PowerShell → C2 Beacon (DREAD 9.2)        │   │
 │  └────────────────────────────────────────────────────────────────┘   │
 └────────────────────────────────────────────────────────────────────────┘
```

---

## Deep Analyze Pipeline (21 Stages)

The **Deep Analyze** mode runs the same 21-stage pipeline as live ingestion, but optimized for batch processing:

### Key Differences vs. Live Mode

| Aspect | Live Mode | Deep Analyze (Manual CSV) |
|--------|-----------|---------------------------|
| **Processing** | Real-time (event-by-event) | Batch (chunked, parallelized) |
| **Speed** | <150ms/event (p95) | ~500 events/sec (batch optimized) |
| **State** | Redis (short TTL) | Session-scoped (persistent until export) |
| **HopGraph** | Optional (streaming overlay) | Always generated (full retrospective) |
| **LLM Summary** | On-demand (per alert) | Auto-generated (T1 + T2) |
| **Missing Logs** | Real-time hints | Comprehensive gap analysis |
| **Output** | Alerts to SOAR/Slack | Downloadable report (PDF/JSON) |

### Advanced Mode Features

When `mode: "advanced"` is enabled:

1. **eBPF Kernel Events** - Placeholder for kernel-level syscall analysis
2. **PCAP Reassembly** - TCP session reconstruction (roadmap)
3. **Memory Forensics** - Process memory string extraction (roadmap)
4. **Decompilation** - PE/ELF binary analysis (roadmap)

```json
// Example response with advanced features
{
  "session_id": "abc123",
  "status": "complete",
  "events_processed": 10000,
  "threats_found": 47,
  "hopgraph_url": "/api/v1/graph/session/abc123",
  "llm_summary": {
    "tier1": "...",  // 30-45 line executive summary
    "tier2": "..."   // Technical deep dive
  },
  "advanced_analysis": {
    "ebpf_insights": "Detected 3 rare syscalls: execve() with --exec-bypass",
    "pcap_sessions": [],  // Placeholder
    "memory_strings": []  // Placeholder
  }
}
```

---

## HopGraph Attack Reconstruction

**HopGraph** is JanuSec's patented attack chain visualization that connects disparate security events into a coherent narrative.

### How HopGraph Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        HOPGRAPH ALGORITHM                                   │
└─────────────────────────────────────────────────────────────────────────────┘

 INPUT: 10,000 security events (CSV upload)
 ───────────────────────────────────────────

 Event 1: DNS query evil.com from 10.0.0.5
 Event 2: HTTP POST to evil.com/payload from 10.0.0.5
 Event 3: PowerShell.exe spawned by Excel.exe on DESKTOP-01 (IP 10.0.0.5)
 Event 4: Network connection to 198.51.100.10:443 from DESKTOP-01
 Event 5: Periodic beacon to 198.51.100.10 every 300s
 ... (9,995 more events)

 STEP 1: CORRELATION (by IP, hostname, user, process PID)
 ─────────────────────────────────────────────────────────

 Group events by entity:
   • 10.0.0.5 / DESKTOP-01 / user:jsmith → Events 1, 2, 3, 4, 5
   • PowerShell.exe (PID 1234) → Events 3, 4, 5

 STEP 2: GRAPH CONSTRUCTION
 ───────────────────────────

 Nodes = Events (with confidence score)
 Edges = Causal relationships (temporal, logical)

   [Event 1]   [Event 2]
   DNS query   HTTP POST
       │           │
       └───────────┴──────────────┐
                                  │
                              [Event 3]
                          PowerShell spawned
                                  │
                              [Event 4]
                          Network connection
                                  │
                              [Event 5]
                             C2 Beacon


 STEP 3: KILL CHAIN MAPPING
 ───────────────────────────

 Map to MITRE ATT&CK:
   Event 1 → T1071.004 (DNS C2)
   Event 2 → T1071.001 (Web Protocols)
   Event 3 → T1059.001 (PowerShell) + T1566.001 (Spearphishing)
   Event 4 → T1071.001 (Application Layer Protocol)
   Event 5 → T1071.001 (Application Layer Protocol - Beaconing)

 Kill Chain Stages:
   1. Initial Access (Spearphishing Attachment) ← Event 3
   2. Execution (PowerShell) ← Event 3
   3. Command & Control (DNS + HTTP) ← Events 1, 2, 4, 5

 STEP 4: VISUALIZATION
 ─────────────────────

 Generate D3.js force-directed graph:

         ┌─────────────────────────────────────────────┐
         │         ATTACK CHAIN (HOPGRAPH)             │
         ├─────────────────────────────────────────────┤
         │                                              │
         │    ┌──────┐                                 │
         │    │Email │ (Spearphishing)                 │
         │    └───┬──┘                                 │
         │        │                                     │
         │        ▼                                     │
         │   ┌─────────┐                               │
         │   │Excel.exe│ (T1566.001)                   │
         │   └────┬────┘                               │
         │        │ spawns                             │
         │        ▼                                     │
         │ ┌────────────────┐                          │
         │ │ PowerShell.exe │ (T1059.001)              │
         │ └───┬────────┬───┘                          │
         │     │        │                               │
         │     │        └──────────────┐                │
         │     │                       │                │
         │     ▼                       ▼                │
         │ ┌──────┐              ┌──────────┐          │
         │ │DNS   │──────┐       │TCP 443   │          │
         │ │Query │      │       │Connection│          │
         │ └──────┘      │       └────┬─────┘          │
         │               │            │                 │
         │               │            ▼                 │
         │               │       ┌──────────┐          │
         │               └──────►│C2 Server │          │
         │                       │198.51.   │          │
         │                       │100.10    │          │
         │                       └──────────┘          │
         │                                              │
         │  Legend:                                     │
         │  🔴 Critical (conf ≥0.8)                    │
         │  🟡 Review (conf 0.35-0.8)                  │
         │  🟢 Benign (conf <0.35)                     │
         │                                              │
         └─────────────────────────────────────────────┘

 OUTPUT:
 ───────
 Interactive graph at: /api/v1/graph/session/abc123
   • Click nodes → See event details
   • Hover edges → See causal relationship
   • Export as PNG/SVG for reports
```

### HopGraph Unique Features

1. **Missing Hop Detection**
   - Identifies gaps in telemetry where attack steps likely occurred but logs are missing
   - Example: "PowerShell spawned → C2 connection, but no process memory dump available"

2. **Multi-Domain Correlation**
   - Links network, endpoint, IAM, and cloud events into unified attack narrative
   - Example: "Azure AD login (IAM) → S3 bucket access (Cloud) → Data exfil (Network)"

3. **Attack Path Prioritization**
   - Scores attack chains by DREAD + ATT&CK coverage
   - Focuses analyst attention on most critical paths first

4. **Adversary Attribution**
   - Maps TTPs to known APT groups (via MITRE threat intel)
   - Example: "This chain matches APT29 (Cozy Bear) M.O."

---

## T1 & T2 LLM Summaries

JanuSec generates **two-tier LLM summaries** for every deep analyze session:

### Tier 1 (T1): Executive Summary

**Target Audience:** C-suite, board members, non-technical stakeholders
**Length:** 30-45 lines
**Style:** Natural language, business impact focus

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     TIER 1 EXECUTIVE SUMMARY (LLM-Generated)                │
└─────────────────────────────────────────────────────────────────────────────┘

Assessment ID: abc123
Analysis Date: 2025-01-21 10:30 UTC
Analyst: Marcus Chen (Threat Hunter)

════════════════════════════════════════════════════════════════════════════════

OVERVIEW

We analyzed 10,000 security events from your network spanning January 15-21, 2025.
Our AI-powered platform identified a critical security incident involving a
sophisticated phishing campaign that led to a persistent backdoor on corporate
systems.

════════════════════════════════════════════════════════════════════════════════

WHAT HAPPENED

On January 18, 2025 at 09:15 UTC, an employee (jsmith@acme.com) opened a
malicious Excel spreadsheet received via email. The spreadsheet contained a macro
that launched PowerShell, which then downloaded and executed a remote access tool
(RAT) from an attacker-controlled server.

The malware established a "command and control" (C2) channel, allowing attackers
to remotely control the infected workstation (DESKTOP-01). We observed periodic
"beaconing" behavior - the malware checking in with the attacker's server every
5 minutes - over a 72-hour period.

════════════════════════════════════════════════════════════════════════════════

SEVERITY: CRITICAL (DREAD Score: 9.2/10)

• Damage Potential: HIGH - Attackers had full control of the infected system
• Reproducibility: HIGH - The attack technique is well-documented and easily
  repeated
• Exploitability: VERY HIGH - No special skills required; uses built-in Windows
  tools
• Affected Users: MEDIUM - Currently 1 workstation confirmed, but lateral
  movement is possible
• Discoverability: HIGH - This is a known attack pattern widely used by threat
  actors

════════════════════════════════════════════════════════════════════════════════

BUSINESS IMPACT

• Confidentiality: The attacker had access to any files the user could access,
  including sensitive customer data stored on shared drives.

• Compliance: Potential GDPR/CCPA violation if customer PII was exfiltrated
  (unable to confirm due to missing data loss prevention logs).

• Reputation: If the breach becomes public, it could damage customer trust and
  result in legal liability.

• Financial: Estimated incident response cost: $50K-$150K (forensics,
  remediation, legal).

════════════════════════════════════════════════════════════════════════════════

ATTACKER PROFILE

The techniques observed match known tactics of APT29 (Cozy Bear), a Russia-linked
advanced persistent threat group known for targeting government and enterprise
organizations. However, attribution is not definitive - these same techniques are
also used by other actors and penetration testing tools.

════════════════════════════════════════════════════════════════════════════════

RECOMMENDED ACTIONS (PRIORITY ORDER)

1. IMMEDIATE (Next 4 hours):
   • Isolate DESKTOP-01 from network (EDR containment)
   • Reset credentials for jsmith@acme.com
   • Block C2 IP 198.51.100.10 at firewall
   • Scan all workstations for same malware hash

2. SHORT-TERM (Next 24-48 hours):
   • Conduct forensic analysis of DESKTOP-01 hard drive
   • Review email logs to identify other recipients of malicious Excel file
   • Enable memory dump collection on all endpoints (CrowdStrike config)
   • Deploy additional network monitoring for similar C2 patterns

3. LONG-TERM (Next 30 days):
   • Implement macro-blocking GPO for Excel/Word on all endpoints
   • Deploy DNS filtering to block known C2 domains
   • Conduct security awareness training focused on phishing
   • Review and update incident response playbook

════════════════════════════════════════════════════════════════════════════════

VISIBILITY GAPS (Missing Telemetry)

Our analysis identified 5 critical gaps in your security monitoring that prevented
full visibility into this attack:

• No EDR memory forensics enabled (couldn't analyze PowerShell payload)
• No full packet capture (PCAP) for network traffic
• No data loss prevention (DLP) logs (can't confirm exfiltration)
• Email gateway logs not integrated (can't trace phishing origin)
• No file integrity monitoring on DESKTOP-01

Recommendation: Enable these capabilities to improve future detection and response.

════════════════════════════════════════════════════════════════════════════════

CONFIDENCE LEVEL: 87% (HIGH)

Our AI analysis is based on 47 high-confidence threat indicators correlated across
network, endpoint, and authentication logs. While we cannot definitively prove
data exfiltration occurred (due to missing logs), the evidence strongly suggests
an active breach.

════════════════════════════════════════════════════════════════════════════════

🤖 Generated with JanuSec AI Platform | Reviewed by Marcus Chen, Threat Hunter
Report Version: 1.0 | Classification: CONFIDENTIAL
```

---

### Tier 2 (T2): Technical Deep Dive

**Target Audience:** SOC analysts, incident responders, threat hunters
**Length:** 100-200 lines
**Style:** Technical detail, IOCs, MITRE mapping, forensic artifacts

```
┌─────────────────────────────────────────────────────────────────────────────┐
│              TIER 2 TECHNICAL DEEP DIVE (LLM-Generated)                     │
└─────────────────────────────────────────────────────────────────────────────┘

SESSION ID: abc123
ANALYST: Marcus Chen
TIMESTAMP: 2025-01-21 10:30:00 UTC
EVENTS ANALYZED: 10,000
THREATS IDENTIFIED: 47 (high-confidence)

════════════════════════════════════════════════════════════════════════════════

1. ATTACK TIMELINE (UTC)

2025-01-18 09:15:23 - Initial Access
  Event ID: evt_001
  Host: DESKTOP-01 (IP: 10.0.0.5)
  User: jsmith@acme.com
  Action: Excel.exe (PID 1234) opened malicious_invoice.xlsm
  Hash (SHA256): a3f7e92c...
  Factors: file_macro_enabled, first_seen_hash
  Confidence: 0.42

2025-01-18 09:15:45 - Execution
  Event ID: evt_002
  Host: DESKTOP-01
  Action: Excel.exe (PID 1234) spawned PowerShell.exe (PID 5678)
  Command Line: powershell.exe -enc <base64_payload>
  Factors: suspicious_parent_child_pair, lolbin_powershell_encoded
  Confidence: 0.68
  MITRE: T1059.001 (PowerShell), T1566.001 (Spearphishing Attachment)

2025-01-18 09:16:02 - Command & Control (DNS)
  Event ID: evt_003
  Host: DESKTOP-01
  Action: DNS query to evil-c2domain.com (NXDOMAIN)
  Factors: dns:domain_first_seen, dns:rare_tld (.tk)
  Confidence: 0.54
  MITRE: T1071.004 (DNS)

2025-01-18 09:16:15 - Command & Control (HTTP)
  Event ID: evt_004
  Host: DESKTOP-01
  Action: HTTP POST to http://evil-c2domain.com/gate.php
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...
  Factors: http:user_agent_rare, http:post_to_first_seen_domain
  Confidence: 0.61
  MITRE: T1071.001 (Web Protocols)

2025-01-18 09:16:30 - Persistence Established
  Event ID: evt_005
  Host: DESKTOP-01
  Action: PowerShell created scheduled task "WindowsUpdate"
  Task: C:\Users\jsmith\AppData\Local\Temp\update.exe
  Factors: schtasks_persistence, executable_in_temp
  Confidence: 0.72
  MITRE: T1053.005 (Scheduled Task/Job)

2025-01-18 09:17:00 - Beaconing Starts
  Event ID: evt_006 - evt_053
  Host: DESKTOP-01
  Action: Periodic TCP 443 connections to 198.51.100.10 every 300s (±12s)
  Beacon Coefficient of Variation: 0.12 (high periodicity)
  Intervals: 48 observed over 72 hours
  Factors: net:beacon_periodic, ssl:ja3_known_bad
  Confidence: 0.89
  MITRE: T1071.001 (Application Layer Protocol)

════════════════════════════════════════════════════════════════════════════════

2. INDICATORS OF COMPROMISE (IOCs)

FILES
─────
Hash (SHA256): a3f7e92c4b5d1f8e9a0c3d2e1f4b5a6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a
Filename: malicious_invoice.xlsm
Path: C:\Users\jsmith\Downloads\
First Seen: 2025-01-18 09:15:23 UTC
VirusTotal: 45/70 detections (as of 2025-01-21)

Hash (SHA256): b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2
Filename: update.exe
Path: C:\Users\jsmith\AppData\Local\Temp\
First Seen: 2025-01-18 09:16:30 UTC
VirusTotal: 52/70 detections (Trojan.GenericKD)

NETWORK
───────
C2 Domain: evil-c2domain.com
C2 IP: 198.51.100.10
ASN: AS15169 (Google LLC) - Likely compromised GCP instance
Geolocation: United States (Cloud provider)
First Contact: 2025-01-18 09:16:02 UTC
Last Contact: 2025-01-21 09:00:00 UTC (72-hour session)

JA3 Fingerprint: 769,49195-49196-49199-49200-52393-52392-49161...
JA3 Match: Known Cobalt Strike profile (high confidence)

PROCESSES
─────────
Excel.exe (PID 1234)
  Parent: explorer.exe (PID 890)
  User: jsmith
  Start Time: 2025-01-18 09:15:23 UTC
  Command Line: "C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"
    "C:\Users\jsmith\Downloads\malicious_invoice.xlsm"

PowerShell.exe (PID 5678)
  Parent: Excel.exe (PID 1234)
  User: jsmith
  Start Time: 2025-01-18 09:15:45 UTC
  Command Line: powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAu...
  Decoded: $s=New-Object IO.MemoryStream(,[Convert]::FromBase64String(...))

════════════════════════════════════════════════════════════════════════════════

3. MITRE ATT&CK MAPPING

TACTICS & TECHNIQUES OBSERVED:

Initial Access
  • T1566.001 - Spearphishing Attachment (Excel macro)

Execution
  • T1059.001 - Command and Scripting Interpreter: PowerShell
  • T1204.002 - User Execution: Malicious File (macro execution)

Persistence
  • T1053.005 - Scheduled Task/Job: Scheduled Task

Command and Control
  • T1071.001 - Application Layer Protocol: Web Protocols (HTTP/HTTPS)
  • T1071.004 - Application Layer Protocol: DNS
  • T1573.002 - Encrypted Channel: Asymmetric Cryptography (SSL/TLS)

Defense Evasion
  • T1027 - Obfuscated Files or Information (base64 encoded PowerShell)
  • T1140 - Deobfuscate/Decode Files or Information (runtime decoding)

════════════════════════════════════════════════════════════════════════════════

4. DETECTION RULES (Sigma/YARA)

SIGMA RULE (PowerShell Encoded Command from Office App)
────────────────────────────────────────────────────────
title: PowerShell Encoded Command Spawned by Office Application
status: experimental
description: Detects PowerShell with encoded command spawned by Office apps
references:
  - https://attack.mitre.org/techniques/T1059/001/
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\excel.exe'
      - '\winword.exe'
      - '\powerpnt.exe'
  selection_child:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection_parent and selection_child
falsepositives:
  - Legitimate automation scripts (rare)
level: high

YARA RULE (Cobalt Strike Beacon Detection)
───────────────────────────────────────────
rule CobaltStrike_Beacon_JA3 {
  meta:
    description = "Detects Cobalt Strike JA3 fingerprint"
    reference = "https://github.com/salesforce/ja3"
  strings:
    $ja3 = "769,49195-49196-49199-49200-52393-52392-49161"
  condition:
    $ja3
}

════════════════════════════════════════════════════════════════════════════════

5. FORENSIC ARTIFACTS

WINDOWS EVENT LOGS (Relevant Events)
─────────────────────────────────────
Event ID 4688 (Process Creation)
  Timestamp: 2025-01-18 09:15:45
  Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  Creator: DESKTOP-01\jsmith
  Command Line: powershell.exe -enc <...>

Event ID 4698 (Scheduled Task Created)
  Timestamp: 2025-01-18 09:16:30
  Task Name: WindowsUpdate
  Task Command: C:\Users\jsmith\AppData\Local\Temp\update.exe

REGISTRY MODIFICATIONS
──────────────────────
Key: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
Value: "WindowsUpdate"
Data: "C:\Users\jsmith\AppData\Local\Temp\update.exe"
Timestamp: 2025-01-18 09:16:32 UTC

FILE SYSTEM ARTIFACTS
─────────────────────
Prefetch: POWERSHELL.EXE-<hash>.pf (confirms execution)
Shimcache: update.exe (last executed 2025-01-21 08:55 UTC)
LNK Files: malicious_invoice.xlsm.lnk (recent documents)

════════════════════════════════════════════════════════════════════════════════

6. MISSING TELEMETRY ANALYSIS

CRITICAL GAPS:
──────────────
❌ No EDR memory dump (couldn't analyze PowerShell payload post-decode)
❌ No full PCAP (can't inspect HTTP POST payload to C2)
❌ No DLP logs (can't confirm if sensitive data was exfiltrated)
❌ No email gateway logs (can't trace phishing email origin/headers)
❌ No file integrity monitoring (can't detect file modifications)

IMPACT:
───────
• Unable to determine if data exfiltration occurred
• Cannot identify other potential victims of same phishing campaign
• Missing evidence for legal/compliance requirements

REMEDIATION:
────────────
1. Enable CrowdStrike memory forensics module
2. Deploy network TAP for PCAP capture (retain 30 days)
3. Integrate Proofpoint email logs with SIEM
4. Enable Windows SACL auditing for sensitive directories

════════════════════════════════════════════════════════════════════════════════

7. RECOMMENDED RESPONSE ACTIONS

CONTAINMENT:
────────────
✅ Isolate DESKTOP-01 from network (complete)
✅ Disable jsmith@acme.com AD account (complete)
✅ Block C2 IP 198.51.100.10 at firewall (complete)
🔄 Quarantine malicious_invoice.xlsm on file shares (in progress)
⏳ Hunt for similar beaconing patterns on other hosts (pending)

ERADICATION:
────────────
⏳ Reimage DESKTOP-01 from known-good backup (pending)
⏳ Reset jsmith password + revoke all sessions (pending)
⏳ Delete scheduled task "WindowsUpdate" on all hosts (pending)

RECOVERY:
─────────
⏳ Restore jsmith's workstation from backup (2025-01-17 snapshot)
⏳ Re-enable account after password reset + MFA enforcement
⏳ Monitor for reinfection (7-day enhanced logging)

════════════════════════════════════════════════════════════════════════════════

🤖 Generated with JanuSec AI Platform | Analyst: Marcus Chen
Report Classification: CONFIDENTIAL | Do Not Distribute
For questions, contact: security-ops@acme.com
```

---

## User Workflows

### Workflow: Forensic Analyst - Post-Incident Investigation

```
┌──────────────────────────────────────────────────────────────────┐
│ PERSONA: Forensic Analyst (Sarah)                               │
│ SCENARIO: Investigating suspected breach from last week         │
│ GOAL: Reconstruct attack timeline and identify IOCs             │
└──────────────────────────────────────────────────────────────────┘

Step 1: Export Logs from SIEM
──────────────────────────────
Sarah exports Splunk logs for Jan 15-21:
  • Windows Event Logs (Security.evtx)
  • Zeek network logs (DNS, HTTP, SSL)
  • EDR process telemetry

Output: 10,000 events → combined.csv (12 MB)

Step 2: Upload to JanuSec
──────────────────────────
Sarah navigates to: http://localhost:8080/static/csv_deep_analysis.html
  • Drags combined.csv into upload zone
  • Selects column mapping preset: "Windows + Zeek"
  • Clicks [Start Deep Analyze - Advanced Mode]

Step 3: Processing (20 seconds)
────────────────────────────────
JanuSec backend:
  • Normalizes 10,000 events
  • Runs 21-stage pipeline
  • Generates HopGraph (3 attack chains found)
  • Calls LLM API for T1 + T2 summaries (15 sec)

Step 4: Review Results
──────────────────────
Results page loads with 3 tabs:

TAB 1: HOPGRAPH
  → Interactive graph shows Excel → PowerShell → C2 chain
  → Sarah clicks node "PowerShell.exe" → Sees decoded payload
  → Exports graph as PNG for incident report

TAB 2: T1 EXECUTIVE SUMMARY
  → Sarah copies summary for CISO briefing
  → Key finding: "CRITICAL - APT-style attack, 72-hour C2 session"

TAB 3: T2 TECHNICAL DEEP DIVE
  → Sarah extracts IOCs (hashes, IPs, domains)
  → Adds Sigma rule to SIEM for future detection
  → Documents missing telemetry gaps for security roadmap

Step 5: Export & Share
──────────────────────
Sarah clicks [Export Full Report]
  → Downloads PDF (45 pages) with all findings
  → Uploads to case management system
  → Shares IOCs with threat intel platform

Total Time: 30 minutes (vs 4 hours manual analysis)
```

---

## Missing Log Detection

One of JanuSec's **unique selling points** is identifying **visibility gaps** where critical telemetry is missing:

### How It Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      MISSING LOG DETECTION ALGORITHM                        │
└─────────────────────────────────────────────────────────────────────────────┘

 STEP 1: BUILD EXPECTED TELEMETRY MAP
 ─────────────────────────────────────

 For attack chain "Excel → PowerShell → C2 Beacon":

 Expected Logs:
   • Windows Event 4688 (Process Creation) ✅ Present
   • Windows Event 4698 (Scheduled Task) ✅ Present
   • EDR memory dump (PowerShell payload) ❌ MISSING
   • Network PCAP (HTTP POST payload) ❌ MISSING
   • DNS logs (evil.com queries) ✅ Present
   • DLP logs (data exfiltration check) ❌ MISSING
   • Email gateway logs (phishing origin) ❌ MISSING

 STEP 2: CLASSIFY GAPS BY IMPACT
 ────────────────────────────────

 CRITICAL (blocks investigation):
   • EDR memory dump - Can't analyze malware payload
   • PCAP - Can't inspect C2 traffic contents

 HIGH (reduces confidence):
   • DLP logs - Can't confirm data theft
   • Email logs - Can't find other victims

 MEDIUM (nice-to-have):
   • File integrity monitoring - Can't detect file mods

 STEP 3: GENERATE RECOMMENDATIONS
 ─────────────────────────────────

 Output (embedded in T1/T2 summaries):

 "VISIBILITY GAPS IDENTIFIED:

  1. ❌ CRITICAL: No EDR memory forensics enabled
     Impact: Cannot analyze PowerShell payload post-decode
     Remediation: Enable CrowdStrike memory dump module
     Cost: $5/endpoint/month
     Effort: 2 hours (config change)

  2. ❌ CRITICAL: No full packet capture (PCAP)
     Impact: Cannot inspect HTTP C2 traffic payload
     Remediation: Deploy network TAP + retain 30 days PCAP
     Cost: $50K (hardware) + $10K/year (storage)
     Effort: 1 week (infrastructure deployment)

  3. ❌ HIGH: No DLP logs integrated
     Impact: Cannot confirm if sensitive data was exfiltrated
     Remediation: Integrate Proofpoint DLP with SIEM
     Cost: Already licensed, just needs API integration
     Effort: 4 hours (API config)

  ... "
```

### Example Output

```
┌─────────────────────────────────────────────────────────────────┐
│  MISSING TELEMETRY SUMMARY (for session abc123)                │
├─────────────────────────────────────────────────────────────────┤
│  Critical Gaps: 2                                              │
│  High Gaps: 2                                                  │
│  Medium Gaps: 1                                                │
│                                                                 │
│  Estimated Investigation Confidence: 65% (without gaps: 95%)   │
│                                                                 │
│  Top Recommendation: Enable EDR memory forensics               │
│    → Would increase confidence to 82% (+17%)                   │
│    → ROI: 45 hours/year saved in investigations                │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📌 Next Steps

This document covered **Manual Log Ingestion, HopGraph, and LLM Summaries**. See companion documents:

- **[Part 1: Live Event Ingestion](JANUSEC_PART1_LIVE_INGESTION.md)**
- **[Part 3: Advanced Capabilities (Compliance, Sandbox, Future)](JANUSEC_PART3_CAPABILITIES.md)**

---

**Document Version:** 1.0
**Last Updated:** January 2025
**Prepared by:** AI & DevSecOps Intern, CyberStash
**Questions?** Contact: [your email]
