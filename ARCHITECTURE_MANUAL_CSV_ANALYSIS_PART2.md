# JanuSec Platform: Manual CSV Analysis Flow (Part 2)
**LLM Summaries → Report Generation → HopGraph Correlation**

*Continuation from Part 1*

---

```
┌─────────────────────────────────────────────────────────────────────────┐
│  STEP 6: LLM TIER 1 SUMMARIES (Auto-Generated)                          │
│  ────────────────────────────────────────────────────────────────────   │
│  🎯 Business: "Explain each threat in plain English"                    │
│  🔧 Technical: Batch LLM calls for top N suspicious rows                │
│  📂 Code: src/analysis/auto_llm.py:build_llm_row                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Trigger: If auto_llm=true, automatically queue LLM jobs                │
│                                                                          │
│  For Top 25 Rows (sorted by DREAD score):                               │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Row 15: credential_lsass_dump + privilege_escalation            │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │                                                                   │   │
│  │  LLM Prompt (Tier 1 - Concise Summary):                          │   │
│  │  ───────────────────────────────────────────────────────────    │   │
│  │  You are a tier-1 SOC analyst. Summarize this security event     │   │
│  │  in 2-3 sentences for triage:                                    │   │
│  │                                                                   │   │
│  │  Event Details:                                                   │   │
│  │  - Timestamp: 2025-01-20 14:32:10                                │   │
│  │  - Host: ws-alice-01                                             │   │
│  │  - User: alice                                                   │   │
│  │  - Process: mimikatz.exe                                         │   │
│  │  - Parent: powershell.exe                                        │   │
│  │  - Command: mimikatz.exe sekurlsa::logonpasswords                │   │
│  │  - File Hash: a3f8d92e1b4c... (not in VirusTotal)                │   │
│  │                                                                   │   │
│  │  Detected Factors:                                                │   │
│  │  - credential_lsass_dump (weight: 0.18)                          │   │
│  │  - privilege_escalation (weight: 0.12)                           │   │
│  │  - lolbin_misuse (weight: 0.20)                                  │   │
│  │  - unsigned_binary (weight: 0.18)                                │   │
│  │  - graph_attack_path_dc_compromise (weight: 0.25)                │   │
│  │                                                                   │   │
│  │  MITRE ATT&CK:                                                    │   │
│  │  - T1003.001 (OS Credential Dumping: LSASS Memory)               │   │
│  │  - T1078 (Valid Accounts)                                        │   │
│  │                                                                   │   │
│  │  Risk Score: 0.92 / 1.0 (CRITICAL)                               │   │
│  │  Confidence: 0.88                                                 │   │
│  │                                                                   │   │
│  │  Provide:                                                         │   │
│  │  1. Verdict (Malicious/Suspicious/Benign)                        │   │
│  │  2. Summary (2-3 sentences)                                      │   │
│  │  3. Urgency (Critical/High/Medium/Low)                           │   │
│  │  4. Recommended Actions (1-2 bullet points)                      │   │
│  │  ───────────────────────────────────────────────────────────    │   │
│  │                                                                   │   │
│  │  LLM Response (Tier 1 - ~80 tokens):                             │   │
│  │  ───────────────────────────────────────────────────────────    │   │
│  │  {                                                                │   │
│  │    "verdict": "Malicious",                                       │   │
│  │    "summary": "User 'alice' executed Mimikatz credential dumping │   │
│  │                tool on workstation ws-alice-01, targeting LSASS  │   │
│  │                memory to extract plaintext passwords. This is    │   │
│  │                part of an attack chain leading to domain         │   │
│  │                controller compromise.",                          │   │
│  │    "urgency": "Critical",                                        │   │
│  │    "actions": [                                                  │   │
│  │      "Immediately isolate ws-alice-01 from network",             │   │
│  │      "Reset credentials for user 'alice' and all domain admins", │   │
│  │      "Review lateral movement attempts to dc-prod"               │   │
│  │    ]                                                              │   │
│  │  }                                                                │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Processing:                                                             │
│  - Model Used: Ollama Llama 3.1 8B (local) OR GPT-4-turbo (cloud)       │
│  - Latency: 300ms (local) or 1.2s (cloud) per row                       │
│  - Cost: $0 (local) or $0.003 (GPT-4) per row                           │
│  - Batch Processing: 25 rows in parallel → 3 seconds total (local)      │
│                                                                          │
│  Result Storage:                                                         │
│  - Tier 1 summary saved to: row._llm_tier1                              │
│  - Visible in table: Hover over "LLM" indicator shows summary           │
│  - Click "LLM T1" button → Opens sidebar with full summary              │
│                                                                          │
│  Display in UI (csv_analyzer.html):                                     │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Row | Verdict    | Process        | LLM | Actions                │   │
│  │  ────|───────────|────────────────|────|────────────────────    │   │
│  │  15  | MALICIOUS | mimikatz.exe    | ✓  | [View T1] [View T2]    │   │
│  │                                                                   │   │
│  │  ┌─────────────────────── LLM Tier 1 Sidebar ─────────────────┐  │   │
│  │  │  Row 15: mimikatz.exe                                       │  │   │
│  │  │                                                              │  │   │
│  │  │  🔴 CRITICAL URGENCY                                        │  │   │
│  │  │                                                              │  │   │
│  │  │  User 'alice' executed Mimikatz credential dumping tool on  │  │   │
│  │  │  workstation ws-alice-01, targeting LSASS memory to extract │  │   │
│  │  │  plaintext passwords. This is part of an attack chain       │  │   │
│  │  │  leading to domain controller compromise.                   │  │   │
│  │  │                                                              │  │   │
│  │  │  📋 Recommended Actions:                                    │  │   │
│  │  │  • Immediately isolate ws-alice-01 from network             │  │   │
│  │  │  • Reset credentials for user 'alice' and all domain admins │  │   │
│  │  │  • Review lateral movement attempts to dc-prod              │  │   │
│  │  │                                                              │  │   │
│  │  │  Cost: $0.003 | Model: GPT-4-turbo                          │  │   │
│  │  │                                                              │  │   │
│  │  │  [Close]  [Escalate to Tier 2 Investigation]                │  │   │
│  │  └──────────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  💡 Business Value:                                                      │
│  - Analyst reads 80-token summary vs 500-line raw log                   │
│  - Triage time: 2 minutes → 10 seconds per alert                        │
│  - Non-technical stakeholders can understand threats                    │
└─────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  STEP 7: TIER 2 INVESTIGATIVE DEEP DIVE (On-Demand)                     │
│  ────────────────────────────────────────────────────────────────────   │
│  🎯 Business: "I need forensic-level detail for this one incident"      │
│  🔧 Technical: Extended LLM prompt with full context (200+ line output) │
│  📂 Code: src/api/insights_endpoints.py:generate_tier2_investigation    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Trigger: Analyst clicks "T2: Investigate" button (llmSidebarT2)        │
│                                                                          │
│  Enhanced Prompt (Tier 2 - Comprehensive Analysis):                     │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  You are a senior threat hunter conducting a deep investigation. │   │
│  │  Provide a comprehensive analysis of this incident.               │   │
│  │                                                                   │   │
│  │  === INCIDENT CONTEXT ===                                         │   │
│  │  Incident ID: assess_abc123_row_15                                │   │
│  │  Timestamp: 2025-01-20 14:32:10 UTC                               │   │
│  │  Host: ws-alice-01 (Windows 10, Domain: CORP)                     │   │
│  │  User: alice (Accounting Department, Standard User)               │   │
│  │                                                                   │   │
│  │  === PRIMARY EVENT ===                                            │   │
│  │  Process: mimikatz.exe                                            │   │
│  │  Parent: powershell.exe (spawned by WINWORD.EXE)                  │   │
│  │  Command Line: mimikatz.exe sekurlsa::logonpasswords              │   │
│  │  File Path: C:\Users\alice\AppData\Local\Temp\mimikatz.exe       │   │
│  │  File Hash (SHA256): a3f8d92e1b4c5f7a9d2e3b1c8a4f6e9d2a1b...     │   │
│  │  Signed: No                                                       │   │
│  │  VirusTotal: Not found (likely custom build)                      │   │
│  │                                                                   │   │
│  │  === ATTACK CHAIN (HopGraph Reconstruction) ===                   │   │
│  │  10:15 AM - Email attachment opened (Invoice.docm)                │   │
│  │  10:16 AM - Macro executed → PowerShell payload                   │   │
│  │  10:17 AM - PowerShell downloads mimikatz.exe from 203.0.113.66   │   │
│  │  10:18 AM - Mimikatz dumps LSASS (THIS EVENT)                     │   │
│  │  10:22 AM - RDP connection to ws-bob-02 (lateral movement)        │   │
│  │  10:28 AM - RDP connection to dc-prod (domain controller)         │   │
│  │  10:30 AM - DCSync replication request (credential theft)         │   │
│  │                                                                   │   │
│  │  === NETWORK CONTEXT ===                                          │   │
│  │  C2 Server: 203.0.113.66 (Russia, ASN 12345 "Evil Hosting")       │   │
│  │  JA3 Fingerprint: a3b2c1... (rare, <50 global observations)       │   │
│  │  DNS Queries: malware-c2.xyz (newly registered domain, 2 days)    │   │
│  │  Beaconing Pattern: Every 60 seconds (coefficient of variation:   │   │
│  │                     0.008 - highly periodic)                      │   │
│  │                                                                   │   │
│  │  === SIMILAR INCIDENTS (Vector DB Lookup) ===                     │   │
│  │  • 3 similar incidents in past 30 days (same JA3, different IPs)  │   │
│  │  • TTP match with APT29 (Cozy Bear) campaign (85% similarity)     │   │
│  │  • Same phishing template seen in VirusTotal submissions           │   │
│  │                                                                   │   │
│  │  === MISSING LOG SOURCES (Gaps in Visibility) ===                 │   │
│  │  ⚠️ No email gateway logs (can't confirm attachment source)       │   │
│  │  ⚠️ No full PCAP (can't see encrypted C2 payload)                 │   │
│  │  ✅ Have: Sysmon, Windows Security, EDR telemetry                 │   │
│  │                                                                   │   │
│  │  === QUESTION FOR ANALYSIS ===                                    │   │
│  │  Provide the following in your response:                          │   │
│  │                                                                   │   │
│  │  1. **Executive Summary** (2-3 paragraphs)                        │   │
│  │     - What happened, who was targeted, impact                     │   │
│  │                                                                   │   │
│  │  2. **Detailed Timeline** (chronological with timestamps)         │   │
│  │     - All events leading up to and after this incident            │   │
│  │                                                                   │   │
│  │  3. **Threat Actor Attribution** (if applicable)                  │   │
│  │     - Known APT groups, malware families, campaigns               │   │
│  │                                                                   │   │
│  │  4. **MITRE ATT&CK Mapping** (full kill chain)                    │   │
│  │     - Tactics, Techniques, Sub-techniques with IDs                │   │
│  │                                                                   │   │
│  │  5. **Indicators of Compromise (IOCs)**                           │   │
│  │     - File hashes, IPs, domains, registry keys, etc.              │   │
│  │                                                                   │   │
│  │  6. **Scope of Compromise**                                       │   │
│  │     - How many hosts/users potentially affected?                  │   │
│  │     - What data was accessed/exfiltrated?                         │   │
│  │                                                                   │   │
│  │  7. **Recommended Remediation Steps** (prioritized)               │   │
│  │     - Immediate containment actions                               │   │
│  │     - Eradication steps                                           │   │
│  │     - Recovery procedures                                         │   │
│  │     - Long-term preventive measures                               │   │
│  │                                                                   │   │
│  │  8. **Collection Playbook** (missing logs to gather)              │   │
│  │     - What additional data sources would improve analysis?        │   │
│  │     - Specific queries for SIEM, EDR, firewall, etc.              │   │
│  │                                                                   │   │
│  │  Format: Markdown with headers, bullet points, code blocks        │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  LLM Response (Tier 2 - ~1200 tokens / 200+ lines):                     │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  # Incident Investigation Report: Mimikatz Credential Theft      │   │
│  │                                                                   │   │
│  │  **Incident ID**: assess_abc123_row_15                            │   │
│  │  **Date**: 2025-01-20                                             │   │
│  │  **Analyst**: AI Tier 2 (Verified by Human Analyst Required)     │   │
│  │  **Severity**: CRITICAL                                           │   │
│  │                                                                   │   │
│  │  ---                                                               │   │
│  │                                                                   │   │
│  │  ## Executive Summary                                             │   │
│  │                                                                   │   │
│  │  On January 20, 2025, user Alice from the Accounting Department   │   │
│  │  fell victim to a sophisticated phishing campaign resulting in    │   │
│  │  full domain compromise. The attack began with a malicious macro- │   │
│  │  enabled Word document delivered via email, which deployed a      │   │
│  │  PowerShell payload to download and execute Mimikatz, a           │   │
│  │  credential-harvesting tool. The attacker successfully extracted  │   │
│  │  LSASS memory contents, obtained domain credentials, and pivoted  │   │
│  │  laterally to the domain controller within 15 minutes.            │   │
│  │                                                                   │   │
│  │  The attack chain matches known APT29 (Cozy Bear) tactics with    │   │
│  │  85% similarity, suggesting a state-sponsored threat actor or     │   │
│  │  sophisticated cybercriminal group. Immediate containment and     │   │
│  │  credential rotation across the entire domain is critical to      │   │
│  │  prevent further compromise.                                      │   │
│  │                                                                   │   │
│  │  **Impact**: Compromise of 3 hosts, 1 domain controller, and      │   │
│  │  potential access to all domain user credentials. Estimated scope │   │
│  │  affects 250+ users and servers in the CORP domain.               │   │
│  │                                                                   │   │
│  │  ---                                                               │   │
│  │                                                                   │   │
│  │  ## Detailed Timeline                                             │   │
│  │                                                                   │   │
│  │  **T-0 (10:15 AM)** - Initial Compromise                          │   │
│  │  - User Alice receives phishing email with attachment             │   │
│  │    "Invoice_Jan2025.docm"                                         │   │
│  │  - Subject line: "Urgent: Payment Overdue - Action Required"      │   │
│  │  - Sender: finance@trusted-vendor[.]com (typosquatting)           │   │
│  │  - Attachment opened on ws-alice-01                               │   │
│  │                                                                   │   │
│  │  **T+1 min (10:16 AM)** - Macro Execution                         │   │
│  │  - Event ID 4688: Process Created                                 │   │
│  │    - Parent: WINWORD.EXE (PID 4521)                               │   │
│  │    - Child: powershell.exe -ExecutionPolicy Bypass -WindowStyle   │   │
│  │      Hidden -EncodedCommand [base64 blob]                         │   │
│  │  - MITRE: T1566.001 (Phishing: Spearphishing Attachment)          │   │
│  │           T1059.001 (PowerShell)                                  │   │
│  │                                                                   │   │
│  │  **T+2 min (10:17 AM)** - C2 Communication & Payload Download     │   │
│  │  - DNS Query: malware-c2.xyz → 203.0.113.66                       │   │
│  │  - HTTPS GET request to hxxps://203.0.113[.]66/stage2.exe         │   │
│  │    - JA3: a3b2c1d4e5... (rare fingerprint)                        │   │
│  │    - User-Agent: "Mozilla/5.0 (compatible; MSIE 9.0)" (outdated)  │   │
│  │  - File written: C:\Users\alice\AppData\Local\Temp\mimikatz.exe   │   │
│  │  - MITRE: T1071.001 (Web Protocols), T1105 (Ingress Tool Transfer)│   │
│  │                                                                   │   │
│  │  **T+3 min (10:18 AM)** - Credential Harvesting (PRIMARY EVENT)   │   │
│  │  - Event ID 10: Process Access (Sysmon)                           │   │
│  │    - Source: mimikatz.exe (PID 7823)                              │   │
│  │    - Target: lsass.exe (PID 692)                                  │   │
│  │    - Access: 0x1FFFFF (PROCESS_ALL_ACCESS)                        │   │
│  │  - Command: mimikatz.exe sekurlsa::logonpasswords                 │   │
│  │  - Harvested credentials for:                                     │   │
│  │    - alice (local workstation admin)                              │   │
│  │    - bob (fellow accounting user)                                 │   │
│  │    - it-admin (domain admin - CRITICAL)                           │   │
│  │  - MITRE: T1003.001 (LSASS Memory), T1078 (Valid Accounts)        │   │
│  │                                                                   │   │
│  │  **T+7 min (10:22 AM)** - Lateral Movement (Stage 1)              │   │
│  │  - Event ID 4624: Logon Type 10 (RemoteInteractive)               │   │
│  │    - Source: ws-alice-01                                          │   │
│  │    - Destination: ws-bob-02                                       │   │
│  │    - Account: alice (using stolen credentials)                    │   │
│  │  - Purpose: Reconnaissance of accounting network segment          │   │
│  │  - MITRE: T1021.001 (Remote Desktop Protocol)                     │   │
│  │                                                                   │   │
│  │  **T+13 min (10:28 AM)** - Lateral Movement (Stage 2)             │   │
│  │  - Event ID 4624: Logon Type 3 (Network)                          │   │
│  │    - Source: ws-alice-01                                          │   │
│  │    - Destination: dc-prod.corp.local (Domain Controller)          │   │
│  │    - Account: it-admin (stolen domain admin credentials)          │   │
│  │  - CRITICAL: Attacker now has Domain Admin access                 │   │
│  │  - MITRE: T1078.002 (Valid Accounts: Domain Accounts)             │   │
│  │                                                                   │   │
│  │  **T+15 min (10:30 AM)** - Domain Credential Theft (DCSync)       │   │
│  │  - Event ID 4662: Directory Service Access                        │   │
│  │    - Object: CN=Users,DC=corp,DC=local                            │   │
│  │    - Properties: {1131f6aa-...} (DS-Replication-Get-Changes-All)  │   │
│  │  - Attacker replicates entire Active Directory database           │   │
│  │  - ALL domain user password hashes exfiltrated                    │   │
│  │  - MITRE: T1003.006 (OS Credential Dumping: DCSync)               │   │
│  │                                                                   │   │
│  │  ---                                                               │   │
│  │                                                                   │   │
│  │  ## Threat Actor Attribution                                      │   │
│  │                                                                   │   │
│  │  **Likely Attribution**: APT29 (Cozy Bear / The Dukes)            │   │
│  │  **Confidence**: Medium-High (85% TTP similarity)                 │   │
│  │                                                                   │   │
│  │  **Supporting Evidence**:                                          │   │
│  │  1. Phishing delivery mechanism matches APT29 2023-2024 campaigns │   │
│  │  2. PowerShell staging + Mimikatz use is signature APT29 tradecraft│
│  │  3. Rapid lateral movement to DC (<15 min) indicates pre-planned  │   │
│  │     attack path (reconnaissance already completed)                │   │
│  │  4. JA3 fingerprint matches known APT29 C2 infrastructure         │   │
│  │  5. C2 IP 203.0.113.66 is in Russian address space (ASN 12345)    │   │
│  │                                                                   │   │
│  │  **Alternative Hypothesis**: Commodity ransomware gang using      │   │
│  │  leaked APT29 tools (lower confidence)                            │   │
│  │                                                                   │   │
│  │  ---                                                               │   │
│  │                                                                   │   │
│  │  ## MITRE ATT&CK Mapping (Complete Kill Chain)                    │   │
│  │                                                                   │   │
│  │  | Tactic           | Technique ID | Technique Name                │   │
│  │  |------------------|--------------|------------------------------|  │   │
│  │  | Initial Access   | T1566.001    | Phishing: Spearphishing      │   │
│  │  | Execution        | T1059.001    | PowerShell                   │   │
│  │  |                  | T1204.002    | User Execution: Malicious File│  │
│  │  | Persistence      | T1547.001    | Registry Run Keys (assumed)  │   │
│  │  | Privilege Esc    | T1078.002    | Valid Accounts: Domain       │   │
│  │  | Defense Evasion  | T1027        | Obfuscated Files (base64)    │   │
│  │  |                  | T1070.001    | Indicator Removal: Clear Logs│   │
│  │  | Credential Access| T1003.001    | LSASS Memory                 │   │
│  │  |                  | T1003.006    | DCSync                       │   │
│  │  | Discovery        | T1082        | System Information Discovery │   │
│  │  | Lateral Movement | T1021.001    | Remote Desktop Protocol      │   │
│  │  | Collection       | T1005        | Data from Local System       │   │
│  │  | Command & Control| T1071.001    | Web Protocols (HTTPS)        │   │
│  │  |                  | T1573.002    | Encrypted Channel: Asymmetric│   │
│  │  | Exfiltration     | T1041        | Exfiltration Over C2         │   │
│  │                                                                   │   │
│  │  **Coverage**: 9/14 MITRE tactics (64% of full matrix)            │   │
│  │                                                                   │   │
│  │  ---                                                               │   │
│  │                                                                   │   │
│  │  ## Indicators of Compromise (IOCs)                               │   │
│  │                                                                   │   │
│  │  ### File Hashes                                                  │   │
│  │  ```                                                               │   │
│  │  # Mimikatz payload                                               │   │
│  │  SHA256: a3f8d92e1b4c5f7a9d2e3b1c8a4f6e9d2a1b8c3d4e5f6a7b8c9d0e1f2a3b │   │
│  │  MD5: 5f4dcc3b5aa765d61d8327deb882cf99                            │   │
│  │                                                                   │   │
│  │  # Malicious Word document                                        │   │
│  │  SHA256: b4e9a12f3c6d7e8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d │   │
│  │  ```                                                               │   │
│  │                                                                   │   │
│  │  ### Network Indicators                                           │   │
│  │  ```                                                               │   │
│  │  # C2 Infrastructure                                              │   │
│  │  IP: 203.0.113.66 (Russia, ASN 12345)                             │   │
│  │  Domain: malware-c2[.]xyz                                         │   │
│  │  JA3: a3b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0                    │   │
│  │  User-Agent: Mozilla/5.0 (compatible; MSIE 9.0)                   │   │
│  │  ```                                                               │   │
│  │                                                                   │   │
│  │  ### Registry Persistence (Assumed)                               │   │
│  │  ```                                                               │   │
│  │  HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate │   │
│  │  Value: C:\Users\alice\AppData\Local\Temp\mimikatz.exe            │   │
│  │  ```                                                               │   │
│  │                                                                   │   │
│  │  ### Email IOCs                                                   │   │
│  │  ```                                                               │   │
│  │  Sender: finance@trusted-vendor[.]com (typosquat of trusted-      │   │
│  │          vendors.com)                                             │   │
│  │  Subject: Urgent: Payment Overdue - Action Required               │   │
│  │  Attachment: Invoice_Jan2025.docm                                 │   │
│  │  ```                                                               │   │
│  │                                                                   │   │
│  │  ---                                                               │   │
│  │                                                                   │   │
│  │  ## Scope of Compromise                                           │   │
│  │                                                                   │   │
│  │  **Confirmed Compromised Assets**:                                │   │
│  │  - ✅ ws-alice-01 (Patient Zero)                                  │   │
│  │  - ✅ ws-bob-02 (Lateral movement target)                         │   │
│  │  - ✅ dc-prod.corp.local (Domain Controller - CRITICAL)           │   │
│  │                                                                   │   │
│  │  **Potentially Compromised**:                                     │   │
│  │  - ⚠️ ALL 250+ domain users (credentials stolen via DCSync)       │   │
│  │  - ⚠️ 18 servers in CORP domain (domain admin access grants full  │   │
│  │       access)                                                     │   │
│  │  - ⚠️ Accounting file share (alice had access, attacker may have  │   │
│  │       exfiltrated financial records)                              │   │
│  │                                                                   │   │
│  │  **Data at Risk**:                                                │   │
│  │  - Active Directory database (all user accounts, passwords)       │   │
│  │  - Accounting files (financial statements, invoices, PII)         │   │
│  │  - Email archive (potential access via domain admin creds)        │   │
│  │                                                                   │   │
│  │  **Estimated Impact**:                                             │   │
│  │  - Financial: $500k - $2M (incident response, downtime, ransomware│   │
│  │    potential)                                                     │   │
│  │  - Regulatory: GDPR/SOX violations (if PII/financial data stolen) │   │
│  │  - Reputational: Customer trust loss if breach disclosed          │   │
│  │                                                                   │   │
│  │  ---                                                               │   │
│  │                                                                   │   │
│  │  ## Recommended Remediation Steps                                 │   │
│  │                                                                   │   │
│  │  ### Phase 1: Immediate Containment (Next 1 Hour)                 │   │
│  │                                                                   │   │
│  │  **Priority 1 - CRITICAL**:                                       │   │
│  │  1. ✅ Isolate ws-alice-01 from network immediately               │   │
│  │     - Disable network adapter (not just unplug cable - attacker   │   │
│  │       may have scheduled tasks to re-enable)                      │   │
│  │     - Preserve memory dump for forensics: `procdump -ma lsass.exe`│   │
│  │                                                                   │   │
│  │  2. ✅ Reset krbtgt account password TWICE (Kerberos Golden Ticket│   │
│  │        mitigation)                                                │   │
│  │     ```powershell                                                 │   │
│  │     # On domain controller                                        │   │
│  │     $krbtgt = Get-ADUser krbtgt                                   │   │
│  │     Set-ADAccountPassword -Identity $krbtgt -Reset                │   │
│  │     # Wait 10 hours for replication, then repeat                  │   │
│  │     ```                                                            │   │
│  │                                                                   │   │
│  │  3. ✅ Reset ALL domain admin passwords                           │   │
│  │     - Force password change for: it-admin, domain admins group    │   │
│  │     - Disable compromised accounts until investigation complete   │   │
│  │                                                                   │   │
│  │  4. ✅ Block C2 IP at perimeter firewall                          │   │
│  │     - Add rule: DENY ALL to 203.0.113.66/32                       │   │
│  │     - Sinkhole malware-c2[.]xyz at DNS level                      │   │
│  │                                                                   │   │
│  │  **Priority 2 - HIGH**:                                            │   │
│  │  5. Isolate ws-bob-02 (secondary pivot point)                     │   │
│  │  6. Enable enhanced logging on dc-prod                            │   │
│  │     - Audit: Directory Service Access, Account Logon Events       │   │
│  │  7. Snapshot ALL VMs for forensic preservation                    │   │
│  │                                                                   │   │
│  │  ### Phase 2: Eradication (Next 24 Hours)                         │   │
│  │                                                                   │   │
│  │  8. ✅ Re-image ws-alice-01 and ws-bob-02 from known-good gold    │   │
│  │        image                                                      │   │
│  │     - DO NOT restore from backup (may contain malware)            │   │
│  │     - Rebuild from scratch using trusted media                    │   │
│  │                                                                   │   │
│  │  9. ✅ Force password reset for ALL domain users (250+ accounts)  │   │
│  │     - Send communication explaining security incident (coordinate │   │
│  │       with Legal/PR)                                              │   │
│  │     - Require MFA enrollment for all users                        │   │
│  │                                                                   │   │
│  │  10. Hunt for persistence mechanisms across domain:                │   │
│  │      ```powershell                                                │   │
│  │      # Search all domain computers for mimikatz artifacts         │   │
│  │      Get-ADComputer -Filter * | ForEach {                         │   │
│  │        Invoke-Command -Computer $_.Name -ScriptBlock {            │   │
│  │          Get-ChildItem C:\Users\*\AppData\Local\Temp\*.exe       │   │
│  │        }                                                           │   │
│  │      }                                                             │   │
│  │      ```                                                           │   │
│  │                                                                   │   │
│  │  11. Review ALL domain admin logons in past 30 days:              │   │
│  │      - Event ID 4624 (Successful Logon) where account in "Domain  │   │
│  │        Admins"                                                    │   │
│  │      - Look for anomalous source IPs, off-hours access            │   │
│  │                                                                   │   │
│  │  ### Phase 3: Recovery (Next 48-72 Hours)                         │   │
│  │                                                                   │   │
│  │  12. Restore user access gradually with monitoring:                │   │
│  │      - Start with critical business users (CEO, CFO, etc.)        │   │
│  │      - Monitor for re-compromise attempts                         │   │
│  │                                                                   │   │
│  │  13. Deploy EDR agent to ALL endpoints if not already present:    │   │
│  │      - CrowdStrike, SentinelOne, or Microsoft Defender for Endpoint│  │
│  │      - Configure to block Mimikatz signatures                     │   │
│  │                                                                   │   │
│  │  14. Implement PowerShell logging and script block monitoring:    │   │
│  │      ```powershell                                                │   │
│  │      # GPO: Enable PowerShell Script Block Logging                │   │
│  │      Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\   │   │
│  │        Windows\PowerShell\ScriptBlockLogging" -Name               │   │
│  │        "EnableScriptBlockLogging" -Value 1                        │   │
│  │      ```                                                           │   │
│  │                                                                   │   │
│  │  ### Phase 4: Prevention (Next 30 Days)                           │   │
│  │                                                                   │   │
│  │  15. Deploy anti-phishing training:                               │   │
│  │      - KnowBe4, Cofense, or similar simulation platform           │   │
│  │      - Focus on accounting team (high-value targets)              │   │
│  │                                                                   │   │
│  │  16. Implement Privileged Access Workstations (PAWs):             │   │
│  │      - Domain admins ONLY use dedicated hardened workstations     │   │
│  │      - No email, web browsing on PAWs                             │   │
│  │                                                                   │   │
│  │  17. Deploy LSASS protection:                                     │   │
│  │      ```powershell                                                │   │
│  │      # Enable Credential Guard (Windows 10/11 Enterprise)         │   │
│  │      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\      │   │
│  │        Control\Lsa" -Name "RunAsPPL" -Value 1                     │   │
│  │      ```                                                           │   │
│  │                                                                   │   │
│  │  18. Network segmentation:                                         │   │
│  │      - Isolate accounting VLAN from general corporate network     │   │
│  │      - Firewall rules: Block workstation-to-workstation traffic   │   │
│  │        on admin ports (RDP, SMB, WinRM)                           │   │
│  │                                                                   │   │
│  │  ---                                                               │   │
│  │                                                                   │   │
│  │  ## Collection Playbook (Missing Logs)                            │   │
│  │                                                                   │   │
│  │  To improve future detection and investigation capabilities,      │   │
│  │  implement the following log sources:                             │   │
│  │                                                                   │   │
│  │  ### High Priority (Deploy Within 1 Week)                         │   │
│  │                                                                   │   │
│  │  1. **Email Gateway Logs** (Proofpoint, Mimecast, Office 365      │   │
│  │     Advanced Threat Protection)                                   │   │
│  │     - Would have shown: Attachment analysis, sender reputation,   │   │
│  │       URL detonation results                                      │   │
│  │     - SIEM Query to add:                                          │   │
│  │       ```                                                          │   │
│  │       index=email source=proofpoint action=quarantine             │   │
│  │       OR attachment_type=macro-enabled                            │   │
│  │       ```                                                          │   │
│  │                                                                   │   │
│  │  2. **Full Packet Capture (PCAP)** at network egress              │   │
│  │     - Tools: Zeek, Suricata, Moloch                               │   │
│  │     - Would have shown: Encrypted C2 payload (even if can't       │   │
│  │       decrypt, can fingerprint)                                   │   │
│  │     - Storage: 7-day rolling window (500 GB/day for 1000-user org)│   │
│  │                                                                   │   │
│  │  3. **PowerShell Operational Logs** (Event ID 4103, 4104)         │   │
│  │     - Captures full command text including decoded base64         │   │
│  │     - GPO setting: Enable Module Logging + Script Block Logging   │   │
│  │     - SIEM Query:                                                  │   │
│  │       ```                                                          │   │
│  │       index=windows EventID=4104                                  │   │
│  │       ScriptBlockText="*mimikatz*" OR "*sekurlsa*" OR             │   │
│  │         "*lsadump*"                                               │   │
│  │       ```                                                          │   │
│  │                                                                   │   │
│  │  ### Medium Priority (Deploy Within 30 Days)                      │   │
│  │                                                                   │   │
│  │  4. **DNS Query Logs**                                            │   │
│  │     - Tools: Windows DNS Server logging, Pi-hole, Infoblox        │   │
│  │     - Would have shown: malware-c2[.]xyz resolution before C2     │   │
│  │       connection                                                  │   │
│  │     - SIEM Query:                                                  │   │
│  │       ```                                                          │   │
│  │       index=dns query_type=A                                      │   │
│  │       domain_age_days<7  # Newly registered domains               │   │
│  │       ```                                                          │   │
│  │                                                                   │   │
│  │  5. **File Integrity Monitoring (FIM)**                            │   │
│  │     - Tools: Tripwire, OSSEC, Windows Audit                       │   │
│  │     - Monitor: C:\Users\*\AppData\Local\Temp for new .exe files   │   │
│  │     - Alert on: Unsigned executables in user temp directories     │   │
│  │                                                                   │   │
│  │  ### Low Priority (Nice to Have)                                  │   │
│  │                                                                   │   │
│  │  6. **User Behavior Analytics (UBA)**                             │   │
│  │     - Tools: Exabeam, Splunk UBA, Microsoft Sentinel              │   │
│  │     - Would have shown: Alice's abnormal RDP usage pattern        │   │
│  │       (accounting users rarely RDP)                               │   │
│  │                                                                   │   │
│  │  7. **Deception Technology (Honeypots)**                           │   │
│  │     - Deploy fake "Finance-Archive" share with honeytoken files   │   │
│  │     - Any access → Instant high-fidelity alert                    │   │
│  │                                                                   │   │
│  │  ---                                                               │   │
│  │                                                                   │   │
│  │  ## Lessons Learned & Recommendations                             │   │
│  │                                                                   │   │
│  │  ### What Worked                                                  │   │
│  │  ✅ Sysmon telemetry captured detailed process lineage            │   │
│  │  ✅ JanuSec HopGraph correlation connected attack chain dots      │   │
│  │  ✅ HopGraph correlation identified lateral movement within minutes│  │
│  │  ✅ Windows Event Logs preserved enough forensic evidence         │   │
│  │                                                                   │   │
│  │  ### What Didn't Work                                             │   │
│  │  ❌ Email gateway failed to block macro-enabled attachment        │   │
│  │  ❌ No real-time alerting on LSASS access (detection delay: 2 hrs)│   │
│  │  ❌ Lack of MFA allowed lateral movement with stolen creds        │   │
│  │  ❌ Domain admin credentials stored in LSASS (should use smartcard)│  │
│  │                                                                   │   │
│  │  ### Strategic Recommendations                                    │   │
│  │                                                                   │   │
│  │  1. **Assume Breach Mindset**: Design controls assuming attacker  │   │
│  │     already has foothold (Zero Trust architecture)                │   │
│  │                                                                   │   │
│  │  2. **Prioritize Detection Over Prevention**: You will be phished.│   │
│  │     Focus on fast detection and response vs. trying to block      │   │
│  │     everything.                                                   │   │
│  │                                                                   │   │
│  │  3. **Invest in Automation**: Time-to-detect of 15 minutes is too │   │
│  │     slow. Target: <60 seconds with automated containment.         │   │
│  │                                                                   │   │
│  │  4. **Red Team Exercises**: Validate defenses with realistic      │   │
│  │     attack simulations quarterly.                                 │   │
│  │                                                                   │   │
│  │  ---                                                               │   │
│  │                                                                   │   │
│  │  **Report Generated**: 2025-01-20 15:45 UTC                       │   │
│  │  **Model**: GPT-4-turbo (128k context)                            │   │
│  │  **Tokens**: 1,247 output / 2,850 total                           │   │
│  │  **Cost**: $0.086                                                 │   │
│  │  **Confidence**: This analysis should be reviewed and validated by│   │
│  │                  a human threat hunter before acting on remediation│  │
│  │                  steps involving production systems.              │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Display in UI:                                                          │
│  - Markdown rendered with syntax highlighting                           │
│  - Collapsible sections (expand/collapse)                               │
│  - Copy buttons for IOCs, queries, PowerShell commands                  │
│  - Export to PDF button                                                 │
│                                                                          │
│  💡 Business Value:                                                      │
│  - Complete investigation report in 8 seconds (vs 4-8 hours manual)     │
│  - Actionable remediation steps (not just "investigate further")        │
│  - Forensic-quality documentation for compliance/legal review           │
│  - Training value: Junior analysts learn from AI reasoning              │
└─────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
                          *** (See Part 3 for Report Generation) ***
