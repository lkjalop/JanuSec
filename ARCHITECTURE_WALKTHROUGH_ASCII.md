# JanuSec Platform: Complete Architecture Walkthrough
*ASCII Diagrams + Step-by-Step Explanation*

---

## Overview Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          DATA INGESTION LAYER                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │   EDR    │  │  SIEM    │  │ Network  │  │  Cloud   │  │  CSV     │     │
│  │ CrowdSt. │  │ Splunk   │  │  Zeek    │  │ AWS/Azure│  │ Upload   │     │
│  │ Sentinel │  │ QRadar   │  │  Suricata│  │  GuardD. │  │ CyberStash│    │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘     │
│       │             │              │             │             │            │
│       └─────────────┴──────────────┴─────────────┴─────────────┘            │
│                                     │                                        │
└─────────────────────────────────────┼────────────────────────────────────────┘
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         EVENT NORMALIZATION                                  │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  Unified Event Schema Mapper (src/api/routes/events.py)              │  │
│  │  • 50+ source formats → Canonical schema                             │  │
│  │  • Field mapping: process_name, src_ip, user, timestamp, etc.        │  │
│  │  • Multi-tenancy isolation (tenant_id extraction)                    │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       25-STAGE ANALYSIS PIPELINE                             │
│                  (src/core/event_pipeline/pipeline.py)                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ STAGE 1-8: PRIMITIVE CHECKS (primitives.py)                         │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │  1. Allowlist Check        → Hard suppress known-good (-0.15)       │    │
│  │  2. Temporal Dedup         → Skip redundant events                  │    │
│  │  3. Baseline Drift         → Compare learned behavior               │    │
│  │  4. Geo Enrichment         → Add country/ASN/city                   │    │
│  │  5. Threat Intel IOC       → Match IPs/domains vs feeds             │    │
│  │  6. User Role Context      → Tag privileged accounts                │    │
│  │  7. Time Window Context    → Flag off-hours (0-5am, 10pm+)          │    │
│  │  8. Asset Criticality      → Weight by tier (DC=critical)           │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                     │                                        │
│                                     ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ STAGE 9-14: NETWORK ANALYSIS (network.py)                           │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │  9. SSL Fingerprinting     → JA3/JA3S/JA4/JARM rarity (+0.06)      │    │
│  │ 10. DNS Tunnel Detection   → Entropy + QPS heuristic (+0.08)       │    │
│  │ 11. Beaconing Detection    → C2 periodic callback (CV<0.2) (+0.07) │    │
│  │ 12. HTTP Anomaly           → Rare User-Agent, header inject (+0.04)│    │
│  │ 13. Port Scan Detection    → 20+ ports = vertical scan (+0.08)     │    │
│  │ 14. Lateral Movement       → SMB/RDP/WinRM internal pivot (+0.04)  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                     │                                        │
│                                     ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ STAGE 15-25: ADVANCED BEHAVIORAL (advanced.py)                      │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │ 15. Process Lineage        → Parent-child anomalies (+0.08)        │    │
│  │ 16. LOLBin Detection       → certutil/mshta abuse (+0.20)           │    │
│  │ 17. Persistence Mech       → Registry/WMI/task (+0.12-0.14)        │    │
│  │ 18. Privilege Escalation   → Token manip, UAC bypass (+0.12)       │    │
│  │ 19. Credential Access      → LSASS dump, DCSync (+0.18)            │    │
│  │ 20. Data Staging           → Compress + exfil prep (+0.10)         │    │
│  │ 21. Domain Trust Abuse     → Cross-domain exploit (+0.10)          │    │
│  │ 22. Script Obfuscation     → PowerShell -enc, base64 (+0.14)       │    │
│  │ 23. Macro Analysis         → Office autoexec macro (+0.16)         │    │
│  │ 24. Remote Tool Exec       → PsExec, WMI, WinRM (+0.12)            │    │
│  │ 25. Anti-Forensics         → Log clear, timestomp (+0.10)          │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                     │                                        │
│                    ┌────────────────┴────────────────┐                       │
│                    ▼                                 ▼                       │
│          ┌──────────────────┐             ┌──────────────────┐              │
│          │  SBOM Execution  │             │  SBOM Vuln Map   │              │
│          │  (sbom.py)       │             │  (CVE + CVSS)    │              │
│          │  • Match process │             │  • KEV/EPSS      │              │
│          │    to inventory  │             │  • Exploit avail │              │
│          └──────────────────┘             └──────────────────┘              │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        FACTOR AGGREGATION                                    │
│                   (146 possible factors extracted)                           │
├─────────────────────────────────────────────────────────────────────────────┤
│  Example: ["lolbin_misuse", "ssl:ja3_rare", "net:beacon_periodic",          │
│            "fresh_download", "unsigned_binary", "off_hours_activity"]        │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      HOPGRAPH CORRELATION ENGINE                             │
│                  (src/core/graph/hopgraph_lite.py)                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Temporal Entity Graph (in-memory sliding window)                   │    │
│  │                                                                      │    │
│  │       [User:alice] ──auth──> [Host:ws-01] ──net──> [Host:dc-01]    │    │
│  │            │                        │                                │    │
│  │            └──spawn──> [Process:powershell.exe]                     │    │
│  │                                     │                                │    │
│  │                              └──connect──> [IP:evil.com:443]        │    │
│  │                                                                      │    │
│  │  Edge TTLs: Auth=72h, Net=24h, Proc=12h                             │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
│  Motif Detection:                                                            │
│    ✓ User touches >3 hosts in 15min → lateral_velocity_hph                  │
│    ✓ Auth burst + remote tool + DC access → graph_motif_auth_burst_dc       │
│    ✓ Personalized PageRank → ppr_topk_contains_dc                           │
│                                                                               │
│  Output: ["lateral_movement_candidate", "graph_motif_auth_burst_dc"]        │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      CORRELATION RULES ENGINE                                │
│               (src/core/correlation/hunt_correlation.py)                     │
├─────────────────────────────────────────────────────────────────────────────┤
│  Combines base factors into higher-order patterns:                           │
│                                                                               │
│  Rule 1: office_macro_spawn_ps + ssl:ja3_rare                               │
│          → CORR_OFFICE_PS_RARE_JA3 (+0.15)                                  │
│                                                                               │
│  Rule 2: powershell_encoded + signed_to_unsigned                            │
│          → CORR_ENCODED_PS_SIGNED_UNSIGNED (+0.18)                          │
│                                                                               │
│  Rule 3: net:beacon_periodic + jarm_rare + dns:long_label                   │
│          → CORR_PERSISTENT_BEACON_CLUSTER (+0.20)                           │
│                                                                               │
│  Rule 4: lateral_smb + lateral_rdp + lateral_winrm (within 5min)            │
│          → CORR_STEALTH_LATERAL_STAGING (+0.22)                             │
│                                                                               │
│  Total: 15 active rules, 30 planned                                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         RISK SYNTHESIS ENGINE                                │
│                     (src/artifact/risk.py)                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  Base Risk = Σ(factor_weight)  [40 weighted factors]                        │
│    Example: lolbin_misuse(0.20) + fresh_download(0.12) + ja3_rare(0.06)     │
│           = 0.38 base                                                        │
│                                                                               │
│  Temporal Boost = rarity × 0.1 + cluster_malicious_density × 0.05           │
│    Example: RARE artifact + 3/10 cluster malicious = 0.10 + 0.015 = 0.115   │
│                                                                               │
│  Vulnerability Context (if SBOM matched):                                    │
│    CVSS ≥ 7.0 AND exploit_available → +0.15                                 │
│                                                                               │
│  Correlation Bonus = Σ(correlation_factor_weights)                          │
│    Example: CORR_OFFICE_PS_RARE_JA3 = +0.15                                 │
│                                                                               │
│  Preliminary Risk = base + temporal + vuln + corr                           │
│                   = 0.38 + 0.115 + 0.15 + 0.15 = 0.795                      │
│                                                                               │
│  Confidence Score = f(factor_count, weight_consensus, rarity)               │
│    factor_count/6 × 0.5 + (1-std_dev) × 0.4 + rarity_bonus × 0.1           │
│    Example: 6 factors, low std → 0.82 confidence                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      DECISION ROUTER                                         │
│                 (src/core/decision_engine.py)                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  IF confidence ≤ 0.10 AND risk < 0.20:                                      │
│      ──> BENIGN PATH (auto-suppress, no alert)                              │
│                                                                               │
│  IF confidence 0.10-0.90 AND risk 0.20-0.85:                                │
│      ──> DEEP ANALYSIS (AI escalation)                                      │
│                                                                               │
│  IF confidence ≥ 0.90 OR risk ≥ 0.85:                                       │
│      ──> MALICIOUS PATH (alert/block)                                       │
└─────────────────────────────────────────────────────────────────────────────┘
           │                             │                             │
           ▼                             ▼                             ▼
    ┌──────────┐              ┌──────────────────┐            ┌──────────────┐
    │  BENIGN  │              │  DEEP ANALYSIS   │            │  MALICIOUS   │
    │  (suppress)│             │  (AI Tier Route) │            │  (alert)     │
    └──────────┘              └──────────────────┘            └──────────────┘
                                       │
                                       ▼
         ┌─────────────────────────────────────────────────────────────────┐
         │              AI ESCALATION LADDER                                │
         │           (src/ai/model_manager.py)                              │
         ├─────────────────────────────────────────────────────────────────┤
         │                                                                  │
         │  Tier 1: Lightweight ML (IsolationForest + KMeans)              │
         │    • Latency: <5ms                                              │
         │    • Cost: $0                                                   │
         │    • Use: Quick anomaly score                                   │
         │                                                                  │
         │  Tier 2: Open-Source LLM (Ollama Llama3/Mistral)                │
         │    • Latency: 200-500ms                                         │
         │    • Cost: $0 (local GPU)                                       │
         │    • Use: Narrative generation for moderate-risk                │
         │                                                                  │
         │  Tier 3: External AI (OpenAI GPT-4, Claude, Gemini)             │
         │    • Latency: 1-3s                                              │
         │    • Cost: $0.01-0.05/event                                     │
         │    • Use: Deep semantic analysis, conflicting factors           │
         │    • FinOps Gate: Block if hourly budget exceeded               │
         │                                                                  │
         │  Fallback Chain:                                                 │
         │    GPT-4 fail → OSS Llama → IsolationForest → Rule-based        │
         └─────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
         ┌─────────────────────────────────────────────────────────────────┐
         │              LLM REFINEMENT                                      │
         │           (src/artifact/llm_refine.py)                           │
         ├─────────────────────────────────────────────────────────────────┤
         │  For events in "ambiguity band" (risk 0.40-0.70):                │
         │                                                                  │
         │  Prompt: "Analyze this artifact with factors X, Y, Z.            │
         │           Is this likely malicious? Adjust risk by -0.2 to +0.3."│
         │                                                                  │
         │  LLM Output:                                                     │
         │    {                                                             │
         │      "risk_delta": +0.15,                                        │
         │      "narrative": "PowerShell with rare JA3 after Office macro   │
         │                    suggests phishing payload delivery",          │
         │      "mitre_add": ["T1566.001", "T1059.001"]                     │
         │    }                                                             │
         │                                                                  │
         │  Adjusted Risk = 0.55 + 0.15 = 0.70 (now MALICIOUS threshold)    │
         └─────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      FINAL VERDICT + ACTIONS                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  Verdict: MALICIOUS (confidence: 0.88, risk: 0.70)                          │
│  Factors: [lolbin_misuse, ssl:ja3_rare, fresh_download,                     │
│            CORR_OFFICE_PS_RARE_JA3, off_hours_activity]                     │
│  MITRE: [T1566.001 (Phishing), T1059.001 (PowerShell),                      │
│          T1071.001 (Web Protocols)]                                          │
│  Narrative: "Phishing macro spawned PowerShell with rare SSL fingerprint"   │
│                                                                               │
│  Actions Triggered:                                                          │
│    1. Alert SOC (severity: HIGH)                                            │
│    2. Block C2 domain at firewall (if policy enabled)                       │
│    3. Isolate endpoint (if EDR integration active)                          │
│    4. Create SIEM case (Splunk/Sentinel)                                    │
│    5. Log to audit trail (compliance)                                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      STORAGE & RETRIEVAL                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐          │
│  │   PostgreSQL     │  │   Redis Cache    │  │   SQLite Graph   │          │
│  │  (decisions,     │  │  (temporal corr, │  │  (HopGraph opt.) │          │
│  │   alerts, audit) │  │   dedup, session)│  │                  │          │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘          │
│                                                                               │
│  Retention Policies:                                                         │
│    • Alerts: 90 days (hot), 1 year (cold)                                   │
│    • Decisions: 30 days (queryable)                                         │
│    • HopGraph: 72h (in-memory), 7d (SQLite)                                 │
│    • Audit logs: 7 years (compliance)                                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         USER INTERFACES                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────┐       │
│  │  React Dashboard  │  │   CSV Analyzer    │  │   REST API        │       │
│  │  • Alerts feed    │  │  • Batch upload   │  │  • /api/events    │       │
│  │  • Risk charts    │  │  • Triage results │  │  • /api/alerts    │       │
│  │  • Attack graphs  │  │  • Export filtered│  │  • /api/analyze   │       │
│  │  • Hunt queries   │  └───────────────────┘  │  • /api/hunt      │       │
│  └───────────────────┘                          └───────────────────┘       │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Detailed Step-by-Step Walkthrough

### Example Event: Phishing Attack Lifecycle

Let's trace a real attack through the entire system.

#### Step 1: Event Ingestion (T+0s)

**Source**: Microsoft Defender EDR sends webhook:

```json
{
  "event_type": "ProcessCreation",
  "timestamp": "2025-11-07T14:32:10Z",
  "tenant_id": "acme-corp",
  "host": "ws-bryan-01",
  "user": "bryan.smith",
  "process_name": "powershell.exe",
  "parent_process": "WINWORD.EXE",
  "command_line": "powershell.exe -enc JABhAD0AKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AH...",
  "hash": "d41d8cd98f00b204e9800998ecf8427e",
  "signed": false,
  "zone_id": "3"
}
```

**Normalization** (src/api/routes/events.py:45):
- Extract `tenant_id` → Route to acme-corp partition
- Map `ProcessCreation` → `process_spawn` event type
- Flatten nested fields → Canonical schema

**Output**:
```json
{
  "event_id": "evt_abc123",
  "tenant_id": "acme-corp",
  "event_type": "process_spawn",
  "timestamp": 1699368730,
  "host": "ws-bryan-01",
  "user": "bryan.smith",
  "process": "powershell.exe",
  "parent": "WINWORD.EXE",
  "cmdline": "powershell.exe -enc ...",
  "hash": "d41d8cd98f00b204e9800998ecf8427e",
  "signed": false,
  "zone_id": 3
}
```

#### Step 2: Pipeline Stage 1-8 (Primitives) - T+5ms

**Stage 1: Allowlist Check**
- Hash lookup: `d41d8cd...` NOT in allowlist
- Process: `powershell.exe` + parent `WINWORD.EXE` → Suspicious (Office spawning PS)
- **Output**: Continue processing

**Stage 7: Time Window Context**
- Event time: 14:32 (2:32 PM)
- Office hours: 9am-6pm
- **Output**: ✅ Within business hours (no off-hours factor)

**Stage 8: Asset Criticality**
- Host `ws-bryan-01` → Workstation tier
- User `bryan.smith` → Standard user (not admin)
- **Output**: Normal criticality (no boost)

#### Step 3: Pipeline Stage 15-25 (Advanced) - T+20ms

**Stage 15: Process Lineage**
```python
# src/core/event_pipeline/stages/advanced.py:145
parent = "WINWORD.EXE"
child = "powershell.exe"
if parent in OFFICE_APPS and child in SCRIPTING_ENGINES:
    factors.append("office_macro_spawn_powershell")  # +0.18 weight
```

**Stage 16: LOLBin Detection**
```python
# src/modules/network_hunter.py:75
cmdline = "powershell.exe -enc ..."
if "powershell" in cmdline.lower() and "-enc" in cmdline:
    factors.append("lolbin_misuse")  # +0.20
    factors.append("powershell_encoded_command")  # +0.14
```

**Stage 17: Persistence Check**
- No registry writes detected
- **Output**: No persistence factors

**Stage 22: Script Obfuscation**
```python
# src/artifact/factors.py:68
if BASE64_RE.search(cmdline):
    factors.append("script_encoded_block")  # +0.14
```

**Cumulative Factors After Stage 25**:
```
["office_macro_spawn_powershell", "lolbin_misuse",
 "powershell_encoded_command", "script_encoded_block",
 "unsigned_binary"]
```

**Base Risk** = 0.18 + 0.20 + 0.14 + 0.14 + 0.18 = **0.84**

#### Step 4: Network Event Correlation - T+22ms

2 seconds later, EDR sends another event:

```json
{
  "event_type": "NetworkConnection",
  "timestamp": "2025-11-07T14:32:12Z",
  "src_ip": "10.0.50.42",
  "dst_ip": "203.0.113.66",
  "dst_port": 443,
  "process": "powershell.exe",
  "ja3": "769,49195-49196-49199-49200-52393...",
  "sni": "malware-c2.xyz"
}
```

**Stage 9: SSL Fingerprinting**
```python
# src/modules/network_hunter.py:273
ja3 = "769,49195-..."
self.ja3_freq[ja3] += 1  # First time seen
if self.ja3_freq[ja3] < 5:
    factors.append("ssl:ja3_rare")  # +0.06
```

**Stage 10: DNS Tunnel Check**
- Domain `malware-c2.xyz` not in cache
- **Output**: Factor `new_domain_seen` (+0.02)

#### Step 5: HopGraph Ingestion - T+25ms

```python
# src/core/graph/hopgraph_lite.py:132
graph.observe({
    'user': 'bryan.smith',
    'host': 'ws-bryan-01',
    'proc': 'powershell.exe',
    'peer': '203.0.113.66',
    'edge_type': 'proc'
})
```

**Graph State**:
```
[User:bryan.smith] ──spawn──> [Process:powershell.exe]
        │
        └──auth──> [Host:ws-bryan-01]
                       │
                       └──net──> [IP:203.0.113.66:443]
```

**Motif Detection**:
- User spawned suspicious proc + network connection within 5s
- **Output**: `graph_user_proc_burst` (+0.05)

#### Step 6: Correlation Engine - T+30ms

```python
# src/core/correlation/hunt_correlation.py:195
if "office_macro_spawn_powershell" in factors and "ssl:ja3_rare" in factors:
    new_factors.append("CORR_OFFICE_PS_RARE_JA3")  # +0.15
```

**Updated Factors**:
```
["office_macro_spawn_powershell", "lolbin_misuse", "ssl:ja3_rare",
 "CORR_OFFICE_PS_RARE_JA3", "new_domain_seen", "graph_user_proc_burst"]
```

#### Step 7: Risk Synthesis - T+35ms

```python
# src/artifact/risk.py:synthesize
base_risk = 0.84
temporal_boost = 0.02 (new domain) + 0.05 (graph burst) = 0.07
correlation_bonus = 0.15 (CORR_OFFICE_PS_RARE_JA3)

preliminary_risk = 0.84 + 0.07 + 0.15 = 1.06  # Clamped to 1.0
final_risk = 1.0
```

**Confidence Calculation**:
```python
factor_count = 6
base_conf = min(1.0, 6 / 6.0) = 1.0
consensus = 0.92  # Low weight std dev
rarity_bonus = 0.10  # Rare JA3

confidence = 1.0 × 0.5 + 0.92 × 0.4 + 0.10 = 0.98
```

#### Step 8: Decision Routing - T+40ms

```python
# src/core/decision_engine.py:52
if confidence >= 0.90:
    return RoutingDecision(
        path='malicious',
        confidence=0.98,
        factors=all_factors,
        verdict='malicious'
    )
```

**Routing**: confidence=0.98, risk=1.0 → **MALICIOUS PATH**

**Actions Triggered**:
1. Create alert in DB
2. Send webhook to SOC dashboard
3. (Optional) Block C2 domain via firewall integration
4. (Optional) Isolate endpoint if policy=aggressive

#### Step 9: MITRE ATT&CK Mapping - T+42ms

```python
# src/artifact/technique_mapping.py:apply_mapping
factors = ["office_macro_spawn_powershell", "powershell_encoded_command",
           "ssl:ja3_rare"]

mitre = []
if "office_macro_spawn_powershell" in factors:
    mitre.append("T1566.001")  # Phishing: Spearphishing Attachment
if "powershell_encoded_command" in factors:
    mitre.append("T1059.001")  # Command/Scripting: PowerShell
    mitre.append("T1027")      # Obfuscated Files or Information
if "ssl:ja3_rare" in factors:
    mitre.append("T1071.001")  # Application Layer Protocol: Web Protocols
```

#### Step 10: Attack Reconstruction - T+50ms

```python
# src/core/graph/hopgraph_lite.py:526
graph.reconstruct_attack(seed_alert={
    'user': 'bryan.smith',
    'host': 'ws-bryan-01',
    'process': 'powershell.exe'
}, depth=3)
```

**Reconstructed Attack Graph**:
```json
{
  "seeds": [{"type": "user", "id": "bryan.smith"}],
  "nodes": [
    {"type": "user", "id": "bryan.smith"},
    {"type": "host", "id": "ws-bryan-01"},
    {"type": "proc", "id": "powershell.exe"},
    {"type": "host", "id": "203.0.113.66"}
  ],
  "edges": [
    {"src_type": "user", "src_id": "bryan.smith",
     "dst_type": "host", "dst_id": "ws-bryan-01",
     "phase": "initial_access", "ts": 1699368730},
    {"src_type": "user", "src_id": "bryan.smith",
     "dst_type": "proc", "dst_id": "powershell.exe",
     "phase": "execution", "ts": 1699368730},
    {"src_type": "host", "src_id": "ws-bryan-01",
     "dst_type": "host", "dst_id": "203.0.113.66",
     "phase": "c2", "ts": 1699368732}
  ],
  "timeline": {"start_ts": 1699368730, "end_ts": 1699368732}
}
```

**Narrative Generation** (if ambiguous, uses AI Tier 2):
```
"User bryan.smith opened a malicious Office document on ws-bryan-01, which
executed an obfuscated PowerShell payload. The script established a connection
to a rare C2 server (203.0.113.66) using an uncommon SSL fingerprint,
indicating likely phishing campaign with commodity malware."
```

#### Step 11: Storage & Alerting - T+55ms

**Database Writes**:
1. `decisions` table:
   ```sql
   INSERT INTO decisions (event_id, tenant_id, verdict, confidence, risk,
                          factors, mitre_techniques, narrative)
   VALUES ('evt_abc123', 'acme-corp', 'malicious', 0.98, 1.0,
           '["office_macro_spawn_powershell", ...]',
           '["T1566.001", "T1059.001"]',
           'User opened malicious Office document...');
   ```

2. `alerts` table (if verdict=malicious):
   ```sql
   INSERT INTO alerts (decision_id, severity, status, assigned_to)
   VALUES ('dec_xyz789', 'HIGH', 'open', NULL);
   ```

**Webhook to SOC Dashboard**:
```json
POST https://soc.acme-corp.com/api/webhooks/janusec
{
  "alert_id": "alt_456def",
  "severity": "HIGH",
  "user": "bryan.smith",
  "host": "ws-bryan-01",
  "summary": "Phishing payload execution detected",
  "mitre": ["T1566.001", "T1059.001"],
  "confidence": 0.98,
  "timestamp": "2025-11-07T14:32:12Z"
}
```

#### Step 12: SOC Analyst Review - T+60s

**React Dashboard** (`frontend/react/src/main.jsx`):
- Alert appears in real-time feed
- Analyst clicks → Sees full context:
  - Timeline of events (macro open → PS spawn → C2 connect)
  - Attack graph visualization
  - Factor breakdown (why flagged)
  - MITRE techniques mapped
  - Recommended actions (isolate endpoint, block domain)

**Analyst Actions**:
1. Review narrative: "Looks like real attack, not FP"
2. Click "Approve & Escalate"
3. Trigger automated playbook:
   - Isolate endpoint via EDR API
   - Block `malware-c2.xyz` at firewall
   - Reset user credentials
   - Image endpoint for forensics

**Total Time**: 55ms (detection) + 60s (human review) = **~1 minute TTD (Time to Detect)**

---

## Architecture Highlights

### Multi-Tenancy Isolation

```
┌─────────────────────────────────────────────────────────────┐
│  Tenant: acme-corp                   Tenant: contoso-ltd    │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐                ┌──────────────────┐   │
│  │  Event Queue     │                │  Event Queue     │   │
│  │  (Redis Stream)  │                │  (Redis Stream)  │   │
│  │  acme_events     │                │  contoso_events  │   │
│  └──────────────────┘                └──────────────────┘   │
│          ↓                                    ↓              │
│  ┌──────────────────┐                ┌──────────────────┐   │
│  │  Pipeline Worker │                │  Pipeline Worker │   │
│  │  (isolated ctx)  │                │  (isolated ctx)  │   │
│  └──────────────────┘                └──────────────────┘   │
│          ↓                                    ↓              │
│  ┌──────────────────┐                ┌──────────────────┐   │
│  │  DB Partition    │                │  DB Partition    │   │
│  │  tenant='acme'   │                │  tenant='contoso'│   │
│  └──────────────────┘                └──────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Isolation Guarantees**:
- Row-level security on PostgreSQL (`WHERE tenant_id = ?`)
- Separate Redis key prefixes (`{tenant_id}:cache:*`)
- FinOps budgets enforced per-tenant

### FinOps Budget Controls

```
┌─────────────────────────────────────────────────────────────┐
│  External AI Request                                         │
├─────────────────────────────────────────────────────────────┤
│  Event → Decision Router → "Needs deep analysis"             │
│                ↓                                             │
│  Check FinOps Budget (src/core/finops/finops_manager.py)    │
│    • Current hour spend: $12.50                             │
│    • Hourly limit: $15.00                                   │
│    • Remaining budget: $2.50                                │
│                ↓                                             │
│  IF remaining > event_cost ($0.03):                         │
│      → Allow GPT-4 call                                     │
│      → Deduct $0.03 from budget                             │
│  ELSE:                                                       │
│      → Fallback to OSS Llama3 ($0)                          │
└─────────────────────────────────────────────────────────────┘
```

**Cost Tracking**:
- Per-tenant spend dashboards
- Hourly/daily/monthly rollups
- Alert if 80% budget consumed

---

## Performance Characteristics

**Latency Breakdown** (p95):
- Ingestion + normalization: 10ms
- 25-stage pipeline: 80ms
- HopGraph correlation: 15ms
- Risk synthesis: 5ms
- AI escalation (if needed): 200ms (OSS) or 2000ms (GPT-4)
- **Total**: 110ms (no AI) or 2.3s (with GPT-4)

**Throughput**:
- Single worker: 500 events/sec
- With 4 workers: 1800 events/sec
- Bottleneck: PostgreSQL writes (can be buffered)

**Memory Footprint**:
- Base platform: 512MB
- HopGraph (10k events): +200MB
- OSS LLM (Llama3): +4GB GPU VRAM
- **Total**: ~5GB for full stack

---

## Summary

JanuSec's architecture is a **multi-tiered detection system** that:
1. Ingests heterogeneous security events
2. Processes through 25 specialized detection stages
3. Uses temporal graph correlation to find attack chains
4. Routes ambiguous cases through AI tiers (lightweight → GPT-4)
5. Provides explainable verdicts with MITRE mapping
6. Triggers automated response actions

**Unique Strengths**:
- Factor-based explainability (not black box)
- Cost-aware AI usage (FinOps gates)
- Temporal attack reconstruction (HopGraph)
- Multi-domain coverage in one platform

**Maturity**: 65-70% production-ready, needs scaling + hardening for enterprise.
