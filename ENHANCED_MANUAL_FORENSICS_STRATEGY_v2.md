# Manual Forensics & Human Empowerment Strategy v2.0
## Framework-Aligned IR/Threat Hunter Guidance with Evidence Collection Compliance

**Date**: 2025-12-26  
**Status**: Strategic Architecture Document  
**Philosophy**: **AI ASSISTS, HUMANS DECIDE, EVIDENCE PRESERVED**  
**Target Audience**: Incident Responders, Threat Hunters, SOC Analysts, CISOs

---

## EXECUTIVE SUMMARY

This document provides **operationally actionable guidance** for incident responders and threat hunters using JanuSec's human-in-the-loop forensics platform. It maps every detection capability to:

1. **MITRE ATT&CK** — Specific techniques (T1XXX.XXX)
2. **Cyber Kill Chain** — 7 stages from reconnaissance to actions on objectives
3. **DIAMOND Model** — Adversary-Capability-Infrastructure-Victim relationships
4. **DREAD** — Risk scoring (Damage, Reproducibility, Exploitability, Affected Users, Discoverability)
5. **PASTA** — Process for Attack Simulation and Threat Analysis (business impact)
6. **STRIDE** — Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege

This unified framework approach enables threat hunters to know **exactly where to look**, what evidence to collect, and how to maintain forensic integrity while minimizing false positives.

---

## TABLE OF CONTENTS

1. [Unified Threat Framework Integration](#1-unified-threat-framework-integration)
2. [Where to Look: Kill Chain Detection Matrix](#2-where-to-look-kill-chain-detection-matrix)
3. [Evidence Collection Strategy & Compliance](#3-evidence-collection-strategy--compliance)
4. [Anti-Hallucination & Quality Architecture](#4-anti-hallucination--quality-architecture)
5. [Technical Debt & Latency Reduction](#5-technical-debt--latency-reduction)
6. [Human-in-the-Loop Workflow](#6-human-in-the-loop-workflow)
7. [Implementation Roadmap](#7-implementation-roadmap)

---

## 1. UNIFIED THREAT FRAMEWORK INTEGRATION

### The Problem with Single-Framework Approaches

Most XDR platforms map only to MITRE ATT&CK, missing critical context:

| Framework | What It Answers | Limitation If Used Alone |
|-----------|-----------------|--------------------------|
| **MITRE ATT&CK** | "What technique did they use?" | No business impact, no adversary attribution |
| **Cyber Kill Chain** | "What stage of the attack?" | No technique granularity, linear assumption |
| **DIAMOND Model** | "Who attacked, using what, against whom?" | No procedural detail |
| **DREAD** | "How risky is this?" | No attack path context |
| **PASTA** | "What's the business impact?" | Requires pre-defined scenarios |
| **STRIDE** | "What security property is violated?" | Design-focused, not detection-focused |

### JanuSec's Multi-Framework Correlation

**Every alert includes all six perspectives:**

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│ ALERT: Suspicious PowerShell Execution on ws-finance-01                         │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│ ▶ MITRE ATT&CK                                                                  │
│   Technique: T1059.001 (PowerShell)                                             │
│   Tactic: Execution                                                             │
│   Sub-technique: Encoded Command (-enc flag detected)                           │
│                                                                                 │
│ ▶ CYBER KILL CHAIN                                                              │
│   Stage: 4 - Exploitation / 5 - Installation                                    │
│   Position: Post-delivery, pre-C2 establishment                                 │
│   Implication: Payload executing, time-critical response                        │
│                                                                                 │
│ ▶ DIAMOND MODEL                                                                 │
│   Adversary: Unknown (TTP matches APT29, confidence: 0.45)                      │
│   Capability: Encoded PowerShell downloader                                     │
│   Infrastructure: evil.com (known C2, confidence: 0.85)                         │
│   Victim: alice@ws-finance-01 (Finance department)                              │
│                                                                                 │
│ ▶ DREAD SCORE: 7.8/10                                                           │
│   Damage: 8 (credential access possible)                                        │
│   Reproducibility: 9 (commodity technique)                                      │
│   Exploitability: 8 (user click required, achieved)                             │
│   Affected Users: 6 (single host, but DA path exists)                           │
│   Discoverability: 7 (obfuscated but detectable)                                │
│                                                                                 │
│ ▶ PASTA BUSINESS IMPACT                                                         │
│   Asset: Financial reporting workstation                                        │
│   Data at risk: Q4 earnings (pre-announcement), PII                             │
│   Compliance: SOX, GDPR exposure                                                │
│   Business: Potential material event if exfiltrated                             │
│                                                                                 │
│ ▶ STRIDE CLASSIFICATION                                                         │
│   Primary: Elevation of Privilege (local → domain)                              │
│   Secondary: Information Disclosure (credential theft)                          │
│   Tertiary: Repudiation (log tampering likely next)                             │
│                                                                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│ WHERE TO LOOK NEXT (Prioritized):                                               │
│ 1. ws-finance-01: Check for persistence (T1547.001 - Registry Run Keys)         │
│ 2. dc01: Check 4624/4672 events for alice's token                               │
│ 3. Proxy logs: Validate evil.com traffic volume                                 │
│ 4. Email gateway: Find delivery vector (T1566.001 likely)                       │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. WHERE TO LOOK: KILL CHAIN DETECTION MATRIX

### For Threat Hunters: Stage-by-Stage Investigation Guide

This matrix tells you **exactly what artifacts to examine** at each stage:

### STAGE 1: RECONNAISSANCE (Pre-Intrusion)

**Kill Chain Position**: Attacker gathering target information  
**Detection Difficulty**: HARD (mostly external)

| What to Look For | Data Source | MITRE Technique | Tool/Command |
|------------------|-------------|-----------------|--------------|
| DNS reconnaissance | DNS logs, Passive DNS | T1595.002 | `grep -E "axfr|any" dns.log` |
| LinkedIn scraping indicators | Web proxy (unusual LinkedIn API) | T1593.001 | Check User-Agent anomalies |
| Shodan/Censys scans | Firewall (port scan patterns) | T1595.001 | Look for sequential port hits |
| Email harvesting | Email bounce logs | T1589.002 | Unusual VRFY/EXPN commands |

**JanuSec Detection Factors**:
- `external_recon_dns_axfr`: DNS zone transfer attempts
- `port_scan_sequential`: Sequential port scanning (>50 ports in 60s)
- `email_enumeration`: SMTP user enumeration attempts

**DIAMOND**: Adversary unknown, Capability = OSINT tools, Infrastructure = Tor/VPN exits, Victim = Your public-facing assets

---

### STAGE 2: WEAPONIZATION (Pre-Intrusion)

**Kill Chain Position**: Attacker creating payload  
**Detection Difficulty**: IMPOSSIBLE (occurs on attacker infrastructure)

**What You CAN Detect (Post-Delivery)**:

| Artifact | Indicates | MITRE Technique |
|----------|-----------|-----------------|
| Office doc with macros | Weaponized document | T1566.001 |
| PDF with JavaScript | Exploit delivery | T1566.001 |
| LNK file with cmd.exe | Living-off-the-land | T1204.002 |
| ISO/IMG with executable | Container bypass | T1553.005 |

**JanuSec Detection Factors**:
- `office_macro_enabled`: Document with VBA macros
- `pdf_javascript_embedded`: PDF with embedded JS
- `lnk_suspicious_target`: LNK pointing to scripting engine
- `container_file_executable`: ISO/IMG with PE inside

---

### STAGE 3: DELIVERY

**Kill Chain Position**: Payload reaches victim  
**Detection Difficulty**: MEDIUM (email gateway, proxy logs)

| Delivery Vector | Log Source | MITRE Technique | What to Look For |
|-----------------|------------|-----------------|------------------|
| Phishing email | Email gateway | T1566.001 | Attachment hashes, sender reputation |
| Drive-by download | Proxy logs | T1189 | Referer chains, exploit kit patterns |
| USB drop | Endpoint EDR | T1091 | USBSTOR events, autorun.inf |
| Watering hole | Proxy logs | T1189 | Legit site → malicious redirect |

**JanuSec Detection Factors**:
- `email_attachment_suspicious`: Known-bad hash or suspicious extension
- `download_double_extension`: file.pdf.exe pattern
- `usb_autorun_detected`: autorun.inf or suspicious LNK on USB
- `redirect_chain_suspicious`: >3 redirects ending in download

**WHERE TO LOOK**:
```
1. Email Gateway: quarantine logs, attachment sandbox results
2. Proxy Logs: Downloads from webmail (outlook.live.com, mail.google.com)
3. Endpoint: Browser download history, Recent folder
4. KAPE Collection: $MFT for file creation times
```

**STRIDE Impact**: Tampering (malicious file delivered), Information Disclosure (potential)

---

### STAGE 4: EXPLOITATION

**Kill Chain Position**: Vulnerability or user action triggers payload  
**Detection Difficulty**: MEDIUM-HIGH

| Exploitation Type | Log Source | MITRE Technique | Detection Pattern |
|-------------------|------------|-----------------|-------------------|
| Macro execution | Sysmon 1, 4688 | T1204.002 | WINWORD.EXE → cmd.exe/powershell.exe |
| Browser exploit | Sysmon 1 | T1203 | Browser → unusual child process |
| Local privilege escalation | 4688, Sysmon 1 | T1068 | Low-priv user → SYSTEM process |
| Office OLE exploit | Sysmon 1 | T1559.002 | Office → equation editor → payload |

**JanuSec Detection Factors**:
- `office_spawns_script`: Office app spawning PowerShell/cmd/wscript
- `browser_spawns_unexpected`: Browser spawning non-browser process
- `priv_esc_parent_child`: Low-integrity parent → high-integrity child
- `lolbin_execution`: certutil/mshta/regsvr32 with suspicious args

**WHERE TO LOOK**:
```
1. Sysmon Event 1: Process creation with full command line
2. Windows Security 4688: Process creation (if command line logging enabled)
3. Windows Security 4624: Logon immediately before suspicious process
4. KAPE: Prefetch files for execution timeline
```

**DREAD Scoring Guide**:
- Damage: 7-9 (code execution achieved)
- Reproducibility: Varies by exploit (8-9 for macro, 5-6 for 0day)
- Exploitability: 8 (user interaction complete)
- Affected Users: 1 initially (single host)
- Discoverability: 6-8 (depends on logging)

---

### STAGE 5: INSTALLATION

**Kill Chain Position**: Persistence established  
**Detection Difficulty**: MEDIUM

| Persistence Mechanism | Log Source | MITRE Technique | Registry/File Path |
|-----------------------|------------|-----------------|---------------------|
| Registry Run keys | Sysmon 13 | T1547.001 | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| Scheduled tasks | Security 4698 | T1053.005 | `C:\Windows\System32\Tasks\*` |
| Services | System 7045 | T1543.003 | `HKLM\SYSTEM\CurrentControlSet\Services` |
| WMI subscriptions | WMI-Activity | T1546.003 | WMI event subscriptions |
| Startup folder | Sysmon 11 | T1547.001 | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` |
| DLL hijacking | Sysmon 7 | T1574.001 | DLL in writable PATH location |

**JanuSec Detection Factors**:
- `persistence_registry_run`: Run/RunOnce key modification
- `persistence_scheduled_task`: Task created with suspicious action
- `persistence_service_created`: New service pointing to unusual binary
- `persistence_wmi_subscription`: WMI __EventFilter creation
- `persistence_startup_folder`: File dropped in Startup

**WHERE TO LOOK (KAPE Priority)**:
```
1. Registry hives: NTUSER.DAT (Run keys), SYSTEM (Services)
2. Scheduled Tasks: C:\Windows\System32\Tasks\*
3. Prefetch: Execution history of persistence payload
4. Amcache: SHA1 of persistent executables
5. $MFT: File creation times for timeline
```

**STRIDE Impact**: Elevation of Privilege (persistent access), Tampering (system modification)

---

### STAGE 6: COMMAND & CONTROL (C2)

**Kill Chain Position**: Attacker establishes communication  
**Detection Difficulty**: MEDIUM (network visibility dependent)

| C2 Pattern | Log Source | MITRE Technique | Detection Pattern |
|------------|------------|-----------------|-------------------|
| HTTP/HTTPS beaconing | Proxy/Firewall | T1071.001 | Regular intervals, same URL |
| DNS tunneling | DNS logs | T1071.004 | High entropy subdomains, TXT records |
| Domain fronting | TLS logs | T1090.004 | SNI ≠ Host header |
| Cobalt Strike | Network | T1071.001 | Default profile patterns |
| Encrypted channel | NetFlow | T1573 | Consistent packet sizes, timing |

**JanuSec Detection Factors**:
- `c2_beacon_interval`: Regular connection intervals (±10% jitter)
- `dns_high_entropy`: Subdomain entropy > 3.5
- `domain_fronting_mismatch`: Certificate CN ≠ destination
- `c2_known_infrastructure`: Connection to known-bad IP/domain
- `encrypted_unusual_port`: TLS on non-standard port

**WHERE TO LOOK**:
```
1. Firewall/Proxy: Outbound connections from compromised host
2. DNS logs: Query patterns from compromised host
3. NetFlow: Connection timing, volume, destination geo
4. Zeek/Bro logs: JA3/JA3S fingerprints for tool identification
5. KAPE: Browser history, network connection artifacts
```

**DIAMOND Model Application**:
- Infrastructure: C2 domain/IP (pivot point for attribution)
- Capability: C2 framework fingerprint (Cobalt Strike, Sliver, Brute Ratel)

---

### STAGE 7: ACTIONS ON OBJECTIVES

**Kill Chain Position**: Attacker achieves goal  
**Detection Difficulty**: VARIES (depends on visibility)

| Objective | Log Source | MITRE Technique | Detection Pattern |
|-----------|------------|-----------------|-------------------|
| Credential dumping | Sysmon 10 | T1003.001 | LSASS access from non-system |
| Data exfiltration | Proxy/NetFlow | T1041 | Large uploads, unusual destinations |
| Lateral movement | Security 4624 | T1021.002 | Type 3 logons, admin shares |
| Ransomware | Sysmon 11 | T1486 | Mass file encryption pattern |
| Domain persistence | DC Security | T1098 | Golden ticket indicators |

**JanuSec Detection Factors**:
- `lsass_access_suspicious`: Non-system process accessing LSASS
- `exfil_volume_anomaly`: Upload volume > 3σ from baseline
- `lateral_movement_smb`: SMB to admin shares from workstation
- `ransomware_mass_rename`: >100 file renames in 60 seconds
- `ad_persistence_golden`: DCSync or KRBTGT access

**WHERE TO LOOK**:
```
1. DC Security logs: 4624, 4672 (special privileges), 4768/4769 (Kerberos)
2. NetFlow: Large outbound transfers to cloud storage, Mega, etc.
3. File server: Access logs, file modification timestamps
4. KAPE on DC: NTDS.dit access attempts, SAM hive access
5. SRUM: Network usage per process (exfil identification)
```

**PASTA Business Impact Assessment**:
- Data exfil: Regulatory notification requirements, IP loss
- Ransomware: Business continuity, recovery cost
- Domain compromise: Total environment rebuild

---

## 3. EVIDENCE COLLECTION STRATEGY & COMPLIANCE

### The Fundamental Dilemma

You correctly identified the core tension in your CEO conversation:

```
┌─────────────────────────────────────────────────────────────────┐
│               EVIDENCE COLLECTION DILEMMA                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  NEED: Maximum telemetry for detection                          │
│        ↓                                                        │
│  PROBLEM: Collection methods create new risks                   │
│        ↓                                                        │
│  COMPLIANCE: GDPR, HIPAA, SOX, chain-of-custody                 │
│        ↓                                                        │
│  LEGAL: Evidence admissibility, non-repudiation                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Collection Method Risk Matrix

| Method | Telemetry Quality | Compliance Risk | Legal Risk | Operational Risk |
|--------|-------------------|-----------------|------------|------------------|
| **Deploy new agent** | Excellent | HIGH - Privacy consent | HIGH - Tampering claim | MEDIUM - Attacker detection |
| **Snapshot/Image** | Forensically sound | LOW | LOW | HIGH - Scale, disruption |
| **Existing EDR export** | Good | LOW | LOW | LOW |
| **Existing SIEM logs** | Variable | LOW | LOW | LOW |
| **KAPE (analyst-initiated)** | Excellent | MEDIUM | LOW (if documented) | LOW |
| **Network-only (passive)** | Limited | VERY LOW | VERY LOW | VERY LOW |

### JanuSec's Position: Ingest, Don't Deploy

**Strategic Decision**: JanuSec should NOT deploy agents. Instead:

```
┌─────────────────────────────────────────────────────────────────┐
│                 JANUSEC COLLECTION STRATEGY                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  INGEST WHAT CUSTOMERS ALREADY HAVE:                            │
│  ✅ EDR exports (CrowdStrike, Defender, SentinelOne)            │
│  ✅ SIEM exports (Splunk, Elastic, QRadar)                       │
│  ✅ Cloud audit logs (CloudTrail, Azure AD, GCP)                │
│  ✅ Network logs (firewall, proxy, DNS)                          │
│  ✅ KAPE collections (analyst-initiated, documented)            │
│                                                                  │
│  DO NOT:                                                         │
│  ❌ Deploy new agents                                            │
│  ❌ Auto-trigger endpoint collection                             │
│  ❌ Access live endpoints without explicit authorization         │
│                                                                  │
│  DIFFERENTIATION:                                                │
│  "JanuSec correlates what you already collect—without           │
│   breaking compliance or contaminating evidence."                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Compliance-Preserving Evidence Workflow

**PHASE 1: Passive Collection (Always-On)**
```
Source: Existing telemetry (already consented/documented)
- EDR streaming to SIEM → JanuSec ingestion
- Network logs → JanuSec correlation
- Cloud audit logs → JanuSec analysis

Compliance: ✅ No new collection, existing consent applies
Legal: ✅ Normal business operations
```

**PHASE 2: Active Collection (Incident-Triggered)**
```
Trigger: JanuSec alert reaches threshold (DREAD > 7.0)
Authorization: SOC Manager approval required

Step 1: Document authorization
  - Incident ticket number
  - Business justification
  - Scope of collection
  - Retention period

Step 2: KAPE collection (analyst-initiated)
  - Analyst runs KAPE on specific host
  - Hash all collected files immediately
  - Document analyst identity, timestamp
  - Store on write-once media or hashed storage

Step 3: Upload to JanuSec
  - KAPE CSV uploaded (not live access)
  - Correlate with existing alerts
  - Preserve chain-of-custody metadata

Compliance: ✅ Documented authorization, scope-limited
Legal: ✅ Chain-of-custody preserved
```

### Chain-of-Custody Implementation

```python
# JanuSec Evidence Provenance Tracking
class EvidenceChainOfCustody:
    """
    Track every piece of evidence from collection to analysis
    Required for legal admissibility and compliance
    """
    
    def __init__(self, evidence_id: str):
        self.evidence_id = evidence_id
        self.custody_chain = []
    
    def record_collection(self, 
                          collected_by: str,
                          collection_method: str,
                          source_system: str,
                          authorization_ticket: str,
                          timestamp: datetime):
        """Record initial evidence collection"""
        entry = {
            'action': 'COLLECTED',
            'actor': collected_by,
            'method': collection_method,
            'source': source_system,
            'authorization': authorization_ticket,
            'timestamp': timestamp.isoformat(),
            'hash_at_collection': self._compute_hash(),
            'signature': self._sign_entry()
        }
        self.custody_chain.append(entry)
    
    def record_analysis(self,
                        analyst: str,
                        analysis_type: str,
                        findings_summary: str):
        """Record each analysis action"""
        entry = {
            'action': 'ANALYZED',
            'actor': analyst,
            'analysis_type': analysis_type,
            'findings_summary': findings_summary,
            'timestamp': datetime.utcnow().isoformat(),
            'hash_verified': self._verify_hash(),
            'signature': self._sign_entry()
        }
        self.custody_chain.append(entry)
    
    def export_for_legal(self) -> dict:
        """Export custody chain for legal proceedings"""
        return {
            'evidence_id': self.evidence_id,
            'custody_chain': self.custody_chain,
            'total_custodians': len(set(e['actor'] for e in self.custody_chain)),
            'integrity_verified': all(e.get('hash_verified', True) for e in self.custody_chain)
        }
```

### What Can Go Wrong (Blockers & Mitigations)

| Blocker | Impact | Mitigation |
|---------|--------|------------|
| **GDPR Article 22** | Automated profiling without consent = violation | Human-in-the-loop design (analyst must select/approve) |
| **Chain-of-custody contamination** | Evidence inadmissible in court | Hash on collection, write-once storage, analyst documentation |
| **Non-repudiation failure** | Attacker claims "you planted it" | Collect from existing logs (not new agents), document everything |
| **Privacy (employee monitoring)** | HR/legal pushback, whistleblower risk | Scope collection to security-relevant data only, union consultation where required |
| **Attacker detection** | Agent deployment tips off attacker | Prefer passive collection, EDR already present |
| **Data residency** | Cross-border transfer violations | Process locally first, anonymize before transfer, use SCCs |
| **Retention conflicts** | GDPR minimization vs. investigation needs | Define retention policy per data type, auto-delete on schedule |
| **Privilege escalation** | IR team accesses more than needed | Role-based access, audit all IR actions, least-privilege |

---

## 4. ANTI-HALLUCINATION & QUALITY ARCHITECTURE

### Hallucination Root Causes & Mitigations

| Root Cause | Example | Mitigation |
|------------|---------|------------|
| **Missing data** | LLM invents process when only network logs uploaded | Data Availability Manifest |
| **Overgeneralization** | "PowerShell is always malicious" | Factor provenance with confidence scores |
| **Confabulation** | Invents events not in logs | Strict grounding prompts, deterministic fallback |
| **Temporal confusion** | Mixes past incidents with current | Session isolation, clear context boundaries |
| **Training bias** | Assumes Windows when analyzing Linux | OS-aware analysis, explicit system type |

### Data Availability Manifest (Critical P0)

**Implementation**: Inject available/missing fields into every LLM prompt

```python
def generate_data_manifest(uploaded_data: pd.DataFrame, required_fields: dict) -> dict:
    """
    Generate manifest of available vs missing data
    Prevents LLM hallucination on non-existent fields
    """
    manifest = {
        'available_fields': [],
        'missing_fields': [],
        'field_quality': {}
    }
    
    for field_category, fields in required_fields.items():
        for field in fields:
            if field in uploaded_data.columns:
                # Field exists - check quality
                null_pct = uploaded_data[field].isna().mean()
                manifest['available_fields'].append(field)
                manifest['field_quality'][field] = {
                    'null_percentage': null_pct,
                    'unique_values': uploaded_data[field].nunique(),
                    'sample_values': uploaded_data[field].dropna().head(3).tolist()
                }
            else:
                manifest['missing_fields'].append(field)
    
    return manifest

# LLM Prompt Template with Manifest
LLM_PROMPT_TEMPLATE = """
## DATA AVAILABILITY MANIFEST
AVAILABLE FIELDS: {available_fields}
MISSING FIELDS: {missing_fields}

## CRITICAL INSTRUCTIONS
1. ONLY reference fields listed in AVAILABLE FIELDS
2. For MISSING FIELDS, state: "No [field] data available. To confirm this hypothesis, collect: [specific guidance]"
3. DO NOT invent or assume values for missing fields
4. If analysis requires a MISSING FIELD, explain what you cannot determine and why

## ANALYSIS TASK
{analysis_task}

## EVENT DATA
{event_data}
"""
```

### Confidence Scoring Per Claim

**Every analytical claim includes verifiable confidence**:

```python
class AnalyticalClaim:
    """
    Every claim made by JanuSec includes confidence and evidence
    """
    def __init__(self, claim: str, confidence: float, evidence: list):
        self.claim = claim
        self.confidence = confidence  # 0.0 - 1.0
        self.evidence = evidence
        self.confidence_factors = []
    
    def explain_confidence(self) -> str:
        """Human-readable confidence explanation"""
        explanations = []
        
        if self.confidence >= 0.9:
            explanations.append("HIGH CONFIDENCE: Multiple independent sources confirm")
        elif self.confidence >= 0.7:
            explanations.append("MEDIUM-HIGH CONFIDENCE: Direct evidence available")
        elif self.confidence >= 0.5:
            explanations.append("MEDIUM CONFIDENCE: Inferred from available data")
        else:
            explanations.append("LOW CONFIDENCE: Limited evidence, hypothesis only")
        
        explanations.append(f"Evidence sources: {len(self.evidence)}")
        explanations.append(f"Factors: {', '.join(self.confidence_factors)}")
        
        return '\n'.join(explanations)

# Example output:
# Claim: "PowerShell executed with encoded command"
# Confidence: 0.85
# Explanation: MEDIUM-HIGH CONFIDENCE: Direct evidence available
#              Evidence sources: 2
#              Factors: sysmon_event_1_match, command_line_base64_pattern
```

### T1/T2 Conflict Detection

**Auto-flag when triage and deep analysis disagree**:

```python
def detect_t1_t2_conflicts(t1_result: dict, t2_result: dict) -> dict:
    """
    Compare T1 (fast triage) and T2 (deep investigation) results
    Flag conflicts for mandatory human review
    """
    conflicts = []
    
    # Severity drift
    severity_drift = abs(t1_result['severity'] - t2_result['severity'])
    if severity_drift > 3:
        conflicts.append({
            'type': 'SEVERITY_DRIFT',
            'detail': f"T1: {t1_result['severity']}, T2: {t2_result['severity']}",
            'action': 'MANDATORY_HUMAN_REVIEW',
            'risk': 'Potential hallucination in severity assessment'
        })
    
    # Verdict contradiction
    if t1_result['verdict'] != t2_result['verdict']:
        conflicts.append({
            'type': 'VERDICT_CONTRADICTION',
            'detail': f"T1: {t1_result['verdict']}, T2: {t2_result['verdict']}",
            'action': 'MANDATORY_HUMAN_REVIEW',
            'risk': 'LLM inconsistency - verify against source logs'
        })
    
    # MITRE technique disagreement
    t1_techniques = set(t1_result.get('mitre_techniques', []))
    t2_techniques = set(t2_result.get('mitre_techniques', []))
    if not t1_techniques.issubset(t2_techniques):
        missing = t1_techniques - t2_techniques
        conflicts.append({
            'type': 'MITRE_MISMATCH',
            'detail': f"T1 techniques not in T2: {missing}",
            'action': 'REVIEW_TECHNIQUE_MAPPING',
            'risk': 'Technique mapping inconsistency'
        })
    
    return {
        'has_conflicts': len(conflicts) > 0,
        'conflict_count': len(conflicts),
        'conflicts': conflicts,
        'recommendation': 'ESCALATE_TO_SENIOR_ANALYST' if len(conflicts) > 1 else 'ANALYST_REVIEW'
    }
```

---

## 5. TECHNICAL DEBT & LATENCY REDUCTION

### Current Architecture Problems

| Problem | Symptom | Root Cause |
|---------|---------|------------|
| **LLM Latency** | 5-10s per row analysis | Every row hits LLM |
| **Tech Bloat** | 30+ pipeline stages | Features added without removal |
| **Tech Debt** | Inconsistent factor naming | Rushed implementation, no standardization |
| **Hallucination** | Invented facts in reports | LLM ungrounded, no manifest |

### Tiered Analysis Architecture (Latency Fix)

```
┌─────────────────────────────────────────────────────────────────┐
│                    TIERED ANALYSIS PIPELINE                      │
│                    (90%+ LLM call reduction)                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  TIER 0: DETERMINISTIC HEURISTICS (10ms per row)                │
│  ─────────────────────────────────────────────────              │
│  • PowerShell -enc flag detection                               │
│  • Office spawning scripting engine                             │
│  • Known-bad hash lookup                                        │
│  • Regex pattern matching                                       │
│  Result: 90% of rows classified as PASSED (no LLM needed)       │
│                                                                  │
│           ↓ Only SUSPICIOUS rows continue                        │
│                                                                  │
│  TIER 1: FAST LLM TRIAGE (500ms per row)                        │
│  ─────────────────────────────────────────────────              │
│  • Lightweight model (gpt-4o-mini / Claude Haiku)               │
│  • 30-line summary                                               │
│  • Quick DREAD scoring                                           │
│  • MITRE technique mapping                                       │
│  Result: 70% of suspicious rows resolved                         │
│                                                                  │
│           ↓ Only ESCALATED rows continue                         │
│                                                                  │
│  TIER 2: DEEP INVESTIGATION (2-5s per row)                      │
│  ─────────────────────────────────────────────────              │
│  • Advanced model (gpt-4o / Claude Sonnet)                      │
│  • 100-line detailed analysis                                    │
│  • HopGraph attack reconstruction                                │
│  • Multi-framework correlation (MITRE + Kill Chain + DIAMOND)   │
│  • Missing log recommendations                                   │
│                                                                  │
│  RESULT: 97% LLM cost reduction, 95% latency reduction          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Tech Debt Reduction Strategy

**Principle**: Every pipeline stage must justify its existence

```python
# Stage Justification Framework
class PipelineStage:
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.metrics = {}
    
    def justify(self) -> dict:
        """Every stage must answer these questions"""
        return {
            'false_positive_reduction': self.metrics.get('fp_reduction_pct', 0),
            'false_negative_catch_rate': self.metrics.get('fn_catch_rate', 0),
            'latency_cost_ms': self.metrics.get('latency_ms', 0),
            'unique_value': self.description,
            'deprecation_candidate': self.metrics.get('fp_reduction_pct', 0) < 1.0
        }

# Stage Audit Report
STAGE_AUDIT = {
    'powershell_encoding_stage': {'fp_reduction_pct': 15.2, 'latency_ms': 5},   # KEEP
    'office_child_stage': {'fp_reduction_pct': 22.8, 'latency_ms': 3},          # KEEP
    'port_anomaly_stage': {'fp_reduction_pct': 0.8, 'latency_ms': 50},          # DEPRECATE
    'user_agent_stage': {'fp_reduction_pct': 0.3, 'latency_ms': 20},            # DEPRECATE
}
```

**Tech Bloat Prevention Rules**:
1. **Feature Flag Everything**: New stages start behind feature flags
2. **Sunset Dates**: Every new stage has a 90-day review date
3. **Justification Docs**: PR requires impact analysis before merge
4. **20% Refactor Budget**: Every sprint includes refactoring time
5. **Deprecation Pipeline**: Stages with <1% FP reduction get deprecated

### Caching Strategy

```python
# LLM Response Caching
class AnalysisCache:
    """
    Cache LLM responses for identical/similar inputs
    Reduces redundant LLM calls by 40-60%
    """
    
    def __init__(self, ttl_hours: int = 24):
        self.cache = {}
        self.ttl = ttl_hours * 3600
    
    def get_cache_key(self, event_data: dict) -> str:
        """Generate cache key from event characteristics"""
        # Key on stable attributes, not timestamps
        key_fields = [
            event_data.get('process_name', ''),
            event_data.get('parent_process', ''),
            self._normalize_command_line(event_data.get('command_line', '')),
            event_data.get('mitre_technique', '')
        ]
        return hashlib.sha256('|'.join(key_fields).encode()).hexdigest()
    
    def _normalize_command_line(self, cmdline: str) -> str:
        """Normalize command line for cache matching"""
        # Remove variable parts (timestamps, GUIDs, etc.)
        normalized = re.sub(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', '<GUID>', cmdline)
        normalized = re.sub(r'\d{4}-\d{2}-\d{2}', '<DATE>', normalized)
        return normalized
```

---

## 6. HUMAN-IN-THE-LOOP WORKFLOW

### Workflow Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  STEP 1: UPLOAD (Human initiates)                               │
│  ─────────────────────────────────────────────────────────────  │
│  • Analyst uploads CSV/Excel/JSON (any size)                    │
│  • Client-side parsing (no upload size limits)                  │
│  • Human decision: what data to analyze                         │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│  STEP 2: QUICK TRIAGE (Deterministic, instant)                  │
│  ─────────────────────────────────────────────────────────────  │
│  • Client-side heuristics (10ms)                                │
│  • No LLM, no hallucination risk                                │
│  • Human sees: "100 suspicious, 4,900 clean"                    │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│  STEP 3: HUMAN SELECTION (Critical gate)                        │
│  ─────────────────────────────────────────────────────────────  │
│  • Analyst CHOOSES which rows to analyze                        │
│  • Can select all suspicious, custom subset, or skip            │
│  • AI suggests, HUMAN DECIDES                                   │
│  • Compliance: GDPR Article 22 satisfied                        │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│  STEP 4: DEEP ANALYZE (LLM-assisted, grounded)                  │
│  ─────────────────────────────────────────────────────────────  │
│  • Data Availability Manifest injected                          │
│  • Multi-framework analysis (MITRE + Kill Chain + DIAMOND...)   │
│  • Confidence scores on every claim                             │
│  • Missing log recommendations                                   │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│  STEP 5: HUMAN REVIEW (Final gate)                              │
│  ─────────────────────────────────────────────────────────────  │
│  • Analyst reviews AI output                                    │
│  • Can edit, reject, or approve                                 │
│  • Conflicts flagged for attention                              │
│  • Feedback captured for model improvement                      │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│  STEP 6: REPORT GENERATION (Human-approved)                     │
│  ─────────────────────────────────────────────────────────────  │
│  • Executive summary (CISO-ready)                               │
│  • Technical details (SOC analyst)                              │
│  • Legal/compliance section (counsel)                           │
│  • Missing log playbooks (what to collect next)                 │
│  • All content human-reviewed before export                     │
└─────────────────────────────────────────────────────────────────┘
```

### Human Decision Points

**Where Humans MUST Be Involved**:

| Decision Point | Why Human Required | Automation Allowed |
|----------------|--------------------|--------------------|
| **Row Selection** | Scope control, legal | Suggestions only |
| **Verdict Override** | Context awareness | Never |
| **Severity Assignment** | Business impact | Initial estimate only |
| **Report Approval** | Accountability | Draft generation |
| **Collection Authorization** | Legal/compliance | Never |

**Where Automation Is Appropriate**:

| Task | Automation Level | Human Override |
|------|------------------|----------------|
| **Initial triage** | Full (heuristics) | Always available |
| **MITRE mapping** | High (deterministic) | Edit capability |
| **DREAD scoring** | Medium (LLM-assisted) | Final approval |
| **Missing log playbooks** | High (rule-based) | Customization |

---

## 7. IMPLEMENTATION ROADMAP

### Phase 1: Anti-Hallucination Foundation (Weeks 1-2)

| Task | Effort | Priority | Outcome |
|------|--------|----------|---------|
| Data Availability Manifest | 3 days | **P0** | LLM grounded, no field invention |
| Confidence Scoring | 1 week | **P1** | Every claim verifiable |
| T1/T2 Conflict Detection | 3 days | **P1** | Auto-flag inconsistencies |
| Human Feedback Loop | 2 days | **P1** | Track accuracy, improve prompts |

### Phase 2: Framework Integration (Weeks 3-5)

| Task | Effort | Priority | Outcome |
|------|--------|----------|---------|
| Kill Chain Stage Mapping | 1 week | **P0** | Every alert shows attack phase |
| DIAMOND Model Integration | 1 week | **P1** | Adversary-Capability-Infra-Victim |
| DREAD Auto-Scoring | 3 days | **P1** | Consistent risk assessment |
| STRIDE Classification | 2 days | **P2** | Security property violation |

### Phase 3: Evidence Collection (Weeks 6-8)

| Task | Effort | Priority | Outcome |
|------|--------|----------|---------|
| Chain-of-Custody Tracking | 1 week | **P0** | Legal admissibility |
| KAPE CSV Integration | 2 weeks | **P1** | Endpoint artifact correlation |
| Missing Log Playbooks | 2 weeks | **P0** | Actionable collection guidance |

### Phase 4: Performance & Quality (Weeks 9-10)

| Task | Effort | Priority | Outcome |
|------|--------|----------|---------|
| Tiered Analysis Pipeline | 1 week | **P1** | 90%+ LLM reduction |
| LLM Response Caching | 3 days | **P2** | 40-60% fewer API calls |
| Stage Audit & Deprecation | 1 week | **P1** | Tech bloat reduction |
| Hallucination Audit Trail | 3 days | **P2** | Track accuracy over time |

---

## STRATEGIC SUMMARY

### What JanuSec Does Better Than Competitors

| Capability | Splunk/Elastic | CrowdStrike | **JanuSec** |
|------------|----------------|-------------|-------------|
| **Human-in-the-loop** | ❌ Auto-only | ❌ Auto-only | ✅ Human selects/approves |
| **Multi-framework** | ⚠️ MITRE only | ⚠️ MITRE only | ✅ 6 frameworks integrated |
| **Anti-hallucination** | N/A (no LLM) | ❌ Black box | ✅ Grounded, verifiable |
| **Missing log guidance** | ❌ "Insufficient data" | ❌ "Insufficient data" | ✅ Specific collection commands |
| **Compliance design** | ⚠️ Partial | ❌ Requires customization | ✅ GDPR/HIPAA by design |
| **Chain-of-custody** | ⚠️ Limited | ⚠️ Limited | ✅ Full provenance tracking |

### Pitch Refinement

> **Old**: "JanuSec reduces false positives by 60-80%"
>
> **New**: "JanuSec is the only XDR triage platform where:
> - Humans decide what gets analyzed (GDPR compliant)
> - AI suggests but never acts alone
> - Every claim is verifiable against source evidence
> - You get told exactly what logs to collect next
> - Six threat frameworks guide investigation (not just MITRE)
>
> We don't replace your analysts. We make them 10x more effective."

---

## APPENDIX: FRAMEWORK QUICK REFERENCE

### MITRE ATT&CK Tactics (Ordered by Kill Chain)

| Tactic | Kill Chain Stage | Example Techniques |
|--------|------------------|---------------------|
| Reconnaissance | 1 | T1595, T1593 |
| Resource Development | 1-2 | T1583, T1584 |
| Initial Access | 3 | T1566, T1189, T1190 |
| Execution | 4 | T1059, T1204 |
| Persistence | 5 | T1547, T1053, T1543 |
| Privilege Escalation | 5 | T1068, T1548 |
| Defense Evasion | 5-6 | T1070, T1055, T1027 |
| Credential Access | 6-7 | T1003, T1555 |
| Discovery | 6-7 | T1082, T1083, T1069 |
| Lateral Movement | 7 | T1021, T1570 |
| Collection | 7 | T1005, T1039 |
| Command and Control | 6 | T1071, T1090 |
| Exfiltration | 7 | T1041, T1048 |
| Impact | 7 | T1486, T1490 |

### DREAD Scoring Guide

| Factor | 1-3 (Low) | 4-6 (Medium) | 7-10 (High) |
|--------|-----------|--------------|-------------|
| **Damage** | Info disclosure only | System compromise | Data destruction, ransom |
| **Reproducibility** | Requires 0day | Requires specific config | Commodity technique |
| **Exploitability** | Requires physical | Requires user action | Remote, unauth |
| **Affected Users** | Single user | Department | Entire org |
| **Discoverability** | Requires insider | Publicly documented | Auto-scannable |

### STRIDE Threat Categories

| Category | Security Property | Detection Focus |
|----------|-------------------|-----------------|
| **Spoofing** | Authentication | Invalid credentials, cert mismatch |
| **Tampering** | Integrity | Hash mismatch, log modification |
| **Repudiation** | Non-repudiation | Missing audit logs, timestamp gaps |
| **Information Disclosure** | Confidentiality | Data exfil, unauthorized access |
| **Denial of Service** | Availability | Resource exhaustion, crash |
| **Elevation of Privilege** | Authorization | Priv esc, token manipulation |

---

**Document Version**: 2.0  
**Last Updated**: 2025-12-26  
**Next Review**: 2026-01-26  
**Author**: JanuSec Architecture Team
