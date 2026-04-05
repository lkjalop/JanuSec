# JanuSec XDR Enterprise Framework
## Network & Endpoint Detection with Multi-Framework Threat Intelligence

**Version:** 2.0 Enterprise | **Date:** January 7, 2025 | **Classification:** Internal

---

## 1. Executive Summary

### Strategic Objective
Transform JanuSec's detection capabilities from **75% to 85%+ MITRE ATT&CK coverage** with enterprise-grade threat intelligence integration.

| Dimension | Current | Target | Gap |
|-----------|---------|--------|-----|
| **MITRE ATT&CK** | 75% | 85%+ | +10% |
| **Detection Factors** | 57 | 150+ | +93 |
| **Kill Chain Phases** | 5/7 | 7/7 | Recon, Weaponization |
| **Correlation Rules** | 12 | 50+ | Cross-domain patterns |
| **False Positive Rate** | 18% | <8% | ML + tuning |

### Business Impact

| Metric | Current | Target | Improvement |
|--------|---------|--------|-------------|
| MTTD | 45 min | 12 min | **73% ↓** |
| False Positives | 18% | <8% | **56% ↓** |
| Alert:Incident Ratio | 100:1 | 25:1 | **4x efficiency** |
| Analyst Triage Time | 25 min | 8 min | **68% ↓** |

---

## 2. Multi-Framework Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    THREAT INTELLIGENCE HUB                          │
├─────────────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌───────────┐  ┌────────┐  ┌────────┐  ┌──────────┐ │
│  │  MITRE   │  │   KILL    │  │ STRIDE │  │ DREAD  │  │  CVSS    │ │
│  │  ATT&CK  │  │   CHAIN   │  │ MODEL  │  │ SCORE  │  │  + KEV   │ │
│  │ 14 Tact. │  │ 7 Phases  │  │ 6 Cat. │  │ 5 Dim. │  │ NVD/CISA │ │
│  └────┬─────┘  └─────┬─────┘  └───┬────┘  └───┬────┘  └────┬─────┘ │
│       └──────────────┴────────────┴───────────┴────────────┘       │
│                              │                                      │
│                    ┌─────────▼─────────┐                           │
│                    │   CORRELATION     │                           │
│                    │     ENGINE        │                           │
│                    │  + HopGraph       │                           │
│                    └───────────────────┘                           │
└─────────────────────────────────────────────────────────────────────┘
```

### Framework Purpose Matrix

| Framework | Purpose | Integration |
|-----------|---------|-------------|
| **MITRE ATT&CK** | Adversary behavior taxonomy | Detection factor mapping |
| **Cyber Kill Chain** | Attack progression | Alert sequencing |
| **STRIDE** | Threat categorization | Response routing |
| **DREAD** | Risk quantification | Priority scoring |
| **CVSS** | Vulnerability severity | Alert enrichment |
| **CISA KEV** | Active exploitation | Emergency prioritization |

---

## 3. Detection Factor Schema

### Unified Factor Definition

```python
@dataclass
class DetectionFactor:
    """Multi-framework detection factor with comprehensive mapping."""
    
    # Core identification
    id: str                         # e.g., "endpoint:lsass_memory_access"
    name: str                       # "LSASS Memory Access"
    description: str
    domain: str                     # endpoint, network, identity, cloud
    
    # MITRE ATT&CK
    mitre_tactic: str               # TA0006: Credential Access
    mitre_technique: str            # T1003: OS Credential Dumping
    mitre_sub_technique: str        # T1003.001: LSASS Memory
    
    # Cyber Kill Chain
    kill_chain_phase: str           # actions_on_objectives
    
    # STRIDE Categories
    stride: List[str]               # [information_disclosure, elevation_of_privilege]
    
    # DREAD Scoring (1-10 each)
    dread_damage: int               # 9 - Full credential theft
    dread_reproducibility: int      # 8 - Well-documented tools
    dread_exploitability: int       # 7 - Requires local + admin
    dread_affected_users: int       # 9 - All system users
    dread_discoverability: int      # 6 - Requires endpoint visibility
    
    # CVSS (optional)
    cvss_score: float               # 7.8
    cvss_vector: str                # CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
    
    # Vulnerability correlation
    kev_references: List[str]       # ["CVE-2021-36934"]
    cve_references: List[str]
    
    # Detection metadata
    confidence_weight: float        # 0.90 - High confidence
    false_positive_rate: float      # 0.05 - 5% FP rate
    
    # Correlation hints
    related_factors: List[str]      # Commonly seen together
    prerequisite_factors: List[str] # Typically precede this
    
    @property
    def dread_total(self) -> float:
        return (self.dread_damage + self.dread_reproducibility + 
                self.dread_exploitability + self.dread_affected_users + 
                self.dread_discoverability) / 5
    
    @property
    def dread_risk_level(self) -> str:
        score = self.dread_total
        if score >= 8: return "CRITICAL"
        if score >= 6: return "HIGH"
        if score >= 4: return "MEDIUM"
        return "LOW"
```

---

## 4. Core Detection Factors (50+)

### 4.1 Endpoint Factors

| Factor ID | Name | MITRE | Kill Chain | DREAD | STRIDE |
|-----------|------|-------|------------|-------|--------|
| `endpoint:lsass_memory_access` | LSASS Memory Access | T1003.001 | Actions | 7.8 | I, E |
| `endpoint:sam_database_access` | SAM Database Access | T1003.002 | Actions | 7.6 | I |
| `endpoint:dcsync_replication` | DCSync Attack | T1003.006 | Actions | 8.4 | I, E |
| `endpoint:powershell_encoded` | PowerShell Encoded | T1059.001 | Exploit | 7.0 | T |
| `endpoint:lolbin_execution` | LOLBin Execution | T1218 | Exploit | 6.4 | T |
| `endpoint:wmi_execution` | WMI Execution | T1047 | Exploit | 6.8 | T |
| `endpoint:registry_run_key` | Registry Persistence | T1547.001 | Install | 7.2 | T |
| `endpoint:scheduled_task` | Scheduled Task | T1053.005 | Install | 7.0 | T, E |
| `endpoint:service_creation` | Service Creation | T1543.003 | Install | 7.4 | T, E |
| `endpoint:uac_bypass` | UAC Bypass | T1548.002 | Exploit | 7.6 | E |
| `endpoint:token_manipulation` | Token Manipulation | T1134 | Exploit | 7.4 | E, S |
| `endpoint:process_injection` | Process Injection | T1055 | Exploit | 7.6 | T, E |
| `endpoint:amsi_bypass` | AMSI Bypass | T1562.001 | Exploit | 7.2 | T |
| `endpoint:timestomp` | Timestamp Manipulation | T1070.006 | Actions | 6.2 | R, T |
| `endpoint:event_log_cleared` | Event Log Cleared | T1070.001 | Actions | 7.8 | R, T |
| `endpoint:psexec_execution` | PsExec Execution | T1570 | Actions | 7.4 | T |
| `endpoint:rdp_lateral` | RDP Lateral Movement | T1021.001 | Actions | 6.8 | T |
| `endpoint:keylogger` | Keylogger Activity | T1056.001 | Actions | 7.2 | I |
| `endpoint:screen_capture` | Screen Capture | T1113 | Actions | 5.8 | I |
| `endpoint:data_staged` | Data Staged | T1074 | Actions | 7.4 | I |
| `endpoint:archive_created` | Suspicious Archive | T1560 | Actions | 7.0 | I |

### 4.2 Network Factors

| Factor ID | Name | MITRE | Kill Chain | DREAD | STRIDE |
|-----------|------|-------|------------|-------|--------|
| `network:port_scan_horizontal` | Horizontal Port Scan | T1595.001 | Recon | 5.8 | I |
| `network:port_scan_vertical` | Vertical Port Scan | T1595.001 | Recon | 5.6 | I |
| `network:c2_beaconing` | C2 Beaconing | T1071 | C2 | 7.4 | T |
| `network:dns_tunneling` | DNS Tunneling | T1071.004 | C2 | 7.6 | I |
| `network:dga_domain` | DGA Domain | T1568.002 | C2 | 7.8 | T |
| `network:tor_connection` | Tor Connection | T1090.003 | C2 | 7.0 | R |
| `network:ja3_malicious` | Malicious JA3 | T1573 | C2 | 8.2 | T |
| `network:jarm_c2_server` | C2 JARM Fingerprint | T1573 | C2 | 8.0 | T |
| `network:self_signed_cert` | Self-Signed Cert | T1573.002 | C2 | 5.0 | S |
| `network:large_upload` | Large Data Upload | T1048 | Actions | 7.2 | I |
| `network:data_exfil_cloud` | Cloud Exfiltration | T1567.002 | Actions | 7.8 | I |
| `network:smb_lateral` | SMB Lateral Movement | T1021.002 | Actions | 7.4 | T |

### 4.3 Identity Factors

| Factor ID | Name | MITRE | Kill Chain | DREAD | STRIDE |
|-----------|------|-------|------------|-------|--------|
| `identity:impossible_travel` | Impossible Travel | T1078 | Delivery | 7.0 | S |
| `identity:brute_force` | Brute Force | T1110 | Delivery | 7.2 | S |
| `identity:password_spray` | Password Spray | T1110.003 | Delivery | 7.6 | S |
| `identity:privileged_account` | Privileged Account | T1078.002 | Exploit | 7.8 | E |
| `identity:mfa_bypass` | MFA Bypass | T1111 | Delivery | 8.2 | S, T |

### 4.4 Cloud Factors

| Factor ID | Name | MITRE | Kill Chain | DREAD | STRIDE |
|-----------|------|-------|------------|-------|--------|
| `cloud:iam_privilege_esc` | IAM Privilege Escalation | T1098 | Exploit | 8.6 | E |
| `cloud:s3_public_exposure` | S3 Public Exposure | T1537 | Actions | 9.0 | I |
| `cloud:security_group_mod` | Security Group Modified | T1562.007 | Install | 7.6 | T |
| `cloud:cryptominer` | Cryptominer Detected | T1496 | Actions | 6.8 | D |

**STRIDE Legend:** S=Spoofing, T=Tampering, R=Repudiation, I=Information Disclosure, D=DoS, E=Elevation of Privilege

---

## 5. Cyber Kill Chain Alignment

```
┌─────────────────────────────────────────────────────────────────────┐
│                     KILL CHAIN COVERAGE                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  PHASE 1: RECONNAISSANCE                              ░░░ 25%      │
│  Factors: port_scan_horizontal, port_scan_vertical                 │
│  Gap: External threat intel, OSINT correlation                     │
│                                                                     │
│  PHASE 2: WEAPONIZATION                               ░░░ 15%      │
│  Factors: (limited - threat intel only)                            │
│  Gap: YARA rules, sandbox integration, MISP                        │
│                                                                     │
│  PHASE 3: DELIVERY                                    ▓▓▓░ 65%     │
│  Factors: impossible_travel, brute_force, password_spray           │
│  Gap: USB/removable media detection                                │
│                                                                     │
│  PHASE 4: EXPLOITATION                                ▓▓▓▓ 78%     │
│  Factors: powershell_encoded, lolbin, wmi, uac_bypass             │
│  Gap: Zero-day detection, browser exploits                         │
│                                                                     │
│  PHASE 5: INSTALLATION                                ▓▓▓▓ 80%     │
│  Factors: registry_run_key, scheduled_task, service_creation       │
│  Gap: Bootkit/rootkit, firmware persistence                        │
│                                                                     │
│  PHASE 6: COMMAND & CONTROL                           ▓▓▓▓░ 75%    │
│  Factors: c2_beaconing, dns_tunneling, dga, ja3, jarm             │
│  Gap: Protocol-specific C2, domain fronting                        │
│                                                                     │
│  PHASE 7: ACTIONS ON OBJECTIVES                       ▓▓▓▓░ 72%    │
│  Factors: lsass_access, dcsync, large_upload, data_exfil          │
│  Gap: Ransomware early detection, data destruction                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Kill Chain Tracker Implementation

```python
class KillChainTracker:
    """Track attack progression through Kill Chain phases."""
    
    def process_event(self, event: Dict, factor: DetectionFactor):
        """
        Process event and update kill chain tracking.
        
        Alert conditions:
        1. Reached EXPLOITATION phase (attack underway)
        2. 3+ phases observed (campaign pattern)
        3. Rapid phase progression (<1 hour between phases)
        4. Reached ACTIONS phase (mission execution)
        """
        entity = self._get_entity(event)
        phase = factor.kill_chain_phase
        
        # Update tracking
        sequence = self.active_sequences.get(entity, [])
        sequence.append({"phase": phase, "factor": factor.id, "time": event["timestamp"]})
        
        # Check for significant progression
        unique_phases = len(set(e["phase"] for e in sequence))
        
        if phase in ["exploitation", "actions_on_objectives"]:
            return self._create_alert(entity, sequence, "ATTACK_PROGRESSION")
        
        if unique_phases >= 3:
            return self._create_alert(entity, sequence, "CAMPAIGN_DETECTED")
        
        return None
```

---

## 6. DREAD Risk Scoring

### Scoring Methodology

| Dimension | Description | Scale |
|-----------|-------------|-------|
| **Damage** | How severe if exploited? | 1-10 |
| **Reproducibility** | How easy to reproduce? | 1-10 |
| **Exploitability** | What's required to exploit? | 1-10 |
| **Affected Users** | How many impacted? | 1-10 |
| **Discoverability** | How easy to discover? | 1-10 |

### Risk Level Thresholds

| Level | Score | SLA | Response |
|-------|-------|-----|----------|
| **CRITICAL** | 8.0-10.0 | 1 hour | Immediate, all hands |
| **HIGH** | 6.0-7.9 | 4 hours | Priority response |
| **MEDIUM** | 4.0-5.9 | 8 hours | Standard response |
| **LOW** | 1.0-3.9 | 24 hours | Scheduled review |

### DREAD Calculator with Contextual Modifiers

```python
class DREADCalculator:
    """Calculate risk scores with contextual enrichment."""
    
    def calculate(self, alert: Dict) -> DREADAssessment:
        # Base DREAD from factors
        base = self._aggregate_factor_dread(alert["factors"])
        
        # Asset criticality modifier (0.5-2.0)
        asset_mod = self._get_asset_criticality(alert.get("hostname"))
        # Crown Jewels: 2.0, Tier 1: 1.5, Tier 2: 1.0, Tier 3: 0.5
        
        # Threat intel boost (0-2.0)
        ti_boost = self._check_threat_intel(alert)
        # APT: +2.0, Ransomware: +1.5, Malware family: +1.0
        
        # Historical FP adjustment
        fp_reduction = self._get_fp_rate(alert["factors"]) * 2
        
        # Adjusted score
        adjusted = (base * asset_mod + ti_boost - fp_reduction)
        return min(10.0, max(1.0, adjusted))
```

---

## 7. CVSS & KEV Integration

### CVSS Enrichment

```python
class CVSSEnricher:
    """Enrich alerts with CVSS vulnerability data."""
    
    def enrich(self, alert: Dict) -> Dict:
        cve_ids = self._get_related_cves(alert)
        
        enrichment = {
            "max_cvss_score": 0.0,
            "max_severity": "NONE",
            "network_exploitable": 0,
            "no_auth_required": 0,
            "vulnerabilities": []
        }
        
        for cve_id in cve_ids:
            vuln = self.nvd.get(cve_id)
            if vuln and vuln["cvss_score"] > enrichment["max_cvss_score"]:
                enrichment["max_cvss_score"] = vuln["cvss_score"]
                enrichment["max_severity"] = vuln["severity"]
        
        return enrichment
```

### CISA KEV Integration

```python
class KEVEnricher:
    """Enrich alerts with CISA Known Exploited Vulnerabilities."""
    
    KEV_API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    def enrich(self, alert: Dict) -> Dict:
        cve_ids = self._get_related_cves(alert)
        
        enrichment = {
            "kev_match": False,
            "kev_entries": [],
            "priority_boost": 0.0,
            "compliance_status": "NOT_APPLICABLE",
            "ransomware_risk": False
        }
        
        for cve_id in cve_ids:
            kev_entry = self.catalog.get(cve_id)
            if kev_entry:
                enrichment["kev_match"] = True
                enrichment["priority_boost"] = 2.0
                
                if kev_entry["is_past_due"]:
                    enrichment["priority_boost"] = 3.0
                    enrichment["compliance_status"] = "VIOLATION"
                
                if kev_entry["known_ransomware_use"]:
                    enrichment["ransomware_risk"] = True
                    enrichment["priority_boost"] += 0.5
        
        return enrichment
```

### KEV Priority Override Matrix

| KEV Status | Override | Action |
|------------|----------|--------|
| Match + Past Due | CRITICAL + VIOLATION | Immediate remediation |
| Match + <7 days | CRITICAL | Priority remediation |
| Match + Ransomware | +0.5 boost | Enhanced monitoring |
| Match + <30 days | HIGH minimum | Scheduled remediation |

---

## 8. STRIDE Threat Classification

### Category Coverage

| Category | Coverage | Key Factors |
|----------|----------|-------------|
| **Spoofing** | 78% | impossible_travel, brute_force, token_manipulation |
| **Tampering** | 82% | powershell_encoded, process_injection, amsi_bypass |
| **Repudiation** | 80% | event_log_cleared, timestomp, tor_connection |
| **Info Disclosure** | 85% | lsass_access, dcsync, dns_tunneling, s3_exposure |
| **Denial of Service** | 72% | cryptominer, mass_file_encryption |
| **Elevation of Privilege** | 85% | uac_bypass, token_manipulation, iam_privilege_esc |

### STRIDE-Based Response Routing

```python
RESPONSE_ROUTING = {
    "SPOOFING": {
        "team": "identity_team",
        "action": "account_investigation",
        "sla_hours": 4
    },
    "TAMPERING": {
        "team": "endpoint_team",
        "action": "host_isolation",
        "sla_hours": 2
    },
    "REPUDIATION": {
        "team": "forensics_team",
        "action": "evidence_preservation",
        "sla_hours": 8
    },
    "INFORMATION_DISCLOSURE": {
        "team": "data_security",
        "action": "data_classification_review",
        "sla_hours": 2
    },
    "DENIAL_OF_SERVICE": {
        "team": "network_team",
        "action": "traffic_mitigation",
        "sla_hours": 1
    },
    "ELEVATION_OF_PRIVILEGE": {
        "team": "endpoint_team",
        "action": "privilege_audit",
        "sla_hours": 1
    }
}
```

---

## 9. Correlation Rules Engine

### Enterprise Correlation Rules

| Rule ID | Name | Trigger | Severity |
|---------|------|---------|----------|
| **CORR-001** | Credential Theft Chain | lsass_access → lateral_movement | HIGH |
| **CORR-002** | DCSync Attack | dcsync + privileged_account | CRITICAL |
| **CORR-003** | Malware Infection | suspicious_parent → persistence → c2 | HIGH |
| **CORR-004** | Ransomware Precursor | shadow_delete + bcdedit + encryption | CRITICAL |
| **CORR-005** | Data Exfiltration | archive_created → large_upload | CRITICAL |
| **CORR-006** | Lateral Movement Campaign | Multiple hosts via remote exec | HIGH |
| **CORR-007** | Security Tool Tampering | amsi_bypass + defender_disable | HIGH |
| **CORR-008** | Advanced C2 Channel | beaconing + ja3/jarm/dga | CRITICAL |
| **CORR-009** | Account Compromise | impossible_travel + malicious_activity | HIGH |
| **CORR-010** | Cloud Infrastructure Attack | iam_escalation + s3_exposure | CRITICAL |

### Correlation Rule Definition

```python
@dataclass
class CorrelationRule:
    rule_id: str
    name: str
    description: str
    
    # Matching criteria
    required_factors: List[str]     # Must be present
    optional_factors: List[str]     # Boost confidence
    time_window_minutes: int        # Max time between events
    entity_fields: List[str]        # Fields to match (host, user, ip)
    
    # Scoring
    base_confidence: float          # Base if rule matches
    factor_weights: Dict[str, float]  # Per-factor weights
    
    # Output
    incident_type: str              # Type if rule fires
    severity_override: str          # Override calculated severity
    
    # Context
    kill_chain_phases: List[str]
    mitre_techniques: List[str]

# Example: Credential Theft Chain
CORR_001 = CorrelationRule(
    rule_id="CORR-001",
    name="Credential Theft Chain",
    description="Credential dumping followed by lateral movement",
    required_factors=["endpoint:lsass_memory_access"],
    optional_factors=[
        "endpoint:sam_database_access",
        "endpoint:dcsync_replication",
        "network:smb_lateral",
        "endpoint:psexec_execution"
    ],
    time_window_minutes=60,
    entity_fields=["hostname", "user"],
    base_confidence=0.85,
    factor_weights={
        "endpoint:dcsync_replication": 0.95,
        "network:smb_lateral": 0.80
    },
    incident_type="CREDENTIAL_THEFT",
    severity_override="HIGH",
    kill_chain_phases=["actions_on_objectives"],
    mitre_techniques=["T1003", "T1021"]
)
```

---

## 10. Implementation Roadmap

### Phase 1: Foundation (Months 1-3)

| Week | Focus | Deliverables |
|------|-------|--------------|
| 1-2 | Detection Factor Registry | Multi-framework schema, 50 core factors |
| 3-4 | eBPF Linux Agent | Process/network/file syscall hooks |
| 5-6 | DREAD Calculator | Risk scoring engine |
| 7-8 | TLS Fingerprinting | JA3/JA3S/JARM implementation |
| 9-10 | KEV Integration | CISA API sync, alert enrichment |
| 11-12 | Kill Chain Tracker | Phase correlation, timeline assembly |

### Phase 2: Advanced Detection (Months 4-6)

| Week | Focus | Deliverables |
|------|-------|--------------|
| 13-14 | ETW Windows Agent | Kernel-level Windows telemetry |
| 15-16 | Behavioral ML | Process/user anomaly detection |
| 17-18 | Correlation Engine | 10 enterprise correlation rules |
| 19-20 | CVSS/NVD Integration | Vulnerability enrichment |
| 21-22 | STRIDE Classifier | Threat categorization, routing |
| 23-24 | Production Hardening | Performance, reliability, tuning |

### Success Metrics

| Milestone | Current | Target | Timeline |
|-----------|---------|--------|----------|
| Detection Factors | 57 | 150+ | Month 6 |
| MITRE Coverage | 75% | 85%+ | Month 6 |
| Kill Chain Coverage | 5/7 | 7/7 | Month 3 |
| Correlation Rules | 12 | 50+ | Month 6 |
| False Positive Rate | 18% | <8% | Month 6 |
| MTTD | 45 min | 12 min | Month 6 |

---

## Appendix A: Quick Reference Cards

### DREAD Scoring Quick Reference

```
DAMAGE (1-10)
  10: Full system/network compromise
   8: Credential theft, ransomware
   6: Privilege escalation
   4: Configuration changes
   2: Minor disruption

REPRODUCIBILITY (1-10)
  10: Public tools, always works
   6: Specific conditions needed
   2: Very difficult to reproduce

EXPLOITABILITY (1-10)
  10: Remote, no auth, automated
   6: Insider access needed
   2: Physical access + admin

AFFECTED USERS (1-10)
  10: Enterprise-wide
   6: Single department
   2: Single user

DISCOVERABILITY (1-10)
  10: Public CVE, active exploitation
   6: Standard enumeration
   2: Extensive research needed
```

### Kill Chain → Factor Mapping

```
RECONNAISSANCE → port_scan_*, dns_recon
DELIVERY → impossible_travel, brute_force, password_spray
EXPLOITATION → powershell_*, lolbin, wmi, uac_bypass
INSTALLATION → registry_run_key, scheduled_task, service_creation
COMMAND_CONTROL → c2_beaconing, dns_tunneling, dga, ja3/jarm
ACTIONS → lsass_access, dcsync, large_upload, data_exfil
```

### STRIDE → Response Team

```
S (Spoofing) → identity_team (4h SLA)
T (Tampering) → endpoint_team (2h SLA)
R (Repudiation) → forensics_team (8h SLA)
I (Info Disclosure) → data_security (2h SLA)
D (DoS) → network_team (1h SLA)
E (Privilege Esc) → endpoint_team (1h SLA)
```

---

**Document Version:** 2.0 Enterprise  
**Generated:** January 7, 2025  
**Classification:** Internal - Technical Architecture
