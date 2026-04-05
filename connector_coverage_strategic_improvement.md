# JanuSec Connector Coverage: Strategic Improvement Guide
## Cross-Domain Attack Detection & Telemetry Enrichment

**Version:** 2.0  
**Date:** November 2025  
**Purpose:** Transform 68% coverage into attack-chain-aware detection capability

---

## Executive Assessment

### What You Did Right

Your existing document shows solid architectural thinking:

1. **Domain taxonomy is correct** — 8 security domains is industry-standard (MITRE D3FEND aligns similarly)
2. **API-first approach** — Smart for multi-tenant SaaS; webhook receivers scale better than polling
3. **HopGraph correlation** — This is your differentiator; most competitors bolt-on correlation
4. **Canonical schema thinking** — Entity normalization is the foundation of cross-domain detection

### What's Missing for Real Attack Chains

Your current coverage is **breadth-focused** (many sources, shallow depth). For the attacks you mentioned, you need **depth-focused** coverage:

| Attack Chain | Current Capability | Gap |
|-------------|-------------------|-----|
| **Lateral Movement** | RDP logs only | Missing: PTH/PTT detection, SMB lateral, WMI/PSRemoting |
| **Data Exfiltration** | Generic DLP (50%) | Missing: DNS exfil, steganography, cloud sync abuse |
| **Email Phishing** | O365/Gmail (60%) | Missing: Link detonation, attachment sandboxing correlation |
| **Registry Persistence** | Sysmon Event 13 only | Missing: Full registry hive analysis, autoruns correlation |
| **BGP Poisoning** | Not covered | Missing: BGP route monitoring, ASN anomaly detection |

**Honest Assessment: You have telemetry sources, but not attack detection logic.**

---

## Part 1: Attack Chain Coverage Analysis

### Attack Chain 1: Lateral Movement

**Kill Chain:**
```
Initial Access → Execution → Credential Access → Lateral Movement → Collection → Exfiltration
```

**Current Coverage:**
```
✅ RDP/Bastion logs (90% coverage)
⚠️  Sysmon (Event 1, but not Event 3 network connections)
❌ SMB session enumeration
❌ WMI/WinRM remote execution
❌ Pass-the-Hash/Pass-the-Ticket detection
❌ DCOM lateral movement
❌ PsExec/service installation
```

**Required Telemetry:**

| Technique | MITRE ID | Required Telemetry | Source |
|-----------|----------|-------------------|--------|
| Remote Services: RDP | T1021.001 | ✅ Have this | RDP logs |
| Remote Services: SMB | T1021.002 | Event 5140, 5145 | Windows Security |
| Remote Services: WinRM | T1021.006 | Event 91, 168 | WinRM Operational |
| Pass-the-Hash | T1550.002 | Event 4624 (Type 9), NTLM events | Windows Security |
| Pass-the-Ticket | T1550.003 | Event 4768, 4769 anomalies | Kerberos logs |
| WMI | T1047 | Event 5857-5861 | WMI Operational |
| Service Execution | T1569.002 | Event 7045, 4697 | Windows Security |
| DCOM | T1021.003 | DCOMScm events | DCOM logs |

**Missing Connector:**
```python
# src/collectors/windows_lateral_collector.py

class WindowsLateralMovementCollector:
    """
    Collect Windows events specifically for lateral movement detection.
    
    Key Event IDs:
    - 4624: Logon (filter Type 3, 9, 10)
    - 4625: Failed logon
    - 4648: Explicit credentials
    - 4768: Kerberos TGT request
    - 4769: Kerberos service ticket
    - 4776: NTLM authentication
    - 5140: Network share access
    - 5145: Network share object access
    - 7045: Service installed
    """
    
    LATERAL_MOVEMENT_EVENTS = {
        # Logon events
        4624: {'name': 'logon', 'logon_types': [3, 9, 10]},  # Network, NewCreds, RemoteInteractive
        4625: {'name': 'failed_logon'},
        4648: {'name': 'explicit_credentials'},
        
        # Kerberos events (PTT detection)
        4768: {'name': 'tgt_request'},
        4769: {'name': 'service_ticket'},
        4771: {'name': 'kerberos_preauth_failed'},
        
        # NTLM events (PTH detection)
        4776: {'name': 'ntlm_auth'},
        
        # Share access (SMB lateral)
        5140: {'name': 'share_access'},
        5145: {'name': 'share_object_access'},
        
        # Service/execution
        7045: {'name': 'service_installed'},
        4697: {'name': 'service_installed_audit'},
    }
    
    def detect_pass_the_hash(self, events: list) -> list:
        """
        PTH indicators:
        1. Type 9 (NewCredentials) logon
        2. NTLM auth with no preceding interactive logon
        3. Same user, multiple hosts, short timeframe
        """
        pth_candidates = []
        
        for event in events:
            if event.get('event_id') == 4624:
                logon_type = event.get('logon_type')
                auth_package = event.get('auth_package', '').lower()
                
                if logon_type == 9 and 'ntlm' in auth_package:
                    pth_candidates.append({
                        'detection': 'potential_pth',
                        'confidence': 0.7,
                        'evidence': {
                            'logon_type': logon_type,
                            'auth_package': auth_package,
                            'target_host': event.get('workstation_name'),
                            'source_ip': event.get('ip_address'),
                            'user': event.get('target_user_name')
                        }
                    })
        
        return pth_candidates
    
    def detect_pass_the_ticket(self, events: list) -> list:
        """
        PTT indicators:
        1. TGS request without preceding TGT request
        2. Service ticket for unusual SPNs
        3. Ticket encryption downgrade (RC4 instead of AES)
        """
        ptt_candidates = []
        
        # Group by user
        user_events = {}
        for event in events:
            user = event.get('target_user_name')
            if user not in user_events:
                user_events[user] = {'tgt': [], 'tgs': []}
            
            if event.get('event_id') == 4768:
                user_events[user]['tgt'].append(event)
            elif event.get('event_id') == 4769:
                user_events[user]['tgs'].append(event)
        
        # Check for TGS without TGT
        for user, ticket_events in user_events.items():
            if ticket_events['tgs'] and not ticket_events['tgt']:
                ptt_candidates.append({
                    'detection': 'potential_ptt',
                    'confidence': 0.8,
                    'evidence': {
                        'reason': 'TGS_without_TGT',
                        'user': user,
                        'service_names': [e.get('service_name') for e in ticket_events['tgs']]
                    }
                })
        
        return ptt_candidates
```

---

### Attack Chain 2: Data Exfiltration

**Current Coverage:**
```
✅ Network flows (Zeek - bytes out tracking)
⚠️  Generic DLP (50%)
❌ DNS tunneling detection
❌ HTTPS/TLS to suspicious destinations
❌ Cloud storage abuse (OneDrive, GDrive, Dropbox)
❌ Steganography/encoded data
❌ Email-based exfil (large attachments)
❌ USB/removable media
```

**Required Telemetry:**

| Exfil Method | Detection Approach | Required Source |
|-------------|-------------------|-----------------|
| DNS Tunneling | Long queries, high entropy, unusual TXT records | DNS logs (full query) |
| HTTPS to C2 | JA3 fingerprint, cert anomalies, beacon patterns | Zeek SSL logs + TI |
| Cloud Storage | API calls to cloud services from sensitive hosts | CASB or proxy logs |
| Steganography | File type/size anomalies, entropy analysis | DLP + file inspection |
| Email Exfil | Large attachments, external recipients | O365/Gmail DLP |
| USB Exfil | Removable device events | Sysmon Event 6, Windows 6416 |

**Missing Connector - DNS Exfil Detection:**
```python
# src/detectors/dns_exfil_detector.py

import math
from collections import Counter

class DNSExfilDetector:
    """
    Detect DNS-based data exfiltration.
    
    Indicators:
    1. High entropy subdomains (encoded data)
    2. Unusually long queries
    3. High volume of TXT/NULL record requests
    4. Queries to known DNS tunnel domains
    5. Consistent query patterns (beaconing)
    """
    
    # Known DNS tunneling tools domains
    KNOWN_TUNNEL_DOMAINS = [
        'dnscat2', 'iodine', 'dns2tcp', 'dnsexfiltrator'
    ]
    
    @staticmethod
    def calculate_entropy(string: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not string:
            return 0.0
        
        counter = Counter(string)
        length = len(string)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
        )
        return entropy
    
    def analyze_query(self, query: str, record_type: str) -> dict:
        """
        Analyze a single DNS query for exfil indicators.
        
        Returns dict with:
        - is_suspicious: bool
        - confidence: float
        - indicators: list of detected patterns
        """
        indicators = []
        confidence = 0.0
        
        # Extract subdomain (everything before the registered domain)
        parts = query.lower().split('.')
        if len(parts) < 3:
            return {'is_suspicious': False, 'confidence': 0.0, 'indicators': []}
        
        subdomain = '.'.join(parts[:-2])
        
        # Check 1: High entropy subdomain
        entropy = self.calculate_entropy(subdomain)
        if entropy > 3.5:  # Random/encoded data typically > 4.0
            indicators.append({
                'type': 'high_entropy_subdomain',
                'value': entropy,
                'threshold': 3.5
            })
            confidence += 0.3
        
        # Check 2: Unusually long query
        if len(query) > 50:
            indicators.append({
                'type': 'long_query',
                'length': len(query),
                'threshold': 50
            })
            confidence += 0.2
        
        # Check 3: Suspicious record type
        if record_type in ['TXT', 'NULL', 'PRIVATE']:
            indicators.append({
                'type': 'suspicious_record_type',
                'record_type': record_type
            })
            confidence += 0.15
        
        # Check 4: Hex/Base64 patterns in subdomain
        if self._looks_encoded(subdomain):
            indicators.append({
                'type': 'encoded_subdomain',
                'pattern': 'hex_or_base64'
            })
            confidence += 0.25
        
        # Check 5: Known tunnel domain
        for known in self.KNOWN_TUNNEL_DOMAINS:
            if known in query.lower():
                indicators.append({
                    'type': 'known_tunnel_domain',
                    'matched': known
                })
                confidence += 0.5
        
        return {
            'is_suspicious': confidence >= 0.4,
            'confidence': min(confidence, 1.0),
            'indicators': indicators,
            'query': query,
            'subdomain_entropy': entropy
        }
    
    def _looks_encoded(self, string: str) -> bool:
        """Check if string appears to be hex or base64 encoded."""
        # Hex: only 0-9, a-f
        hex_chars = set('0123456789abcdef')
        if len(string) > 10 and all(c in hex_chars for c in string.lower() if c != '.'):
            return True
        
        # Base64: alphanumeric + /+=
        b64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        if len(string) > 10 and all(c in b64_chars for c in string if c != '.'):
            return True
        
        return False
    
    def analyze_session(self, queries: list, time_window_sec: int = 300) -> dict:
        """
        Analyze a session of DNS queries for exfil patterns.
        
        Additional session-level checks:
        - Query frequency (beaconing)
        - Total data volume in queries
        - Unique vs repeated queries ratio
        """
        if not queries:
            return {'is_suspicious': False}
        
        session_indicators = []
        
        # Check: High query volume to single domain
        domain_counts = Counter(q.get('domain') for q in queries)
        for domain, count in domain_counts.most_common(5):
            if count > 100:  # >100 queries in 5 min window
                session_indicators.append({
                    'type': 'high_query_volume',
                    'domain': domain,
                    'count': count,
                    'window_sec': time_window_sec
                })
        
        # Check: Regular intervals (beaconing)
        timestamps = sorted(q.get('timestamp', 0) for q in queries)
        if len(timestamps) > 10:
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            avg_interval = sum(intervals) / len(intervals)
            std_interval = (sum((i - avg_interval)**2 for i in intervals) / len(intervals)) ** 0.5
            
            # Low standard deviation = regular beaconing
            if std_interval < 2.0 and avg_interval < 60:  # < 2 sec std dev, < 60 sec avg
                session_indicators.append({
                    'type': 'beacon_pattern',
                    'avg_interval_sec': avg_interval,
                    'std_dev': std_interval
                })
        
        # Check: Total data in subdomains
        total_subdomain_bytes = sum(
            len(q.get('query', '').split('.')[0])
            for q in queries
        )
        if total_subdomain_bytes > 10000:  # >10KB in subdomain data
            session_indicators.append({
                'type': 'high_subdomain_volume',
                'bytes': total_subdomain_bytes
            })
        
        return {
            'is_suspicious': len(session_indicators) > 0,
            'indicators': session_indicators,
            'query_count': len(queries),
            'unique_domains': len(domain_counts)
        }
```

---

### Attack Chain 3: Email Phishing → Execution

**Current Coverage:**
```
✅ O365/Gmail basic logs
⚠️  URL extraction (partial)
❌ Link detonation correlation
❌ Attachment sandbox results
❌ Click tracking → endpoint execution correlation
❌ QR code phishing (quishing)
❌ Callback phishing (TOAD)
```

**Required Telemetry Correlation:**

```
Email received (ts: T0)
    → User clicked link (ts: T0 + 30s) [O365 Safe Links / Proofpoint TAP]
    → Browser navigated to URL (ts: T0 + 32s) [Proxy/DNS]
    → File downloaded (ts: T0 + 45s) [Proxy/Endpoint]
    → Process executed (ts: T0 + 60s) [EDR/Sysmon]
    
This is a SINGLE attack chain that spans 4 telemetry sources.
```

**Missing Connector - Phishing Correlation:**
```python
# src/detectors/phishing_chain_detector.py

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, List

@dataclass
class PhishingChainEvent:
    timestamp: datetime
    event_type: str  # email_received, link_clicked, url_visited, file_downloaded, process_executed
    user: str
    source: str
    details: dict

class PhishingChainDetector:
    """
    Correlate email → click → download → execution chains.
    
    This is the money maker for phishing detection.
    Most tools detect individual events; we detect the CHAIN.
    """
    
    CHAIN_WINDOW_SEC = 300  # 5 minutes from email to execution
    
    def __init__(self, hopgraph_client):
        self.hopgraph = hopgraph_client
        self.pending_chains = {}  # user -> list of partial chains
    
    def ingest_event(self, event: PhishingChainEvent) -> Optional[dict]:
        """
        Process an event and check if it completes or extends a chain.
        """
        user = event.user
        
        if user not in self.pending_chains:
            self.pending_chains[user] = []
        
        # Clean up old chains
        self._cleanup_stale_chains(user)
        
        # Try to extend existing chains
        for chain in self.pending_chains[user]:
            if self._event_extends_chain(chain, event):
                chain['events'].append(event)
                chain['last_update'] = event.timestamp
                
                # Check if chain is complete
                if self._chain_is_complete(chain):
                    return self._generate_alert(chain)
        
        # Start new chain if this is an email event
        if event.event_type == 'email_received':
            self.pending_chains[user].append({
                'start_time': event.timestamp,
                'last_update': event.timestamp,
                'user': user,
                'events': [event],
                'email_details': event.details
            })
        
        return None
    
    def _event_extends_chain(self, chain: dict, event: PhishingChainEvent) -> bool:
        """Check if event logically follows the chain."""
        last_event = chain['events'][-1]
        time_delta = (event.timestamp - last_event.timestamp).total_seconds()
        
        # Must be within window
        if time_delta > self.CHAIN_WINDOW_SEC or time_delta < 0:
            return False
        
        # Check logical sequence
        valid_transitions = {
            'email_received': ['link_clicked', 'attachment_opened'],
            'link_clicked': ['url_visited', 'file_downloaded'],
            'url_visited': ['file_downloaded'],
            'attachment_opened': ['file_downloaded', 'process_executed'],
            'file_downloaded': ['process_executed'],
        }
        
        return event.event_type in valid_transitions.get(last_event.event_type, [])
    
    def _chain_is_complete(self, chain: dict) -> bool:
        """
        Chain is complete when we see execution following email.
        
        Complete chains:
        - email → click → download → execute
        - email → attachment → execute
        """
        event_types = [e.event_type for e in chain['events']]
        
        complete_patterns = [
            ['email_received', 'link_clicked', 'file_downloaded', 'process_executed'],
            ['email_received', 'link_clicked', 'url_visited', 'file_downloaded', 'process_executed'],
            ['email_received', 'attachment_opened', 'process_executed'],
        ]
        
        for pattern in complete_patterns:
            if self._matches_pattern(event_types, pattern):
                return True
        
        return False
    
    def _matches_pattern(self, event_types: list, pattern: list) -> bool:
        """Check if event_types contains pattern in order (not necessarily contiguous)."""
        pattern_idx = 0
        for event_type in event_types:
            if event_type == pattern[pattern_idx]:
                pattern_idx += 1
                if pattern_idx == len(pattern):
                    return True
        return False
    
    def _generate_alert(self, chain: dict) -> dict:
        """Generate a high-confidence phishing chain alert."""
        events = chain['events']
        
        # Extract key IOCs
        email_event = next(e for e in events if e.event_type == 'email_received')
        exec_event = next((e for e in events if e.event_type == 'process_executed'), None)
        
        iocs = {
            'sender': email_event.details.get('from'),
            'subject': email_event.details.get('subject'),
            'urls': [e.details.get('url') for e in events if 'url' in e.details],
            'files': [e.details.get('file_path') for e in events if 'file_path' in e.details],
            'process': exec_event.details.get('process_name') if exec_event else None,
            'command_line': exec_event.details.get('command_line') if exec_event else None,
        }
        
        # Calculate chain duration
        duration_sec = (events[-1].timestamp - events[0].timestamp).total_seconds()
        
        return {
            'alert_type': 'phishing_chain_complete',
            'severity': 'CRITICAL',
            'confidence': 0.95,  # Very high - we saw the full chain
            'user': chain['user'],
            'chain_duration_sec': duration_sec,
            'event_count': len(events),
            'iocs': iocs,
            'timeline': [
                {
                    'timestamp': e.timestamp.isoformat(),
                    'event_type': e.event_type,
                    'source': e.source,
                    'details': e.details
                }
                for e in events
            ],
            'mitre_techniques': [
                'T1566.001',  # Phishing: Spearphishing Attachment
                'T1566.002',  # Phishing: Spearphishing Link
                'T1204.001',  # User Execution: Malicious Link
                'T1204.002',  # User Execution: Malicious File
            ],
            'recommended_actions': [
                'Isolate endpoint immediately',
                'Block sender domain at email gateway',
                'Block URLs at proxy',
                'Search for other recipients of same email',
                'Preserve email for forensics',
            ]
        }
    
    def _cleanup_stale_chains(self, user: str):
        """Remove chains older than window."""
        now = datetime.utcnow()
        self.pending_chains[user] = [
            chain for chain in self.pending_chains[user]
            if (now - chain['last_update']).total_seconds() < self.CHAIN_WINDOW_SEC
        ]
```

---

### Attack Chain 4: Registry Persistence

**Current Coverage:**
```
✅ Sysmon Event 13 (Registry value set)
⚠️  Limited to real-time events
❌ Historical registry analysis
❌ Registry hive forensics
❌ Autoruns correlation
❌ WMI persistence
❌ Scheduled task persistence
```

**Required Telemetry:**

| Persistence Method | MITRE ID | Required Telemetry |
|-------------------|----------|-------------------|
| Registry Run Keys | T1547.001 | Sysmon 13 + Registry hive analysis |
| Scheduled Task | T1053.005 | Sysmon 1 + Task Scheduler logs |
| WMI Event Subscription | T1546.003 | WMI Operational logs |
| Boot/Logon Init Scripts | T1037 | Registry + GPO analysis |
| DLL Search Order Hijack | T1574.001 | File system + process monitoring |
| Services | T1543.003 | Event 7045, Service registry keys |

**Missing Connector - Persistence Detection:**
```python
# src/detectors/persistence_detector.py

class PersistenceDetector:
    """
    Detect persistence mechanisms across registry, scheduled tasks, and services.
    """
    
    # High-value persistence registry paths
    PERSISTENCE_REGISTRY_PATHS = {
        # User-level Run keys
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run': 'run_key',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce': 'runonce_key',
        
        # Machine-level Run keys
        r'HKLM\Software\Microsoft\Windows\CurrentVersion\Run': 'run_key',
        r'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce': 'runonce_key',
        
        # Services
        r'HKLM\SYSTEM\CurrentControlSet\Services': 'service_key',
        
        # Winlogon
        r'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell': 'winlogon_shell',
        r'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit': 'winlogon_userinit',
        
        # Image File Execution Options (IFEO)
        r'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options': 'ifeo',
        
        # AppInit DLLs
        r'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs': 'appinit_dlls',
        
        # Browser Helper Objects
        r'HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects': 'bho',
        
        # COM hijacking
        r'HKCU\Software\Classes\CLSID': 'com_hijack',
        r'HKLM\Software\Classes\CLSID': 'com_hijack',
        
        # Startup folder (via registry)
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Startup': 'startup_folder',
    }
    
    # Suspicious value patterns
    SUSPICIOUS_PATTERNS = [
        r'powershell.*-enc',           # Encoded PowerShell
        r'cmd.*/c.*&',                 # Command chaining
        r'mshta.*http',                # MSHTA with URL
        r'regsvr32.*/s.*/u',           # Regsvr32 abuse
        r'rundll32.*javascript',       # Rundll32 JS execution
        r'certutil.*-urlcache',        # Certutil download
        r'bitsadmin.*/transfer',       # BITS download
        r'\\AppData\\Local\\Temp\\',   # Temp folder execution
        r'\\Users\\Public\\',          # Public folder execution
    ]
    
    def analyze_registry_event(self, event: dict) -> dict:
        """
        Analyze a Sysmon Event 13 (Registry value set) for persistence.
        """
        target_object = event.get('target_object', '')
        details = event.get('details', '')  # The value being set
        
        result = {
            'is_persistence': False,
            'persistence_type': None,
            'confidence': 0.0,
            'indicators': [],
            'mitre_technique': None
        }
        
        # Check if path is a known persistence location
        for reg_path, persistence_type in self.PERSISTENCE_REGISTRY_PATHS.items():
            if reg_path.lower() in target_object.lower():
                result['is_persistence'] = True
                result['persistence_type'] = persistence_type
                result['confidence'] = 0.6
                result['indicators'].append({
                    'type': 'persistence_registry_path',
                    'path': target_object,
                    'category': persistence_type
                })
                break
        
        if not result['is_persistence']:
            return result
        
        # Check value for suspicious patterns
        import re
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, details, re.IGNORECASE):
                result['confidence'] += 0.2
                result['indicators'].append({
                    'type': 'suspicious_value_pattern',
                    'pattern': pattern,
                    'matched_value': details[:200]  # Truncate for logging
                })
        
        # Check for unsigned/unknown executables
        # This would integrate with your existing novel_global check
        if '\\temp\\' in details.lower() or '\\appdata\\' in details.lower():
            result['confidence'] += 0.15
            result['indicators'].append({
                'type': 'suspicious_path',
                'path': details
            })
        
        # Map to MITRE
        result['mitre_technique'] = self._map_to_mitre(result['persistence_type'])
        
        return result
    
    def _map_to_mitre(self, persistence_type: str) -> str:
        mapping = {
            'run_key': 'T1547.001',
            'runonce_key': 'T1547.001',
            'service_key': 'T1543.003',
            'winlogon_shell': 'T1547.004',
            'winlogon_userinit': 'T1547.004',
            'ifeo': 'T1546.012',
            'appinit_dlls': 'T1546.010',
            'bho': 'T1176',
            'com_hijack': 'T1546.015',
            'startup_folder': 'T1547.001',
        }
        return mapping.get(persistence_type, 'T1547')
    
    def analyze_scheduled_task(self, event: dict) -> dict:
        """
        Analyze scheduled task creation for persistence.
        
        Event sources:
        - Sysmon Event 1 with schtasks.exe
        - Task Scheduler Operational log Event 106, 140, 141
        """
        result = {
            'is_persistence': False,
            'confidence': 0.0,
            'indicators': [],
            'mitre_technique': 'T1053.005'
        }
        
        task_name = event.get('task_name', '')
        action = event.get('action', '')  # Command to execute
        trigger = event.get('trigger', '')  # When it runs
        user = event.get('user', '')
        
        # Task created by non-admin running as SYSTEM = suspicious
        if 'SYSTEM' in event.get('run_as', '') and 'admin' not in user.lower():
            result['is_persistence'] = True
            result['confidence'] += 0.4
            result['indicators'].append({
                'type': 'privilege_escalation_task',
                'created_by': user,
                'runs_as': event.get('run_as')
            })
        
        # Check action for suspicious patterns
        import re
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, action, re.IGNORECASE):
                result['is_persistence'] = True
                result['confidence'] += 0.3
                result['indicators'].append({
                    'type': 'suspicious_task_action',
                    'pattern': pattern,
                    'action': action[:200]
                })
        
        # Boot/logon trigger = persistence
        if any(t in trigger.lower() for t in ['boot', 'logon', 'startup', 'idle']):
            result['is_persistence'] = True
            result['confidence'] += 0.2
            result['indicators'].append({
                'type': 'persistence_trigger',
                'trigger': trigger
            })
        
        return result
```

---

### Attack Chain 5: BGP Poisoning / Route Hijacking

**Current Coverage:**
```
❌ Not covered at all
```

**This is a Gap, But...**

BGP monitoring is typically handled at the network edge by:
- ISPs
- BGP monitoring services (BGPStream, RIPE RIS, RouteViews)
- Enterprise BGP routers (if you're a large org)

**What JanuSec Can Do:**

1. **Ingest BGP alerts from monitoring services**
2. **Correlate with network telemetry** (traffic to hijacked prefixes)
3. **Detect ASN anomalies in your traffic**

**Missing Connector - BGP/ASN Anomaly:**
```python
# src/collectors/bgp_monitor_collector.py

import aiohttp
from datetime import datetime, timedelta

class BGPMonitorCollector:
    """
    Collect BGP anomaly data from public monitoring services.
    
    Sources:
    - BGPStream (CAIDA) - https://bgpstream.caida.org/
    - RIPE RIS - https://ris.ripe.net/
    - Cloudflare Radar - https://radar.cloudflare.com/
    """
    
    BGPSTREAM_API = "https://bgpstream.caida.org/api/v2"
    
    async def fetch_hijack_alerts(self, prefixes: list[str], hours: int = 24) -> list:
        """
        Fetch BGP hijack alerts for monitored prefixes.
        
        prefixes: List of your organization's IP prefixes (e.g., ['192.0.2.0/24'])
        """
        alerts = []
        
        async with aiohttp.ClientSession() as session:
            for prefix in prefixes:
                params = {
                    'resource': prefix,
                    'starttime': (datetime.utcnow() - timedelta(hours=hours)).isoformat(),
                    'type': 'hijacks,leaks'
                }
                
                async with session.get(f"{self.BGPSTREAM_API}/events", params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for event in data.get('events', []):
                            alerts.append({
                                'alert_type': 'bgp_anomaly',
                                'event_type': event.get('type'),  # hijack, leak, outage
                                'prefix': prefix,
                                'origin_asn': event.get('origin_asn'),
                                'expected_asn': event.get('expected_asn'),
                                'detected_by': event.get('collector'),
                                'timestamp': event.get('timestamp'),
                                'severity': self._assess_severity(event)
                            })
        
        return alerts
    
    def _assess_severity(self, event: dict) -> str:
        if event.get('type') == 'hijack':
            return 'CRITICAL'
        elif event.get('type') == 'leak':
            return 'HIGH'
        else:
            return 'MEDIUM'


class ASNAnomalyDetector:
    """
    Detect anomalies in ASN patterns from your network traffic.
    
    Use case: Identify traffic going to unexpected ASNs which could indicate:
    - BGP hijacking affecting your users
    - Traffic interception
    - Route leaks
    """
    
    def __init__(self, baseline_asns: dict):
        """
        baseline_asns: Expected ASNs for critical destinations
        Example: {
            'google.com': [15169],
            'microsoft.com': [8075, 8068, 8069],
            'your-bank.com': [12345]
        }
        """
        self.baseline = baseline_asns
    
    def analyze_connection(self, dest_domain: str, dest_asn: int) -> dict:
        """
        Check if traffic to a domain is going to the expected ASN.
        """
        if dest_domain not in self.baseline:
            return {'is_anomaly': False, 'reason': 'domain_not_monitored'}
        
        expected_asns = self.baseline[dest_domain]
        
        if dest_asn not in expected_asns:
            return {
                'is_anomaly': True,
                'severity': 'HIGH',
                'reason': 'unexpected_asn',
                'details': {
                    'domain': dest_domain,
                    'observed_asn': dest_asn,
                    'expected_asns': expected_asns
                },
                'possible_causes': [
                    'BGP hijack in progress',
                    'Route leak',
                    'DNS hijack + traffic reroute',
                    'CDN/anycast expected variation (verify)'
                ]
            }
        
        return {'is_anomaly': False}
```

---

## Part 2: Tool Integration Priority Matrix

### Tier 1: Critical for Attack Chain Detection (Implement First)

| Tool | Attack Chains Enabled | Integration Effort | ROI |
|------|----------------------|-------------------|-----|
| **CrowdStrike Falcon** | All endpoint chains | 2 weeks | HIGH - real-time EDR data |
| **Proofpoint TAP** | Phishing chain | 3 days | HIGH - #1 attack vector |
| **Microsoft Defender for Endpoint** | All endpoint chains | 2 weeks | HIGH - if customer uses M365 |
| **AWS CloudTrail** | Cloud lateral movement, exfil | 1 week | HIGH - most common cloud |
| **Velociraptor** | Forensic artifact collection | 1 week | HIGH - DFIR capability |

### Tier 2: Important for Visibility Depth

| Tool | Attack Chains Enabled | Integration Effort | ROI |
|------|----------------------|-------------------|-----|
| **Suricata EVE** | Network IDS alerts | 3 days | MEDIUM |
| **Tetragon** | Container/K8s attacks | 5 days | MEDIUM |
| **Varonis** | Data exfil detection | 1 week | MEDIUM |
| **KAPE** | Forensic timeline | 1 week | MEDIUM |
| **OSQuery** | Live endpoint interrogation | 3 days | MEDIUM |

### Tier 3: Nice to Have

| Tool | Use Case | Effort | ROI |
|------|----------|--------|-----|
| **Duo Security** | MFA bypass detection | 2 days | LOW |
| **Carbon Black** | Alternative EDR | 2 weeks | LOW (unless customer has it) |
| **BGPStream** | Route hijacking | 3 days | LOW (niche use case) |
| **GCP Audit Logs** | GCP visibility | 1 week | LOW (unless customer uses GCP) |

---

## Part 3: Client Security Posture Assessment

### Integration Selection Framework

**Question 1: What's their primary endpoint protection?**
```
CrowdStrike    → Build CrowdStrike connector first
Microsoft MDE  → Build MDE connector first
SentinelOne    → Build S1 connector first
Carbon Black   → Build CB connector first
None/Legacy AV → Recommend Velociraptor + Sysmon
```

**Question 2: What's their email security?**
```
Proofpoint     → Build TAP connector
Mimecast       → Build Mimecast connector
Microsoft O365 → Enhance existing O365 connector
Google         → Enhance existing Gmail connector
None           → Major gap, recommend deployment
```

**Question 3: What's their cloud footprint?**
```
AWS primary    → CloudTrail + GuardDuty connectors
Azure primary  → Activity Log + Sentinel connectors
GCP primary    → Audit Log connector
Multi-cloud    → All of the above + CSPM integration
```

**Question 4: What's their identity provider?**
```
Okta           → ✅ Already have
Azure AD       → ✅ Already have
Google         → Need enhancement
JumpCloud      → Build connector
On-prem AD     → Need Windows Event forwarding
```

### Client Onboarding Decision Tree

```python
# src/onboarding/connector_selector.py

def recommend_connectors(client_profile: dict) -> list:
    """
    Recommend connectors based on client's security stack.
    """
    recommendations = []
    
    # Always needed
    recommendations.append({
        'connector': 'sysmon',
        'priority': 'CRITICAL',
        'reason': 'Baseline endpoint visibility'
    })
    
    # EDR selection
    edr = client_profile.get('edr')
    if edr == 'crowdstrike':
        recommendations.append({
            'connector': 'crowdstrike_falcon',
            'priority': 'CRITICAL',
            'reason': 'Primary EDR integration'
        })
    elif edr == 'microsoft_mde':
        recommendations.append({
            'connector': 'microsoft_defender',
            'priority': 'CRITICAL',
            'reason': 'Primary EDR integration'
        })
    elif edr is None:
        recommendations.append({
            'connector': 'velociraptor',
            'priority': 'HIGH',
            'reason': 'Compensate for missing EDR with DFIR capability'
        })
    
    # Email security
    email_sec = client_profile.get('email_security')
    if email_sec == 'proofpoint':
        recommendations.append({
            'connector': 'proofpoint_tap',
            'priority': 'CRITICAL',
            'reason': 'Email threat intelligence'
        })
    elif email_sec == 'mimecast':
        recommendations.append({
            'connector': 'mimecast',
            'priority': 'CRITICAL',
            'reason': 'Email threat intelligence'
        })
    
    # Cloud - always add if they have it
    if 'aws' in client_profile.get('cloud_providers', []):
        recommendations.extend([
            {'connector': 'aws_cloudtrail', 'priority': 'HIGH', 'reason': 'AWS audit trail'},
            {'connector': 'aws_guardduty', 'priority': 'MEDIUM', 'reason': 'AWS threat detection'}
        ])
    
    if 'azure' in client_profile.get('cloud_providers', []):
        recommendations.extend([
            {'connector': 'azure_activity', 'priority': 'HIGH', 'reason': 'Azure audit trail'},
            {'connector': 'azure_sentinel', 'priority': 'MEDIUM', 'reason': 'Azure SIEM integration'}
        ])
    
    # Identity - fill gaps
    idp = client_profile.get('identity_provider')
    if idp not in ['okta', 'azure_ad']:  # We already have these
        recommendations.append({
            'connector': f'{idp}_connector',
            'priority': 'HIGH',
            'reason': 'Identity visibility gap'
        })
    
    # Sort by priority
    priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    recommendations.sort(key=lambda x: priority_order.get(x['priority'], 4))
    
    return recommendations
```

---

## Part 4: Cross-Domain Correlation Improvements

### Current HopGraph Limitations

Based on your connector doc, HopGraph has:
- ✅ Temporal correlation (events within time window)
- ✅ Entity linking (user, host, IP)
- ⚠️ Limited to single-hop connections
- ❌ No multi-hop attack path reconstruction
- ❌ No probabilistic path scoring

### Recommended Improvements

```python
# src/graph/attack_path_analyzer.py

class AttackPathAnalyzer:
    """
    Analyze multi-hop attack paths across domains.
    
    This is what differentiates JanuSec from competitors:
    - Splunk: Manual SPL queries for correlation
    - Elastic: Requires custom detection rules
    - Chronicle: Limited to Google-defined entity links
    
    JanuSec: Automatic multi-domain attack chain detection
    """
    
    # Define valid attack path transitions
    VALID_TRANSITIONS = {
        'email_received': ['link_clicked', 'attachment_opened'],
        'link_clicked': ['file_downloaded', 'credential_phished'],
        'attachment_opened': ['process_executed', 'macro_executed'],
        'file_downloaded': ['process_executed'],
        'credential_phished': ['authentication_attempt', 'mfa_bypass'],
        'authentication_attempt': ['session_established', 'failed_auth'],
        'session_established': ['privilege_escalation', 'lateral_movement', 'data_access'],
        'process_executed': ['child_process_spawned', 'network_connection', 'file_created', 'registry_modified'],
        'privilege_escalation': ['domain_admin_access', 'cloud_admin_access'],
        'lateral_movement': ['session_established', 'service_installed'],
        'data_access': ['data_staged', 'data_exfiltrated'],
        'data_staged': ['data_exfiltrated', 'data_encrypted'],
        'data_exfiltrated': [],  # Terminal
        'data_encrypted': [],  # Terminal (ransomware)
    }
    
    def find_attack_paths(
        self, 
        events: list, 
        start_event_type: str = None,
        max_depth: int = 10,
        time_window_sec: int = 3600
    ) -> list:
        """
        Find all valid attack paths in the event stream.
        
        Returns list of attack chains with risk scores.
        """
        # Group events by entity (user, host)
        entity_events = self._group_by_entity(events)
        
        paths = []
        
        for entity, entity_events in entity_events.items():
            # Sort by timestamp
            sorted_events = sorted(entity_events, key=lambda x: x['timestamp'])
            
            # Find paths starting from initial access events
            initial_events = [
                e for e in sorted_events 
                if e['event_type'] in ['email_received', 'drive_by_download', 'usb_inserted']
            ]
            
            for start_event in initial_events:
                path = self._trace_path(
                    start_event, 
                    sorted_events, 
                    max_depth, 
                    time_window_sec
                )
                if path and len(path['events']) > 2:
                    paths.append(path)
        
        # Score and rank paths
        scored_paths = [self._score_path(p) for p in paths]
        return sorted(scored_paths, key=lambda x: x['risk_score'], reverse=True)
    
    def _trace_path(
        self, 
        start: dict, 
        all_events: list, 
        max_depth: int, 
        window_sec: int
    ) -> dict:
        """Recursively trace attack path from start event."""
        path = {
            'start_time': start['timestamp'],
            'entity': start.get('user') or start.get('host'),
            'events': [start],
            'transitions': []
        }
        
        current_event = start
        depth = 0
        
        while depth < max_depth:
            # Find valid next events
            valid_next_types = self.VALID_TRANSITIONS.get(current_event['event_type'], [])
            if not valid_next_types:
                break  # Terminal event
            
            # Find matching events within time window
            next_event = None
            for event in all_events:
                time_delta = (event['timestamp'] - current_event['timestamp']).total_seconds()
                
                if 0 < time_delta <= window_sec and event['event_type'] in valid_next_types:
                    # Check entity linkage
                    if self._entities_linked(current_event, event):
                        next_event = event
                        break
            
            if not next_event:
                break
            
            path['events'].append(next_event)
            path['transitions'].append({
                'from': current_event['event_type'],
                'to': next_event['event_type'],
                'time_delta_sec': time_delta
            })
            
            current_event = next_event
            depth += 1
        
        path['end_time'] = path['events'][-1]['timestamp']
        path['duration_sec'] = (path['end_time'] - path['start_time']).total_seconds()
        
        return path
    
    def _entities_linked(self, event1: dict, event2: dict) -> bool:
        """Check if two events share an entity (user, host, IP, process)."""
        link_fields = ['user', 'host', 'src_ip', 'dst_ip', 'process_id', 'session_id']
        
        for field in link_fields:
            val1 = event1.get(field)
            val2 = event2.get(field)
            if val1 and val2 and val1 == val2:
                return True
        
        return False
    
    def _score_path(self, path: dict) -> dict:
        """
        Score attack path based on:
        - Length (longer = more sophisticated)
        - Event severity
        - Terminal event (exfil/encrypt = higher)
        - Time compression (fast = automated/sophisticated)
        """
        base_score = 0.0
        
        # Length score (more events = more sophisticated attack)
        length_score = min(len(path['events']) / 10, 0.3)
        base_score += length_score
        
        # Severity score (based on event types)
        severity_weights = {
            'data_exfiltrated': 0.25,
            'data_encrypted': 0.25,
            'domain_admin_access': 0.20,
            'cloud_admin_access': 0.20,
            'credential_phished': 0.15,
            'privilege_escalation': 0.15,
            'lateral_movement': 0.10,
        }
        
        for event in path['events']:
            event_type = event['event_type']
            base_score += severity_weights.get(event_type, 0.02)
        
        # Time compression (fast attacks are more dangerous)
        if path['duration_sec'] < 300:  # < 5 minutes
            base_score += 0.15
        elif path['duration_sec'] < 3600:  # < 1 hour
            base_score += 0.10
        
        # Cap at 1.0
        path['risk_score'] = min(base_score, 1.0)
        path['risk_label'] = self._score_to_label(path['risk_score'])
        
        return path
    
    def _score_to_label(self, score: float) -> str:
        if score >= 0.8:
            return 'CRITICAL'
        elif score >= 0.6:
            return 'HIGH'
        elif score >= 0.4:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _group_by_entity(self, events: list) -> dict:
        """Group events by primary entity (user or host)."""
        grouped = {}
        
        for event in events:
            entity = event.get('user') or event.get('host') or 'unknown'
            if entity not in grouped:
                grouped[entity] = []
            grouped[entity].append(event)
        
        return grouped
```

---

## Part 5: Implementation Roadmap (Revised)

### Phase 1: Attack Chain Foundation (Weeks 1-2)

| Task | Effort | Attack Chains Enabled |
|------|--------|----------------------|
| Windows lateral movement collector | 3 days | Lateral movement |
| DNS exfil detector | 2 days | Data exfiltration |
| Phishing chain correlator | 3 days | Phishing → execution |
| Persistence detector | 2 days | Registry/task persistence |

### Phase 2: Commercial EDR Integration (Weeks 3-4)

| Task | Effort | Why Critical |
|------|--------|-------------|
| CrowdStrike Falcon API | 5 days | Most common enterprise EDR |
| Microsoft Defender for Endpoint | 5 days | M365 customers |
| Proofpoint TAP | 3 days | Email threat intel |

### Phase 3: Attack Path Analysis (Weeks 5-6)

| Task | Effort | Capability |
|------|--------|-----------|
| Multi-hop path tracer | 4 days | Full attack chain reconstruction |
| Path scoring engine | 2 days | Prioritize real threats |
| Path visualization | 3 days | Analyst-friendly UI |

### Phase 4: Cloud & Forensics (Weeks 7-8)

| Task | Effort | Use Case |
|------|--------|----------|
| AWS CloudTrail + GuardDuty | 4 days | Cloud visibility |
| Velociraptor integration | 3 days | Artifact collection |
| KAPE timeline parser | 2 days | Forensic timeline |

---

## Part 6: Quick Wins (Do This Week)

### 1. Reduce novel_global false positives
Already covered in calibration doc—this is blocking trust in the platform.

### 2. Add DNS query logging
```python
# Enhance Zeek adapter to capture full DNS queries
# This enables DNS exfil detection immediately
```

### 3. Expand Sysmon event coverage
```python
# Current: Event 1, 7, 11, 13
# Add: Event 3 (network), Event 10 (process access), Event 17/18 (pipes)
# These are critical for lateral movement detection
```

### 4. Add email → endpoint correlation
```python
# When you see:
#   1. Email with URL/attachment to user X (O365 log)
#   2. Process execution by user X within 5 min (Sysmon)
# Auto-link and escalate
```

---

## Closing: You're Not a Noob

Kevin, this connector doc shows you understand:
- Security domain taxonomy
- API-first architecture benefits
- The correlation problem
- Competitive positioning

What you're missing is **attack-chain thinking**. Your current approach is:
- "How do I collect data from Source X?"

The winning approach is:
- "What data do I need to detect Attack Chain Y?"
- Then: "Which sources provide that data?"

The detectors I've included above flip the model—they're attack-first, not source-first.

**Your competitive advantage with HopGraph is real**, but only if you feed it the right telemetry to trace full attack paths. Right now you're collecting puzzle pieces; the attack path analyzer assembles the picture.

---

*Document prepared for JanuSec connector strategy*
