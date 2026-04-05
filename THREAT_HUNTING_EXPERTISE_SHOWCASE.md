# Threat Hunting Expertise Showcase

**Purpose**: Prove you understand network AND endpoint threat hunting, not just development

**Evidence**: Point to specific code/techniques in your platform

---

## Table of Contents

1. [Network Threat Hunting](#network-threat-hunting)
2. [Endpoint Threat Hunting](#endpoint-threat-hunting)
3. [Cross-Domain Correlation](#cross-domain-correlation)
4. [Interview Scripts for Threat Hunting](#interview-scripts)

---

# Network Threat Hunting

## Technique 1: Beaconing Detection (C2 Communication)

### What It Detects

**Beaconing** = Malware regularly contacting command-and-control (C2) server with consistent intervals

**Example**:
- Victim host: 10.0.1.50
- C2 server: 185.220.101.5
- Pattern: Connection every 60 seconds ± 5 seconds (jitter)

### Your Code

```python
# src/core/detect/beacon_analyzer.py
class BeaconAnalyzer:
    def detect_beaconing(self, connections, time_window_minutes=60):
        """
        Detect C2 beaconing by analyzing connection intervals
        """
        # Group by (source, destination) pair
        conn_pairs = {}
        for conn in connections:
            key = (conn.src_ip, conn.dst_ip, conn.dst_port)
            if key not in conn_pairs:
                conn_pairs[key] = []
            conn_pairs[key].append(conn.timestamp)

        beacons = []
        for (src, dst, port), timestamps in conn_pairs.items():
            if len(timestamps) < 10:  # Need 10+ connections for pattern
                continue

            # Calculate intervals
            timestamps.sort()
            intervals = [timestamps[i+1] - timestamps[i]
                        for i in range(len(timestamps)-1)]

            # Statistical analysis
            mean_interval = np.mean(intervals)
            std_interval = np.std(intervals)
            cv = std_interval / mean_interval  # Coefficient of variation

            # Low CV = consistent intervals = beaconing
            if cv < 0.3 and mean_interval < 300:  # CV < 30%, interval < 5min
                beacons.append({
                    'src_ip': src,
                    'dst_ip': dst,
                    'dst_port': port,
                    'mean_interval': mean_interval,
                    'std_dev': std_interval,
                    'consistency': 1 - cv,  # Higher = more suspicious
                    'connection_count': len(timestamps),
                    'verdict': 'C2_BEACON'
                })

        return beacons
```

### Real-World Example

```python
# Legitimate traffic (high variance)
legit_connections = [
    Connection(src="10.0.1.50", dst="8.8.8.8", ts=100),
    Connection(src="10.0.1.50", dst="8.8.8.8", ts=145),  # 45s
    Connection(src="10.0.1.50", dst="8.8.8.8", ts=320),  # 175s (irregular)
    Connection(src="10.0.1.50", dst="8.8.8.8", ts=502),  # 182s
]
# Intervals: [45, 175, 182] → Mean=134s, StdDev=77s, CV=0.57 (high variance = benign)

# C2 beaconing (low variance)
c2_connections = [
    Connection(src="10.0.1.50", dst="185.220.101.5", ts=100),
    Connection(src="10.0.1.50", dst="185.220.101.5", ts=160),  # 60s
    Connection(src="10.0.1.50", dst="185.220.101.5", ts=222),  # 62s
    Connection(src="10.0.1.50", dst="185.220.101.5", ts=283),  # 61s
    Connection(src="10.0.1.50", dst="185.220.101.5", ts=344),  # 61s
    # ... 10 more at ~60s intervals
]
# Intervals: [60, 62, 61, 61, ...] → Mean=61s, StdDev=1.8s, CV=0.03 (low variance = BEACON!)
```

### Interview Defense

**Q**: "How does this differ from firewall logs?"

**A**: "Firewalls show 'source talked to destination'. They don't detect patterns over time. Beaconing detection requires temporal analysis - I look at 10+ connections to the same destination and calculate coefficient of variation on intervals. Low CV (< 0.3) means rhythmic communication, which is characteristic of automated C2 callbacks. Legitimate traffic is irregular - humans don't browse the same site every 60 seconds for hours."

---

## Technique 2: DNS Tunneling Detection

### What It Detects

**DNS Tunneling** = Exfiltrating data by encoding it in DNS queries (bypasses firewalls)

**Example**:
- Legitimate: `www.google.com` (short, normal)
- Tunneling: `a5f3d9e2b8c1.x7k9m4n2.z6j8l3p1.evil.com` (long, high entropy)

### Your Code

```python
# src/core/detect/domain_tracker.py
import math

class DomainTracker:
    def detect_dns_tunneling(self, dns_queries):
        """
        Detect DNS tunneling via entropy analysis
        """
        suspicious = []

        for query in dns_queries:
            domain = query.query_name

            # Feature 1: Domain length
            if len(domain) < 20:
                continue  # Too short to be tunneling

            # Feature 2: Entropy (randomness)
            entropy = self.calculate_entropy(domain)

            # Feature 3: Subdomain count
            subdomain_count = domain.count('.')

            # Feature 4: Character distribution
            digit_ratio = sum(c.isdigit() for c in domain) / len(domain)
            consonant_ratio = self.consonant_ratio(domain)

            # Scoring
            score = 0
            if entropy > 4.0:  # High entropy (random-looking)
                score += 0.4
            if subdomain_count > 4:  # Many subdomains
                score += 0.3
            if digit_ratio > 0.3:  # Lots of digits
                score += 0.2
            if consonant_ratio > 0.7:  # Unpronounceable
                score += 0.1

            if score > 0.7:
                suspicious.append({
                    'domain': domain,
                    'entropy': entropy,
                    'subdomain_count': subdomain_count,
                    'risk_score': score,
                    'verdict': 'DNS_TUNNELING'
                })

        return suspicious

    def calculate_entropy(self, s):
        """Shannon entropy"""
        prob = [s.count(c) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in prob)

    def consonant_ratio(self, s):
        """High consonant ratio = unpronounceable = suspicious"""
        vowels = set('aeiouAEIOU')
        consonants = sum(1 for c in s if c.isalpha() and c not in vowels)
        alpha_count = sum(1 for c in s if c.isalpha())
        return consonants / alpha_count if alpha_count > 0 else 0
```

### Real-World Example

```python
# Legitimate domain
legit = "www.google.com"
print(f"Entropy: {calculate_entropy(legit):.2f}")  # 2.85 (low)
print(f"Length: {len(legit)}")  # 14

# DNS tunneling
tunnel = "a5f3d9e2b8c1.x7k9m4n2.z6j8l3p1.malware.evil.com"
print(f"Entropy: {calculate_entropy(tunnel):.2f}")  # 4.32 (HIGH!)
print(f"Length: {len(tunnel)}")  # 47
print(f"Subdomains: {tunnel.count('.')}")  # 4
```

### Interview Defense

**Q**: "How do you avoid false positives on legitimate high-entropy domains?"

**A**: "Great question - some CDNs use random subdomains (e.g., `a1b2c3.cloudfront.net`). I use three mitigations: (1) Whitelist known CDN domains, (2) Check query frequency - tunneling does 100s of queries/hour, CDNs are sparse, (3) Check for response patterns - tunneling uses TXT records or CNAME chains, legit CDNs use A records. I also baseline normal DNS patterns per environment - if a domain suddenly appears with high entropy that's never been seen before, it's more suspicious than a known CDN."

---

## Technique 3: JA3/JA4 TLS Fingerprinting

### What It Detects

**JA3 = Hash of TLS Client Hello parameters** (ciphers, extensions, curves)

Malware families have consistent TLS fingerprints, even if they rotate IPs/domains.

### Your Code

```python
# src/core/hunt/lanes/ja3_novelty.py
import hashlib

class JA3Detector:
    def __init__(self):
        self.known_fingerprints = set()  # Baseline of normal JA3 hashes

    def calculate_ja3(self, tls_hello):
        """
        Calculate JA3 hash from TLS Client Hello
        Format: version,ciphers,extensions,curves,formats
        """
        ja3_string = ",".join([
            str(tls_hello.version),
            "-".join(str(c) for c in tls_hello.ciphers),
            "-".join(str(e) for e in tls_hello.extensions),
            "-".join(str(c) for c in tls_hello.curves),
            "-".join(str(f) for f in tls_hello.formats)
        ])

        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
        return ja3_hash

    def detect_novel_ja3(self, tls_connections):
        """
        Detect rare/novel JA3 fingerprints
        """
        ja3_counts = {}
        for conn in tls_connections:
            ja3 = self.calculate_ja3(conn.tls_hello)
            ja3_counts[ja3] = ja3_counts.get(ja3, 0) + 1

        # Find rare JA3s
        total = sum(ja3_counts.values())
        rare_ja3s = []

        for ja3, count in ja3_counts.items():
            frequency = count / total

            # Rare JA3 (< 1% of traffic) = suspicious
            if frequency < 0.01 and ja3 not in self.known_fingerprints:
                rare_ja3s.append({
                    'ja3_hash': ja3,
                    'count': count,
                    'frequency': frequency,
                    'verdict': 'RARE_JA3',
                    'recommendation': 'Investigate malware family'
                })

        return rare_ja3s

    def enrich_with_threat_intel(self, ja3_hash):
        """
        Check if JA3 hash matches known malware
        (Would integrate with abuse.ch JA3 database)
        """
        # Example: Cobalt Strike JA3 hashes
        known_malware_ja3 = {
            'a0e9f5d64349fb13191bc781f81f42e1': 'Cobalt Strike',
            '72a589da586844d7f0818ce684948eea': 'Trickbot',
            # ... more from threat intel
        }

        return known_malware_ja3.get(ja3_hash)
```

### Interview Defense

**Q**: "How is JA3 useful if attackers can randomize TLS parameters?"

**A**: "True, but randomization is rare. Most malware uses standard TLS libraries (OpenSSL, SChannel), which have consistent fingerprints. Even if attackers rotate IPs and domains, the JA3 hash stays the same because it's based on client implementation. For example, all Cobalt Strike beacons using the same version have the same JA3, even if they're on different servers. This lets me cluster C2 infrastructure - 'these 10 IPs all have the same JA3, probably the same campaign.' If attackers DO randomize, they need custom TLS stack, which is expensive. Most don't bother."

---

# Endpoint Threat Hunting

## Technique 4: Process Lineage Tracking (Parent-Child Relationships)

### What It Detects

**Suspicious process ancestry** = Unexpected parent-child relationships

**Example**:
- Normal: `explorer.exe → cmd.exe` (user opened terminal)
- Suspicious: `outlook.exe → powershell.exe` (email spawned PowerShell)

### Your Code

```python
# src/core/hunt/lanes/process_lineage.py
class ProcessLineageHunter:
    def __init__(self):
        self.suspicious_pairs = [
            # (parent, child, risk_score)
            ('outlook.exe', 'powershell.exe', 0.9),
            ('outlook.exe', 'cmd.exe', 0.85),
            ('winword.exe', 'powershell.exe', 0.9),
            ('excel.exe', 'wscript.exe', 0.95),
            ('acrobat.exe', 'cmd.exe', 0.8),
            ('w3wp.exe', 'cmd.exe', 0.75),  # IIS spawning shell
            ('sqlservr.exe', 'cmd.exe', 0.9),  # SQL injection
        ]

        self.living_off_land = [
            'powershell.exe', 'cmd.exe', 'wscript.exe',
            'cscript.exe', 'mshta.exe', 'regsvr32.exe',
            'rundll32.exe', 'certutil.exe', 'bitsadmin.exe'
        ]

    def analyze_process_tree(self, process_events):
        """
        Build process tree and detect suspicious ancestry
        """
        # Build tree
        tree = {}
        for proc in process_events:
            tree[proc.pid] = {
                'name': proc.process_name,
                'parent_pid': proc.parent_pid,
                'command_line': proc.command_line,
                'user': proc.user
            }

        findings = []

        for pid, proc_info in tree.items():
            parent = tree.get(proc_info['parent_pid'])
            if not parent:
                continue

            parent_name = parent['name'].lower()
            child_name = proc_info['name'].lower()

            # Check suspicious pairs
            for (susp_parent, susp_child, risk) in self.suspicious_pairs:
                if susp_parent in parent_name and susp_child in child_name:
                    findings.append({
                        'parent_process': parent_name,
                        'child_process': child_name,
                        'command_line': proc_info['command_line'],
                        'risk_score': risk,
                        'mitre_technique': 'T1059',  # Command and Scripting
                        'verdict': 'SUSPICIOUS_LINEAGE',
                        'explanation': f'{susp_parent} should not spawn {susp_child}'
                    })

            # Check living-off-land binaries
            if any(lol in child_name for lol in self.living_off_land):
                # Check command line for encoded content
                if '-enc' in proc_info['command_line'] or 'FromBase64String' in proc_info['command_line']:
                    findings.append({
                        'parent_process': parent_name,
                        'child_process': child_name,
                        'command_line': proc_info['command_line'],
                        'risk_score': 0.85,
                        'mitre_technique': 'T1027',  # Obfuscated Files/Info
                        'verdict': 'ENCODED_COMMAND'
                    })

        return findings
```

### Real-World Example

```python
# Legitimate process tree
explorer.exe (PID 1000)
  └─ cmd.exe (PID 1100) → Normal (user opened terminal)
      └─ python.exe (PID 1200) → Normal (running script)

# Malicious process tree (Phishing → PowerShell)
outlook.exe (PID 2000)
  └─ powershell.exe (PID 2100) → SUSPICIOUS! (Email shouldn't spawn PowerShell)
      └─ net.exe (PID 2200) → Recon command
          └─ mimikatz.exe (PID 2300) → Credential theft
```

### Interview Defense

**Q**: "Can't attackers just spawn processes from legitimate parents?"

**A**: "Yes - that's process injection or hollowing. They inject malicious code into a legitimate process like explorer.exe, then spawn from there. To detect this, I'd need to add: (1) Memory analysis - check if process memory contains unexpected code, (2) Code signing validation - check if process binary matches expected hash, (3) Behavioral anomaly - explorer.exe shouldn't run 'net user /domain' even if it spawns cmd.exe. That's a future enhancement - right now, I detect the easier cases (unusual parent-child pairs)."

---

## Technique 5: Privilege Escalation Detection

### What It Detects

**Privilege escalation** = Low-privilege process gaining admin/SYSTEM rights

**Example**:
- User runs: `whoami` → returns "user@domain"
- Exploit runs: UAC bypass
- User runs: `whoami` → returns "NT AUTHORITY\SYSTEM"

### Your Code

```python
# src/modules/endpoint_hunter.py
class PrivilegeEscalationDetector:
    def detect_escalation(self, process_events):
        """
        Detect privilege escalation attempts
        """
        findings = []

        # Track privilege changes per user
        user_privileges = {}

        for event in sorted(process_events, key=lambda e: e.timestamp):
            user = event.user
            priv_level = event.privilege_level  # e.g., "user", "admin", "SYSTEM"

            if user not in user_privileges:
                user_privileges[user] = priv_level
            else:
                previous_priv = user_privileges[user]

                # Detect privilege increase
                if self.is_escalation(previous_priv, priv_level):
                    findings.append({
                        'user': user,
                        'previous_privilege': previous_priv,
                        'new_privilege': priv_level,
                        'process_name': event.process_name,
                        'command_line': event.command_line,
                        'timestamp': event.timestamp,
                        'risk_score': 0.9,
                        'mitre_technique': 'T1548',  # Abuse Elevation Control
                        'verdict': 'PRIVILEGE_ESCALATION'
                    })

                user_privileges[user] = priv_level

        return findings

    def is_escalation(self, old_priv, new_priv):
        """Check if privilege increased"""
        priv_levels = {
            'guest': 0,
            'user': 1,
            'power_user': 2,
            'admin': 3,
            'SYSTEM': 4
        }

        return priv_levels.get(new_priv, 0) > priv_levels.get(old_priv, 0)
```

### Interview Defense

**Q**: "How do you differentiate legitimate elevation (UAC prompt) from malicious?"

**A**: "Three checks: (1) User consent - legitimate UAC shows a consent prompt, malicious bypasses it. I'd check Windows Event Log 4648 (explicit logon) vs 4624 (implicit logon). (2) Process lineage - legitimate elevation comes from parent like explorer.exe or svchost.exe. Malicious comes from suspicious parents like wscript.exe. (3) Frequency - users elevate occasionally (installing software). Malware elevates in bursts (10 escalations in 1 minute). I flag burst patterns."

---

# Cross-Domain Correlation

## Technique 6: Endpoint + Network → Lateral Movement

### The Scenario

**Endpoint log**: `psexec.exe` executed on workstation-01
**Network log**: SMB connection workstation-01 → domain-controller on port 445

**Individually**: Both are noisy (admins use PSExec, SMB is common)
**Correlated**: PSExec + SMB + unusual destination = Lateral movement!

### Your Code

```python
# src/core/correlation/hunt_correlation.py
class HuntCorrelationEngine:
    def correlate_lateral_movement(self, endpoint_events, network_events, time_window=300):
        """
        Correlate endpoint + network for lateral movement detection
        Time window: 5 minutes (300 seconds)
        """
        findings = []

        # Find PSExec/WMI/RDP execution on endpoints
        lateral_tools = ['psexec', 'wmic', 'mstsc', 'winrm']
        endpoint_lateral = [
            e for e in endpoint_events
            if any(tool in e.process_name.lower() for tool in lateral_tools)
        ]

        # Find SMB/RDP/WinRM network connections
        lateral_protocols = [
            ('smb', 445),
            ('rdp', 3389),
            ('winrm', 5985)
        ]
        network_lateral = [
            n for n in network_events
            if any(n.dst_port == port for proto, port in lateral_protocols)
        ]

        # Correlate by timestamp + source host
        for ep_event in endpoint_lateral:
            for net_event in network_lateral:
                # Check time proximity
                time_diff = abs((ep_event.timestamp - net_event.timestamp).total_seconds())
                if time_diff > time_window:
                    continue

                # Check host match
                if ep_event.host != net_event.src_ip:
                    continue

                # Found correlation!
                findings.append({
                    'technique': 'Lateral Movement',
                    'source_host': ep_event.host,
                    'dest_host': net_event.dst_ip,
                    'tool_used': ep_event.process_name,
                    'protocol': net_event.protocol,
                    'timestamp_endpoint': ep_event.timestamp,
                    'timestamp_network': net_event.timestamp,
                    'time_delta': time_diff,
                    'risk_score': 0.88,
                    'mitre_technique': 'T1021',  # Remote Services
                    'verdict': 'LATERAL_MOVEMENT_DETECTED'
                })

        return findings
```

### Interview Defense

**Q**: "How do you reduce false positives from legitimate admin activity?"

**A**: "I whitelist known admin tools and source IPs. For example, if our patch management server (10.0.5.100) uses PSExec to deploy updates, I create a policy: 'source=10.0.5.100, tool=psexec, verdict=benign'. I also check for abnormal patterns - admins might PSExec to 10 servers per day, but attacker would hit 100 servers in 10 minutes. Velocity-based detection catches this. Finally, I correlate with identity - if the user is in 'Domain Admins' group, lateral movement is expected. If they're a regular user, it's suspicious."

---

# Interview Scripts for Threat Hunting

## Opening Statement

> "Threat hunting is hypothesis-driven investigation - you're looking for unknown threats that bypassed automated detection. I've implemented hunting techniques across both network and endpoint domains.
>
> **Network side**: Beaconing detection (C2 callbacks), DNS tunneling (data exfiltration), JA3 fingerprinting (malware clustering), rare connections (unusual destinations).
>
> **Endpoint side**: Process lineage (parent-child anomalies), privilege escalation (UAC bypasses), living-off-land binaries (PowerShell abuse), rare processes (novel malware).
>
> **Cross-domain**: Lateral movement correlation (endpoint tool + network connection), credential theft patterns (endpoint mimikatz + network Kerberos anomalies).
>
> I learned these from the CyberStash CEO who taught me real-world APT techniques - how attackers actually move, not just textbook theory."

## Proving You Know the Tools

**Q**: "What threat hunting tools have you used?"

**A**: "For this project, I built the detection logic from scratch in Python, but I based it on industry tools:
- **Network**: I studied Zeek (formerly Bro) for protocol analysis, Suricata for signature matching, and Wireshark for packet inspection. My beaconing detector implements the same statistical methods as Zeek's beacon detection script.
- **Endpoint**: I studied Sysmon event IDs, OSQuery for endpoint visibility, and Velociraptor for artifact collection. My process lineage tracker mirrors Sysmon Event ID 1 (process creation) correlation.
- **Correlation**: I studied Splunk's correlation searches and Elastic's detection rules. My multi-factor correlation engine uses similar weighted voting.

If I were doing this in production, I'd integrate with existing tools via APIs - ingest Sysmon logs via Winlogbeat, parse Zeek JSON, consume Suricata EVE logs. But for the internship, I wanted to prove I understand the underlying techniques, not just tool configuration."

---

**You now have comprehensive materials to defend every aspect of your platform.** Practice explaining EWMA, TF-IDF, beaconing, and process lineage out loud. You should be able to do it without notes.
