# 🔌 JanuSec Platform: Connector Coverage & Integration Analysis

**Generated:** 2025-01-20
**Version:** 1.0
**Status:** Production Assessment

---

## 📊 Executive Summary

The JanuSec platform currently has **partial coverage** across 8 security domains with a focus on **API-first ingestion** and **webhook receivers**. This document analyzes what exists, what's missing, and how it compares to enterprise vendors like Splunk, Elastic, Chronicle, and CrowdStrike.

### Coverage Score by Domain:
| Domain | Coverage | Score | Key Gaps |
|--------|----------|-------|----------|
| **Network** | Zeek, PCAP | 70% | Missing Suricata, Bro logs, NetFlow |
| **Endpoint** | EVTX, Sysmon, eBPF/Falco | 80% | Missing Tetragon, KAPE forensics, CrowdStrike native |
| **Identity (IAM)** | Okta, Azure AD, AWS IAM | 85% | Missing JumpCloud, Duo, PingID |
| **Cloud** | AWS, GCP, Azure | 75% | Missing CloudTrail parser, GCP Audit Logs |
| **Email** | O365, Gmail | 60% | Missing Proofpoint, Mimecast webhooks |
| **Remote Access** | VPN, RDP, Bastion | 90% | Coverage is strong |
| **Data Access** | Generic DLP | 50% | Missing Varonis, BigID connectors |
| **Application** | Generic app events | 40% | Missing OWASP ZAP, Burp, WAF logs |

**Overall Platform Coverage: 68%** ⚠️

---

## 🎯 8 Security Domains: What We Have vs. What's Missing

### 1️⃣ **Network Domain**

#### ✅ **What Exists:**
- **Zeek adapter** (src/live/zeek_adapter.py:1-150)
  - Parses: `conn.log`, `dns.log`, `http.log`, `ssl.log`
  - Extracts JA3/JA3S fingerprints
  - Maps to normalized event schema
  - **Webhook:** `POST /api/v1/network/ingest`

- **PCAP parser** (src/parsers/pcap_parser.py)
  - Extracts network flows from packet captures
  - Protocol detection

#### ❌ **What's Missing:**
| Tool/Format | Use Case | Why It Matters | Implementation Effort |
|-------------|----------|----------------|----------------------|
| **Suricata EVE JSON** | IDS/IPS alerts | NSM standard, threat detection | Medium (2-3 days) |
| **NetFlow/IPFIX** | Network telemetry | Baseline traffic patterns | Medium (3-4 days) |
| **PAN-OS logs** | Firewall events | Enterprise firewall visibility | Low (1-2 days) |
| **Cisco ASA/Firepower** | Firewall events | Cisco shop visibility | Low (1-2 days) |

#### 📍 **How to Connect:**
```bash
# Zeek ingestion (existing)
POST /api/v1/network/ingest
{
  "ts": 1705776000.123,
  "orig_host": "192.168.1.100",
  "resp_host": "8.8.8.8",
  "proto": "tcp",
  "dest_port": 443,
  "ja3": "abc123..."
}
```

**Add Suricata connector:**
```python
# Recommend: src/parsers/suricata_parser.py
def parse_suricata_eve(line: str) -> dict:
    """Parse Suricata EVE JSON format"""
    obj = json.loads(line)
    return {
        'ts': obj['timestamp'],
        'src_ip': obj['src_ip'],
        'dst_ip': obj['dest_ip'],
        'alert': obj.get('alert', {}).get('signature'),
        'severity': obj.get('alert', {}).get('severity'),
        'category': obj.get('alert', {}).get('category')
    }
```

---

### 2️⃣ **Endpoint Domain**

#### ✅ **What Exists:**
- **Sysmon via EVTX parser** (src/parsers/evtx_parser.py:28)
  - Event IDs: 1 (ProcessCreate), 7 (ImageLoad), 11 (FileCreate), 13 (RegistrySet)
  - Extracts process exec and persistence events

- **eBPF/Falco webhook** (src/api/ebpf_endpoints.py:73-143)
  - Receives container runtime events
  - Maps Falco priorities to severity
  - In-memory ring buffer (1000 events, 24h TTL)
  - **Webhook:** `POST /api/v1/events/ebpf_ingest`

- **Windows Security Events** (src/parsers/evtx_parser.py:28)
  - 4688 (Process Creation), 7045 (Service Install), 4697 (Service Install)

#### ⚠️ **Partial Support:**
- **Syscall tracing** (references in src/core/event_pipeline/stages/ebpf_analysis.py)
  - Mentioned in code but NOT fully integrated
  - Missing: syscall normalization, MITRE mapping

#### ❌ **What's Missing:**
| Tool/Format | Use Case | Why It Matters | Implementation Effort |
|-------------|----------|----------------|----------------------|
| **Tetragon** | eBPF observability | Richer syscall context than Falco | Medium (3-5 days) |
| **KAPE** | Forensic artifacts | IR/hunt artifact collection | High (1-2 weeks) |
| **RegRipper/RegSeek** | Registry forensics | Hunt persistence mechanisms | Medium (1 week) |
| **CrowdStrike Falcon API** | EDR native | Real-time endpoint telemetry | High (2 weeks) |
| **Velociraptor** | DFIR collector | Artifact hunting at scale | Medium (1 week) |
| **OSQuery** | Endpoint queries | Live system interrogation | Low (2-3 days) |

#### 📍 **How to Connect:**

**Existing Falco webhook (WORKS NOW):**
```bash
POST /api/v1/events/ebpf_ingest
{
  "output": "Shell spawned in container",
  "priority": "Warning",
  "rule": "Terminal shell in container",
  "time": "2025-10-28T10:30:45.123456Z",
  "output_fields": {
    "container.id": "abc123",
    "proc.cmdline": "/bin/bash",
    "user.name": "www-data",
    "evt.type": "execve"
  }
}
```

**Add Tetragon connector (RECOMMENDED):**
```python
# src/collectors/tetragon_collector.py
class TetragonCollector:
    """Collect Tetragon eBPF events via gRPC streaming"""

    async def stream_events(self):
        from tetragon import Observer  # Tetragon Go gRPC binding
        async for event in Observer.GetEvents():
            yield {
                'source': 'tetragon',
                'event_type': event.process_exec.process.binary,
                'pid': event.process_exec.process.pid,
                'args': event.process_exec.process.arguments,
                'parent_pid': event.process_exec.parent.pid,
                'syscalls': [sc.name for sc in event.syscalls],
                'capabilities': event.process_exec.process.cap
            }
```

**Add KAPE connector (NEEDED FOR FORENSICS):**
```python
# src/parsers/kape_parser.py
def parse_kape_timeline(csv_path: str) -> list[dict]:
    """Parse KAPE timeline CSV exports"""
    import csv
    events = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append({
                'timestamp': row['SourceModified'],
                'path': row['SourceFile'],
                'description': row['Description'],
                'artifact_type': row['SourceType']
            })
    return events
```

---

### 3️⃣ **Identity (IAM) Domain**

#### ✅ **What Exists:**
- **Okta collector** (src/collectors/iam_okta_adapter.py:23-100)
  - Uses Okta REST API `/api/v1/logs`
  - Cursor-based pagination (stored in PostgreSQL)
  - Retry logic with tenacity
  - **Detectors:** iam_okta.py (privileged role changes, MFA bypass)

- **Azure AD collector** (src/collectors/iam_aad_adapter.py)
  - MSAL-based auth
  - Sign-in logs and audit logs

- **AWS IAM detection** (src/core/detectors/iam_aws.py)
  - Policy changes, privilege escalation patterns

- **GCP IAM detection** (src/core/detectors/iam_gcp.py)
  - Service account abuse patterns

- **Webhook ingestion** (src/api/routes/identity.py:24)
  - `POST /api/v1/identity/ingest`
  - HopGraph integration for IAM path analysis

#### ❌ **What's Missing:**
| Tool/Format | Use Case | Why It Matters | Implementation Effort |
|-------------|----------|----------------|----------------------|
| **Duo Security** | MFA logs | MFA bypass detection | Low (1-2 days) |
| **JumpCloud** | Directory-as-a-Service | SMB identity source | Low (2-3 days) |
| **PingIdentity/Ping Federate** | SAML/SSO | Enterprise SSO visibility | Medium (3-4 days) |
| **Auth0** | Identity platform | SaaS identity logs | Low (1-2 days) |
| **OneLogin** | IAM platform | SSO event stream | Low (1-2 days) |

#### 📍 **How to Connect:**

**Existing Okta (WORKS NOW):**
```bash
# Set env vars
export OKTA_API_TOKEN="your_token"
export OKTA_ORG_URL="https://dev-123456.okta.com"

# Run collector (background)
python -m src.collectors.iam_okta_adapter
```

**Add Duo Security webhook (RECOMMENDED):**
```python
# src/api/routes/identity.py (add endpoint)
@router.post('/duo_webhook')
async def ingest_duo_webhook(request: Request):
    """Receive Duo MFA events via webhook"""
    event = await request.json()
    return {
        'user': event['user']['name'],
        'event_type': event['eventtype'],
        'mfa_result': event['result'],
        'device': event.get('auth_device', {}).get('name'),
        'ts': event['timestamp']
    }
```

---

### 4️⃣ **Cloud Domain**

#### ✅ **What Exists:**
- **AWS Config adapter** (src/collectors/cloud_aws_config_adapter.py)
  - Collects resource inventory

- **GCP Asset adapter** (src/collectors/cloud_gcp_asset_adapter.py)
  - GCP resource discovery

- **Cloud graph endpoint** (src/api/routes/cloud.py:1-100)
  - `POST /api/v1/cloud/ingest`
  - IAM path analysis (who can reach what)

- **Detectors:**
  - Azure ARM abuse (src/core/detectors/iam_azure_arm.py)
  - AWS privilege escalation (src/core/detectors/iam_aws.py)
  - GCP org policy violations (src/core/detectors/iam_gcp_org.py)

#### ❌ **What's Missing:**
| Tool/Format | Use Case | Why It Matters | Implementation Effort |
|-------------|----------|----------------|----------------------|
| **AWS CloudTrail** | API audit logs | Attack attribution | Medium (3-4 days) |
| **GCP Audit Logs** | Admin activity | GCP attack detection | Medium (3-4 days) |
| **Azure Activity Logs** | Control plane changes | Azure breach detection | Medium (3-4 days) |
| **Kubernetes Audit** | K8s API calls | Container orchestration abuse | High (1 week) |
| **Terraform State** | IaC drift | Unauthorized infra changes | Medium (3-5 days) |

#### 📍 **How to Connect:**

**Existing generic cloud ingest (WORKS NOW):**
```bash
POST /api/v1/cloud/ingest
{
  "resource_id": "arn:aws:s3:::mybucket",
  "principals": ["arn:aws:iam::123456:user/bob"],
  "destinations": ["0.0.0.0/0"],
  "public": true
}
```

**Add CloudTrail connector (CRITICAL FOR AWS):**
```python
# src/collectors/aws_cloudtrail_collector.py
import boto3

class CloudTrailCollector:
    def __init__(self):
        self.client = boto3.client('cloudtrail')

    def fetch_events(self, since_ts: float):
        events = []
        paginator = self.client.get_paginator('lookup_events')
        for page in paginator.paginate(
            StartTime=datetime.fromtimestamp(since_ts),
            LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': 'AssumeRole'}]
        ):
            for event in page['Events']:
                events.append({
                    'event_name': event['EventName'],
                    'user': event.get('Username'),
                    'source_ip': event.get('SourceIPAddress'),
                    'event_time': event['EventTime'].timestamp(),
                    'resources': event.get('Resources', [])
                })
        return events
```

---

### 5️⃣ **Email Domain**

#### ✅ **What Exists:**
- **O365 collector** (src/collectors/email_o365_adapter.py:37-100)
  - MS Graph API `/users/{id}/messages`
  - MSAL authentication
  - Fetches received emails since timestamp

- **Gmail collector** (src/collectors/email_gmail_adapter.py - exists but not reviewed in detail)

- **Email webhook** (src/api/routes/email.py:24-100)
  - `POST /api/v1/email/ingest`
  - SPF/DKIM/DMARC parsing
  - Homograph brand detection (e.g., "micr0soft.com")
  - HopGraph email entity linking

#### ❌ **What's Missing:**
| Tool/Format | Use Case | Why It Matters | Implementation Effort |
|-------------|----------|----------------|----------------------|
| **Proofpoint TAP** | Email security gateway | Phishing detection logs | Medium (3-5 days) |
| **Mimecast** | Email security | Threat intel enrichment | Medium (3-5 days) |
| **Microsoft Defender for O365** | Advanced email threat | ATP logs and verdicts | High (1 week) |
| **Barracuda ESG** | Email gateway | Email-borne threats | Low (2-3 days) |
| **IronPort/ESA** | Cisco email security | Enterprise email logs | Low (2-3 days) |

#### 📍 **How to Connect:**

**Existing O365 (WORKS NOW):**
```bash
# Set env vars
export O365_TENANT="your-tenant-id"
export O365_CLIENT_ID="app-client-id"
export O365_CLIENT_SECRET="secret"
export O365_USER_ID="user@domain.com"

# Run collector
python -m src.collectors.email_o365_adapter
```

**Add Proofpoint TAP webhook (HIGH VALUE):**
```python
# src/api/routes/email.py (add endpoint)
@router.post('/proofpoint_tap')
async def ingest_proofpoint_tap(request: Request):
    """Receive Proofpoint TAP threat alerts"""
    event = await request.json()
    # Proofpoint sends "messagesBlocked" and "messagesDelivered"
    for msg in event.get('messagesBlocked', []):
        yield {
            'from': msg['senderIP'],
            'to': msg['recipient'],
            'subject': msg['subject'],
            'threat_type': msg['threatsInfoMap'][0]['threat'],
            'threat_url': msg['threatsInfoMap'][0]['threatUrl'],
            'verdict': 'blocked',
            'ts': msg['messageTime']
        }
```

---

### 6️⃣ **Remote Access Domain**

#### ✅ **What Exists (STRONG COVERAGE):**
- **Generic remote access** (src/api/routes/remote_access.py:24-150)
  - `POST /api/v1/remote_access/ingest`
  - VPN, RDP, Bastion variants
  - **Detections:**
    - Impossible travel (geo velocity tracker)
    - MFA usage tracking
    - Geo-fencing (ORG_ALLOWED_COUNTRIES)
    - User baseline (first-seen country change)

- **HopGraph integration** for lateral movement tracking

#### ❌ **What's Missing:**
| Tool/Format | Use Case | Why It Matters | Implementation Effort |
|-------------|----------|----------------|----------------------|
| **Cisco AnyConnect** | VPN logs | Enterprise VPN visibility | Low (1-2 days) |
| **Palo Alto GlobalProtect** | VPN logs | VPN session metadata | Low (1-2 days) |
| **BeyondTrust/CyberArk** | PAM logs | Privileged session recording | Medium (3-5 days) |

#### 📍 **How to Connect:**

**Existing VPN/RDP (WORKS NOW):**
```bash
POST /api/v1/remote_access/vpn
{
  "src_ip": "203.0.113.45",
  "user": "alice",
  "dest_host": "prod-db-01",
  "protocol": "vpn",
  "geo_lat": 37.7749,
  "geo_lon": -122.4194,
  "mfa_used": true
}
```

**Add CyberArk PAM (RECOMMENDED):**
```python
# src/collectors/cyberark_collector.py
class CyberArkCollector:
    def fetch_sessions(self, since_ts: float):
        # CyberArk REST API /WebServices/PIMServices.svc/Sessions
        sessions = []
        resp = requests.get(
            f"{self.base_url}/WebServices/PIMServices.svc/Sessions",
            headers={'Authorization': f'Bearer {self.token}'}
        )
        for session in resp.json():
            sessions.append({
                'user': session['User'],
                'target_host': session['RemoteMachine'],
                'session_id': session['SessionID'],
                'start_time': session['Start'],
                'privileged': True
            })
        return sessions
```

---

### 7️⃣ **Data Access Domain**

#### ⚠️ **What Exists (WEAK COVERAGE):**
- **Generic data access endpoint** (src/api/routes/data.py:1-100)
  - `POST /api/v1/data/ingest`
  - Basic schema: user, resource, action, classification

#### ❌ **What's Missing (CRITICAL GAPS):**
| Tool/Format | Use Case | Why It Matters | Implementation Effort |
|-------------|----------|----------------|----------------------|
| **Varonis DatAlert** | File activity monitoring | Insider threat detection | High (1-2 weeks) |
| **BigID** | Data discovery/classification | PII/PHI exposure | High (1-2 weeks) |
| **Microsoft Purview** | Data governance | O365 data activity | Medium (3-5 days) |
| **Netwrix Auditor** | File access auditing | Compliance reporting | Medium (1 week) |
| **Symantec DLP** | Data loss prevention | Exfiltration detection | High (2 weeks) |

#### 📍 **How to Connect:**

**Existing generic (LIMITED):**
```bash
POST /api/v1/data/ingest
{
  "user": "bob",
  "resource": "s3://sensitive-bucket/pii.csv",
  "action": "read",
  "classification": "PII"
}
```

**Add Varonis webhook (HIGH IMPACT):**
```python
# src/api/routes/data.py (add endpoint)
@router.post('/varonis_webhook')
async def ingest_varonis_alert(request: Request):
    """Receive Varonis DatAlert events"""
    event = await request.json()
    return {
        'user': event['User'],
        'resource': event['ResourcePath'],
        'action': event['Operation'],  # Read, Write, Delete
        'anomaly_score': event.get('ThreatScore', 0),
        'baseline_deviation': event.get('IsAnomaly', False),
        'ts': event['EventTime']
    }
```

---

### 8️⃣ **Application Domain**

#### ⚠️ **What Exists (WEAK COVERAGE):**
- **Generic app events** (src/api/routes/app_events.py)
  - Basic application event ingestion

- **WAF parser** (src/parsers/waf_parser.py)
  - Parses WAF logs (format unspecified)

#### ❌ **What's Missing (MAJOR GAPS):**
| Tool/Format | Use Case | Why It Matters | Implementation Effort |
|-------------|----------|----------------|----------------------|
| **OWASP ZAP** | Dynamic app scanning | Vuln discovery | Low (2-3 days) |
| **Burp Suite Enterprise** | Web app scanning | API security testing | Low (2-3 days) |
| **Cloudflare WAF** | Web application firewall | Attack surface visibility | Low (1-2 days) |
| **AWS WAF logs** | Cloud WAF | AWS-hosted app protection | Low (2-3 days) |
| **Imperva WAF** | Enterprise WAF | Layer 7 attack detection | Medium (3-5 days) |
| **NGINX access logs** | Web server | Application access patterns | Low (1 day) |

#### 📍 **How to Connect:**

**Add Cloudflare WAF (RECOMMENDED):**
```python
# src/collectors/cloudflare_waf_collector.py
import requests

class CloudflareWAFCollector:
    def fetch_events(self, since_ts: float):
        # Cloudflare Logpush API
        endpoint = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/events"
        events = []
        resp = requests.get(
            endpoint,
            headers={'Authorization': f'Bearer {self.api_key}'},
            params={'since': since_ts, 'action': 'block'}
        )
        for evt in resp.json()['result']:
            events.append({
                'source_ip': evt['clientIP'],
                'uri': evt['clientRequestURI'],
                'rule_id': evt['ruleId'],
                'action': evt['action'],  # block, challenge, log
                'user_agent': evt['clientRequestHTTPHeaders'].get('User-Agent')
            })
        return events
```

---

## 🔧 Syscall & eBPF Coverage Deep Dive

### **What Works Today:**

#### Falco eBPF (src/api/ebpf_endpoints.py:73-143)
```python
@router.post("/ebpf_ingest")
async def ingest_ebpf_event(request: Request):
    """Accept Falco webhook JSON"""
    falco_event = await request.json()
    normalized = {
        'event_type': 'container_runtime',
        'source': 'falco_ebpf',
        'severity': _map_falco_priority(falco_event.get('priority')),
        'container_id': of.get('container.id'),
        'syscall': of.get('evt.type'),  # execve, open, connect
        'command': of.get('proc.cmdline')
    }
```

**Falco Rules Detected:**
- Terminal shell in container
- Sensitive file access
- Unexpected network connection from container

### **What's Missing:**

#### 1. **Tetragon** (Cilium eBPF - RECOMMENDED)
**Why:** More granular syscall tracing + kernel enforcement hooks
```python
# NEEDS: src/collectors/tetragon_collector.py
from tetragon import Observer

async def stream_tetragon():
    async for event in Observer.GetEvents():
        if event.HasField('process_exec'):
            yield {
                'binary': event.process_exec.process.binary,
                'args': event.process_exec.process.arguments,
                'capabilities': event.process_exec.process.cap,
                'namespaces': event.process_exec.process.ns,
                'syscalls_before': event.process_exec.syscalls
            }
```

#### 2. **Sysdig Inspect** (Commercial eBPF)
**Why:** Richer container context + capture files
```bash
# Would need connector to Sysdig API
# Provides: network topology, service mesh visibility
```

#### 3. **BCC/bpftrace scripts** (Custom probes)
**Why:** Ad-hoc hunting queries
```python
# NEEDS: Executor to run bpftrace scripts on-demand
# Example: Detect execve("/bin/bash") from PHP process
```

---

## 🏢 Vendor Comparison: How JanuSec Stacks Up

| Feature/Capability | **JanuSec** | **Splunk** | **Elastic SIEM** | **Chronicle** | **CrowdStrike** |
|--------------------|-------------|------------|------------------|---------------|-----------------|
| **Network (Zeek)** | ✅ Native | ✅ TA-Zeek | ✅ Filebeat | ✅ Parser | ❌ Limited |
| **Endpoint (Sysmon)** | ✅ EVTX parser | ✅ TA-Microsoft-Sysmon | ✅ Winlogbeat | ✅ UDM | ❌ Uses Falcon EDR |
| **eBPF/Falco** | ✅ Webhook | ⚠️ Custom TA | ✅ Elastic Agent | ❌ No | ❌ No |
| **Okta** | ✅ Native collector | ✅ Okta TA | ✅ Filebeat | ✅ Native | ⚠️ Via API |
| **AWS CloudTrail** | ❌ Missing | ✅ AWS TA | ✅ AWS module | ✅ Native | ✅ Cloud Security |
| **O365 Email** | ✅ Graph API | ✅ O365 TA | ✅ O365 module | ✅ Native | ⚠️ Limited |
| **KAPE Forensics** | ❌ Missing | ⚠️ Manual | ⚠️ Manual | ❌ No | ✅ RTR |
| **HopGraph Correlation** | ✅ **Native** | ❌ SPL queries | ❌ EQL queries | ⚠️ Entity graph | ❌ Threat Graph |
| **API-First Ingest** | ✅ **Native** | ⚠️ HEC only | ⚠️ Beats only | ✅ API | ✅ API |
| **Multi-Tenant** | ✅ Built-in | 💰 Enterprise | 💰 Enterprise | ✅ Native | ✅ Native |
| **Cost Model** | 🆓 **Open Source** | 💰💰💰 Per GB | 💰💰 Per GB | 💰💰💰 Per GB | 💰💰💰 Per endpoint |

### **JanuSec Unique Advantages:**
1. **HopGraph native correlation** - Not bolt-on like competitors
2. **API-first architecture** - Easy SaaS/webhook integration
3. **Multi-tenant from day 1** - Not an enterprise add-on
4. **Cost:** Free vs. $100K+/year for Splunk Enterprise
5. **eBPF-native** - Falco/Tetragon first-class citizens

### **Where JanuSec Lags:**
1. **No commercial EDR connector** (CrowdStrike, SentinelOne, Carbon Black)
2. **Missing forensic artifact parsers** (KAPE, Velociraptor)
3. **No SOAR playbook library** (vs. Splunk SOAR, Palo Alto XSOAR)
4. **Limited cloud-native log parsers** (CloudTrail, GCP Audit)

---

## 🛠️ How to Ensure Correlation Across Domains

### **Current Correlation Mechanism:**

#### HopGraph (src/graph/hopgraph.py)
- **Nodes:** Users, hosts, IPs, processes, files, cloud resources
- **Edges:** Temporal relationships (A → B within time window)
- **Scoring:** Path risk = Σ(edge anomalies) × EWMA weights

#### Example Multi-Domain Attack Path:
```python
# 1. Phishing email (Email domain)
POST /api/v1/email/ingest
{
  "from": "attacker@evil.com",
  "to": "victim@corp.com",
  "subject": "Invoice",
  "threat_url": "http://evil.com/payload.exe"
}

# 2. User clicks link → Process execution (Endpoint domain)
POST /api/v1/events/ebpf_ingest
{
  "rule": "Suspicious process spawn",
  "proc.cmdline": "powershell -enc <base64>",
  "user.name": "victim"
}

# 3. Lateral movement via RDP (Remote Access domain)
POST /api/v1/remote_access/rdp
{
  "src_ip": "10.0.1.100",  # victim's workstation
  "user": "victim",
  "dest_host": "DC-01",    # domain controller
  "mfa_used": false
}

# 4. Cloud IAM privilege escalation (Cloud domain)
POST /api/v1/cloud/ingest
{
  "event_name": "AssumeRole",
  "user": "victim",
  "resource": "arn:aws:iam::123:role/Admin"
}

# 5. Data exfiltration (Network domain)
POST /api/v1/network/ingest
{
  "orig_host": "DC-01",
  "dest_ip": "185.220.101.45",  # Tor exit node
  "bytes_out": 524288000,  # 500 MB
  "proto": "https"
}
```

**HopGraph Output:**
```
Attack Path Score: 8.7/10
victim@corp.com → powershell.exe → DC-01 → arn:aws:iam::123:role/Admin → 185.220.101.45
Factors:
  - email_suspicious_link (0.8)
  - process_encoded_command (0.9)
  - remote_access_mfa_missing (0.7)
  - cloud_privilege_escalation (0.95)
  - network_tor_egress (0.85)
  - data_exfil_volume_spike (0.9)
```

### **How to Guarantee Correlation:**

#### 1. **Unified Entity Keys**
Ensure all connectors emit consistent identifiers:
```python
# RULE: Use these canonical fields
{
  "user": "alice",           # NOT "username", "account", "principal"
  "host": "web-01",          # NOT "hostname", "computer", "asset"
  "ip": "192.168.1.10",      # NOT "src_ip", "client_ip", "address"
  "process": "chrome.exe",   # NOT "proc_name", "image", "binary"
  "file_hash": "sha256:abc", # NOT "hash", "sha256", "digest"
}
```

**Normalization happens here:**
- src/core/normalize.py (email, domain)
- src/api/routes/*.py (each ingest endpoint normalizes to canonical schema)

#### 2. **Temporal Correlation Window**
```python
# src/core/event_pipeline/pipeline.py
CORRELATION_WINDOW_SEC = 3600  # 1 hour
# Events within 1 hour of each other are eligible for graph linking
```

#### 3. **Session ID Tracking** (for multi-event flows)
```python
# Example: Track a full RDP session
POST /api/v1/remote_access/rdp
{
  "session_id": "rdp_abc123",  # Links all events in this session
  "user": "alice",
  "dest_host": "db-01",
  "action": "login"
}

POST /api/v1/data/ingest
{
  "session_id": "rdp_abc123",  # Same session
  "user": "alice",
  "resource": "/var/db/customers.sql",
  "action": "read"
}
# HopGraph will link these via session_id
```

---

## 🚀 Recommended Implementation Roadmap

### **Phase 1: Critical Gaps (1-2 weeks)**
1. ✅ **AWS CloudTrail connector** (src/collectors/aws_cloudtrail_collector.py)
2. ✅ **Tetragon eBPF collector** (src/collectors/tetragon_collector.py)
3. ✅ **Proofpoint TAP webhook** (src/api/routes/email.py)
4. ✅ **Varonis DatAlert webhook** (src/api/routes/data.py)

### **Phase 2: Forensic Capability (2-3 weeks)**
1. ✅ **KAPE timeline parser** (src/parsers/kape_parser.py)
2. ✅ **Velociraptor artifact collector** (src/collectors/velociraptor_collector.py)
3. ✅ **OSQuery integration** (src/collectors/osquery_collector.py)

### **Phase 3: Commercial EDR (3-4 weeks)**
1. ✅ **CrowdStrike Falcon API** (src/integrations/crowdstrike_adapter.py - expand existing)
2. ✅ **SentinelOne API** (src/integrations/sentinelone_adapter.py)
3. ✅ **Microsoft Defender for Endpoint** (src/integrations/mde_adapter.py)

### **Phase 4: Cloud-Native Logs (2-3 weeks)**
1. ✅ **GCP Audit Logs** (src/collectors/gcp_audit_collector.py)
2. ✅ **Azure Activity Logs** (src/collectors/azure_activity_collector.py)
3. ✅ **Kubernetes Audit** (src/collectors/k8s_audit_collector.py)

---

## 📝 Quick Reference: Connector Implementation Template

```python
# Template: src/collectors/{source}_collector.py
from .base import EventCollector
from typing import List, Dict, Any

class {Source}Collector(EventCollector):
    source = "{source_name}"

    def __init__(self, tenant_id: str = 'default'):
        self.tenant_id = tenant_id
        self._api_url = os.getenv('{SOURCE}_API_URL')
        self._api_key = os.getenv('{SOURCE}_API_KEY')

    def fetch_events(self, since_ts: float) -> List[Dict[str, Any]]:
        """Fetch events since timestamp"""
        events = []
        # 1. Call vendor API
        # 2. Parse response
        # 3. Normalize to canonical schema
        for raw_event in self._call_api(since_ts):
            events.append({
                'user': raw_event.get('user'),
                'host': raw_event.get('hostname'),
                'event_type': raw_event.get('type'),
                'ts': raw_event.get('timestamp'),
                'source': self.source,
                'raw': raw_event  # Preserve original for debugging
            })
        return events

    def _call_api(self, since_ts: float):
        """Implement vendor-specific API call"""
        resp = requests.get(
            f"{self._api_url}/events",
            headers={'Authorization': f'Bearer {self._api_key}'},
            params={'since': since_ts}
        )
        return resp.json()['events']
```

---

## 🎯 Conclusion

### **Current State:**
- **68% coverage** across 8 domains
- **Strong:** Identity, Remote Access, Endpoint (basic)
- **Weak:** Data Access, Application, Cloud logs

### **Competitive Position:**
- **Ahead:** API-first architecture, HopGraph correlation, multi-tenancy
- **Behind:** Commercial EDR integrations, forensic parsers, cloud-native logs

### **Next Steps:**
1. **Prioritize CloudTrail + Tetragon** (biggest threat detection ROI)
2. **Add Proofpoint webhook** (email phishing is #1 attack vector)
3. **Build KAPE parser** (critical for IR/forensics)
4. **Standardize canonical schema** (ensure correlation fidelity)

**Estimated Total Effort:** 8-12 weeks for complete coverage
**Resource Requirement:** 2 engineers (1 backend, 1 integrations specialist)

---

**Document Owner:** Platform Security Engineering
**Last Updated:** 2025-01-20
**Review Cycle:** Quarterly
