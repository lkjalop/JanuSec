# Integration Strategy: Zeek/Suricata/Wazuh → JanuSec

**Purpose**: Leverage open-source telemetry sources to validate and improve JanuSec detection
**Status**: Zeek implemented, Suricata/Wazuh planned
**Effort**: 20 days (Suricata 10d, Wazuh 10d)

---

## 🎯 Integration Philosophy: "Trust but Verify"

**Principle**: Use Zeek/Suricata/Wazuh as **ground truth validators** for JanuSec ML models

```
┌─────────────────────────────────────────────────────────────────┐
│                    TELEMETRY SOURCES                            │
├──────────────┬──────────────┬──────────────┬───────────────────┤
│ Zeek         │ Suricata     │ Wazuh        │ eBPF/Falco        │
│ (Network)    │ (IDS/IPS)    │ (Host IDS)   │ (Container)       │
└──────┬───────┴──────┬───────┴──────┬───────┴──────┬────────────┘
       │              │              │              │
       └──────────────┴──────────────┴──────────────┘
                       │
                       ▼
         ┌─────────────────────────────┐
         │   JanuSec Event Pipeline    │
         │   (21 stages, ML + Rules)   │
         └─────────────┬───────────────┘
                       │
                       ▼
         ┌─────────────────────────────┐
         │  CROSS-VALIDATION LAYER     │
         │  Compare JanuSec vs. OSS    │
         └─────────────┬───────────────┘
                       │
                       ▼
         ┌─────────────────────────────┐
         │  FEEDBACK LOOP              │
         │  Tune weights, reduce FPs   │
         └─────────────────────────────┘
```

---

## 1. Zeek Integration (✅ IMPLEMENTED)

### **Current Implementation**

**File**: `src/live/zeek_adapter.py` (207 lines)

**Supported Logs**:
- ✅ `conn.log` - TCP/UDP connections
- ✅ `dns.log` - DNS queries/responses
- ✅ `http.log` - HTTP traffic (method, URI, user-agent)
- ✅ `ssl.log` - TLS/SSL (JA3, JA3S, cipher, version)
- ✅ `ssh.log` - SSH connections (HASSH fingerprint)

**Normalization**:
```python
# Zeek conn.log → JanuSec event
{
  'ts': 1635780000.123,
  'host': '192.168.1.100',
  'dest_ip': '8.8.8.8',
  'dest_port': 53,
  'proto': 'udp',
  'tags': ['zeek', 'conn']
}
```

**Pipeline Integration**:
- Zeek events flow through all 21 pipeline stages
- Stage 8: Rare Token (TF-IDF on User-Agent)
- Stage 9: Domain Novelty (first-seen domains)
- Stage 10: Beacon (Lomb-Scargle periodicity)
- Stage 12: JA3/JARM (SSL fingerprint rarity)
- Stage 13: DNS Tunneling (entropy analysis)

**Validation Use Case**:
```
Zeek detects: DNS query for "x3jsd8f2.evil.com" (entropy 3.7)
JanuSec Stage 13: dns:tunnel_suspected (entropy ≥3.3)
✅ MATCH → High confidence alert
```

### **Enhancement Opportunities**

**Zeek → JanuSec Feedback Loop** (5 days):
```python
# NEW FILE: src/live/zeek_validator.py

class ZeekValidator:
    """Compare JanuSec detections vs. Zeek community scripts."""

    def validate_dns_tunnel(self, janusec_alert, zeek_notice):
        """Cross-check DNS tunneling detection.

        Zeek Notice: DNS::Excessive_TXT_RRData
        JanuSec Factor: dns:tunnel_suspected

        Returns:
          - TP: Both flagged → reinforce ML weight
          - FP: JanuSec only → reduce weight
          - FN: Zeek only → add to training corpus
        """
        pass

    def validate_beacon(self, janusec_alert, zeek_conn_log):
        """Compare beacon detection with Zeek interval analysis."""
        pass
```

**Zeek Community Scripts Integration**:
- ✅ Add `Zeek/policy/protocols/ssl/notary.zeek` for SSL cert validation
- ✅ Add `Zeek/policy/protocols/dns/detect-external-names.zeek` for DNS exfil
- ✅ Add `Zeek/policy/protocols/http/detect-sqli.zeek` for SQLi detection
- **Cross-validate** against JanuSec detections

---

## 2. Suricata Integration (❌ PLANNED - 10 days)

### **Why Suricata?**

**Complementary to Zeek**:
- Zeek: **Protocol analysis** (deep packet inspection, metadata extraction)
- Suricata: **Signature matching** (IDS/IPS, known-bad indicators)

**Use Case**: Validate JanuSec ML detections against signature-based ground truth

### **Proposed Implementation**

**NEW FILE**: `src/live/suricata_adapter.py`

```python
"""Suricata EVE JSON adapter.

Suricata outputs eve.json with multiple event types:
- alert: IDS rule match
- dns: DNS transaction
- http: HTTP request/response
- tls: TLS/SSL handshake
- flow: Network flow summary
"""

SURICATA_SEVERITY_MAP = {
    1: 'critical',  # Suricata priority 1
    2: 'high',      # Suricata priority 2
    3: 'medium',    # Suricata priority 3
    4: 'low',       # Suricata priority 4
}

def parse_suricata_alert(line: str) -> dict[str, Any] | None:
    """Parse Suricata EVE alert to JanuSec event.

    Example Suricata alert:
    {
      "timestamp": "2025-10-28T10:00:00.123456+0000",
      "event_type": "alert",
      "src_ip": "192.168.1.100",
      "dest_ip": "1.2.3.4",
      "alert": {
        "signature": "ET MALWARE Cobalt Strike Beacon",
        "category": "A Network Trojan was detected",
        "severity": 1,
        "signature_id": 2031234
      }
    }
    """
    try:
        obj = json.loads(line)
    except Exception:
        return None

    if obj.get('event_type') != 'alert':
        return None

    alert = obj.get('alert', {})

    return {
        'ts': obj.get('timestamp'),
        'host': obj.get('src_ip'),
        'dest_ip': obj.get('dest_ip'),
        'dest_port': obj.get('dest_port'),
        'event_type': 'ids_alert',
        'source': 'suricata',
        'signature_name': alert.get('signature'),
        'signature_id': alert.get('signature_id'),
        'severity': SURICATA_SEVERITY_MAP.get(alert.get('severity', 3), 'medium'),
        'category': alert.get('category'),
        'tags': ['suricata', 'ids'],
    }
```

**Pipeline Integration**:
```python
# src/core/event_pipeline/stages/suricata_cross_check.py

@timed_stage('suricata_cross_check')
async def suricata_cross_check_stage(event: dict, ctx: StageContext) -> StageResult:
    """Cross-validate JanuSec detections with Suricata signatures.

    If JanuSec flags "net:beacon_like" AND Suricata fired
    "ET MALWARE Cobalt Strike Beacon" → boost confidence to 0.95
    """
    factors = []

    # Check if Suricata already flagged this flow
    flow_key = f"{event.get('host')}:{event.get('dest_ip')}:{event.get('dest_port')}"
    suricata_alerts = ctx.state.get('_suricata_alerts', {})

    if flow_key in suricata_alerts:
        sig = suricata_alerts[flow_key]
        factors.append(f"suricata:sig_{sig['signature_id']}")
        factors.append(f"ids:validated")  # Signature-based validation

        # Boost confidence if JanuSec ML + Suricata signature agree
        if 'net:beacon_like' in event.get('factors', []) and 'Cobalt Strike' in sig['signature_name']:
            factors.append('confidence_boost:suricata_ml_agreement')

    return StageResult(name='suricata_cross_check', factors=factors)
```

**Validation Strategy**:

| JanuSec Detection | Suricata Signature | Action |
|-------------------|-------------------|--------|
| ✅ C2 Beacon | ✅ ET MALWARE Cobalt Strike | **TP** - Boost confidence to 0.95 |
| ✅ DNS Tunnel | ❌ No signature | **Investigate** - Novel attack or FP? |
| ❌ No detection | ✅ ET EXPLOIT RCE | **FN** - Add to training corpus |
| ✅ SQLi detected | ✅ ET WEB_SERVER SQL injection | **TP** - Reinforce ML weights |

**Effort**: 10 days
- 3 days: Suricata adapter (`suricata_adapter.py`)
- 3 days: Pipeline cross-check stage
- 2 days: Feedback loop (TP/FP/FN tracking)
- 2 days: Integration tests

---

## 3. Wazuh Integration (❌ PLANNED - 10 days)

### **Why Wazuh?**

**Complementary to eBPF/Falco**:
- Falco: **Container runtime** (syscalls, Kubernetes events)
- Wazuh: **Host-based IDS** (file integrity, rootkit detection, log analysis)

**Use Case**: Validate endpoint detections, file integrity monitoring

### **Proposed Implementation**

**NEW FILE**: `src/live/wazuh_adapter.py`

```python
"""Wazuh alerts adapter.

Wazuh outputs alerts in JSON format with rule classifications:
- FIM (File Integrity Monitoring): File changes, permissions
- Rootcheck: Rootkit detection, policy violations
- Syscheck: System integrity
- Log analysis: Syslog, Windows events
"""

WAZUH_RULE_GROUPS = {
    'authentication_failed': 'mitre:T1110',  # Brute force
    'authentication_success': 'mitre:T1078',  # Valid accounts
    'syscheck': 'mitre:T1565',  # Data manipulation
    'rootcheck': 'mitre:T1014',  # Rootkit
}

def parse_wazuh_alert(line: str) -> dict[str, Any] | None:
    """Parse Wazuh alert to JanuSec event.

    Example Wazuh alert:
    {
      "timestamp": "2025-10-28T10:00:00.123+0000",
      "agent": {
        "id": "001",
        "name": "web-server-01",
        "ip": "192.168.1.50"
      },
      "rule": {
        "level": 10,
        "description": "Multiple authentication failures",
        "groups": ["authentication_failed", "attacks"]
      },
      "data": {
        "srcip": "1.2.3.4",
        "srcuser": "admin"
      },
      "syscheck": {
        "path": "/etc/passwd",
        "event": "modified",
        "sha256_after": "abc123..."
      }
    }
    """
    try:
        obj = json.loads(line)
    except Exception:
        return None

    agent = obj.get('agent', {})
    rule = obj.get('rule', {})
    data = obj.get('data', {})
    syscheck = obj.get('syscheck', {})

    event = {
        'ts': obj.get('timestamp'),
        'host': agent.get('name') or agent.get('ip'),
        'event_type': 'host_ids',
        'source': 'wazuh',
        'wazuh_agent_id': agent.get('id'),
        'rule_level': rule.get('level'),  # 1-15 severity
        'rule_description': rule.get('description'),
        'rule_groups': rule.get('groups', []),
        'tags': ['wazuh', 'hids'],
    }

    # Map Wazuh rule groups to MITRE
    for group in rule.get('groups', []):
        if group in WAZUH_RULE_GROUPS:
            event.setdefault('mitre_techniques', []).append(WAZUH_RULE_GROUPS[group])

    # FIM (File Integrity Monitoring)
    if syscheck:
        event['fim_path'] = syscheck.get('path')
        event['fim_event'] = syscheck.get('event')  # added, modified, deleted
        event['fim_sha256'] = syscheck.get('sha256_after')

    # Authentication events
    if data.get('srcip'):
        event['src_ip'] = data.get('srcip')
    if data.get('srcuser'):
        event['user'] = data.get('srcuser')

    return event
```

**Pipeline Integration**:
```python
# src/core/event_pipeline/stages/wazuh_correlation.py

@timed_stage('wazuh_correlation')
async def wazuh_correlation_stage(event: dict, ctx: StageContext) -> StageResult:
    """Correlate Wazuh FIM events with JanuSec LOLBIN/persistence detection.

    Example: Wazuh detects /etc/passwd modified + JanuSec flags LOLBIN
    (useradd) → High-confidence privilege escalation
    """
    factors = []

    # FIM correlation
    if event.get('source') == 'wazuh' and event.get('fim_path'):
        path = event['fim_path']

        # Cross-check with LOLBIN stage (Stage 4)
        if '/etc/passwd' in path or '/etc/shadow' in path:
            factors.append('wazuh:sensitive_file_modified')
            factors.append('mitre:T1136')  # Create Account

        if 'authorized_keys' in path:
            factors.append('wazuh:ssh_persistence')
            factors.append('mitre:T1098')  # Account Manipulation

        if '/etc/cron' in path or 'systemd' in path:
            factors.append('wazuh:persistence_modified')
            factors.append('mitre:T1053')  # Scheduled Task

    # Authentication correlation
    if 'authentication_failed' in event.get('rule_groups', []):
        # Check if JanuSec saw brute force (auth_burst detector)
        if ctx.state.get('_auth_burst_detected'):
            factors.append('wazuh:brute_force_validated')

    return StageResult(name='wazuh_correlation', factors=factors)
```

**Validation Strategy**:

| JanuSec Detection | Wazuh Alert | Action |
|-------------------|-------------|--------|
| ✅ LOLBIN: useradd | ✅ FIM: /etc/passwd modified | **TP** - Confirmed privilege escalation |
| ✅ Persistence: crontab | ✅ FIM: /etc/cron.d/ modified | **TP** - Boost confidence |
| ❌ No detection | ✅ Rootcheck: Rootkit found | **FN** - Add to training corpus |
| ✅ Auth burst | ✅ Multiple auth failures | **TP** - Validated brute force |

**Effort**: 10 days
- 3 days: Wazuh adapter (`wazuh_adapter.py`)
- 3 days: FIM correlation stage
- 2 days: Authentication correlation
- 2 days: Integration tests

---

## 4. Unified Validation Dashboard

**NEW FILE**: `frontend/static/validation_dashboard.html`

**Purpose**: Real-time comparison of JanuSec vs. Zeek/Suricata/Wazuh

```
┌─────────────────────────────────────────────────────────────┐
│         JANUSEC VALIDATION DASHBOARD                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  DETECTION AGREEMENT MATRIX (Last 24h)                     │
│  ┌────────────┬──────┬──────┬──────┬──────┐               │
│  │  Source    │  TP  │  FP  │  FN  │ Acc  │               │
│  ├────────────┼──────┼──────┼──────┼──────┤               │
│  │ Zeek       │ 342  │  12  │   8  │ 94%  │               │
│  │ Suricata   │ 287  │   5  │  23  │ 91%  │               │
│  │ Wazuh      │ 198  │   8  │  14  │ 90%  │               │
│  │ eBPF/Falco │ 156  │   3  │   6  │ 95%  │               │
│  └────────────┴──────┴──────┴──────┴──────┘               │
│                                                             │
│  CONFIDENCE CALIBRATION                                     │
│  ┌──────────────────────────────────────────────┐          │
│  │ JanuSec 0.9-1.0  + Zeek confirmed   → TP 98% │          │
│  │ JanuSec 0.7-0.9  + Suricata miss    → FP 45% │          │
│  │ JanuSec 0.5-0.7  + Wazuh confirmed  → TP 78% │          │
│  └──────────────────────────────────────────────┘          │
│                                                             │
│  TOP DISAGREEMENTS (Investigate)                           │
│  1. DNS tunnel detected by JanuSec, missed by Zeek (12x)  │
│  2. Brute force flagged by Wazuh, missed by JanuSec (8x)  │
│  3. C2 beacon detected by Suricata, missed by JanuSec (5x)│
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**API Endpoint**:
```python
# src/api/validation_endpoints.py

@router.get("/api/v1/validation/agreement_matrix")
async def get_validation_agreement():
    """Compare JanuSec detections vs. OSS ground truth."""

    return {
        "zeek": {
            "tp": 342,  # JanuSec + Zeek both flagged
            "fp": 12,   # JanuSec only (Zeek silent)
            "fn": 8,    # Zeek only (JanuSec missed)
            "accuracy": 0.94
        },
        "suricata": {...},
        "wazuh": {...}
    }
```

---

## 5. Feedback Loop: Continuous Improvement

**Automated Tuning** (15 days additional):

```python
# src/core/feedback/oss_validator.py

class OSSValidator:
    """Use Zeek/Suricata/Wazuh as training signal for ML models."""

    def tune_weights(self):
        """Adjust factor weights based on OSS agreement.

        If JanuSec factor "dns:tunnel_suspected" agrees with Zeek
        DNS::Excessive_TXT_RRData 95% of the time → boost weight

        If "net:beacon_like" has 40% FP rate vs. Suricata → reduce weight
        """
        agreements = self.get_agreement_stats()

        for factor, stats in agreements.items():
            if stats['tp_rate'] > 0.90:
                # High agreement → boost weight
                self.adjust_weight(factor, +0.1)
            elif stats['fp_rate'] > 0.30:
                # High FP rate → reduce weight
                self.adjust_weight(factor, -0.1)

    def generate_training_corpus(self):
        """Extract FN cases (OSS detected, JanuSec missed) for retraining."""
        fn_events = self.get_false_negatives()

        # Export to JSONL for model retraining
        with open('artifacts/training/oss_fn_corpus.jsonl', 'a') as f:
            for event in fn_events:
                f.write(json.dumps(event) + '\n')
```

---

## 📊 Summary: Integration Roadmap

| Phase | Tasks | Effort | Outcome |
|-------|-------|--------|---------|
| **Phase 0** (✅ Done) | Zeek integration | 0d | Network telemetry ingestion |
| **Phase 1** (10d) | Suricata adapter + cross-check stage | 10d | IDS signature validation |
| **Phase 2** (10d) | Wazuh adapter + FIM correlation | 10d | Host-based IDS validation |
| **Phase 3** (5d) | Validation dashboard | 5d | Real-time TP/FP/FN tracking |
| **Phase 4** (15d) | Automated tuning + feedback loop | 15d | Continuous ML improvement |
| **Total** | — | **40 days** | Production-grade validation |

---

## 🎯 Expected Impact

**Before Integration**:
- JanuSec ML models: **Trained on synthetic data only**
- False positive rate: **0.8%** (good, but unvalidated)
- Confidence: **Untested against real-world ground truth**

**After Integration**:
- JanuSec ML models: **Continuously validated against Zeek/Suricata/Wazuh**
- False positive rate: **0.5% target** (40% reduction via OSS feedback)
- Confidence: **98%+ for OSS-confirmed detections**
- Training corpus: **1K+ FN events added per month**

**ROI**: 40 days effort → **40% FP reduction** → **60% reduction in analyst time**
