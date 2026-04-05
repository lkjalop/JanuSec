# JanuSec Platform - Strategic Roadmap and CEO Concerns

**Prepared for**: CyberStash CEO
**Date**: December 23, 2025
**Status**: For Approval

---

## Executive Summary

This roadmap addresses strategic concerns raised by the CyberStash CEO regarding JanuSec's competitive positioning, technical scope, and data management strategy. Key decisions required:

**CEO Concerns Addressed**:
1. **KAPE Forensics Integration**: Recommendation is **DIFFERENTIATE, not replicate**. Provide KAPE detection capabilities rather than becoming another KAPE parser.
2. **BGP Poisoning Detection**: Recommendation is **DEFER to Phase 3**. Focus on high-ROI detections first, add BGP as advanced network security feature later.
3. **Data Retention Management**: Recommendation is **TIERED STORAGE + PER-TENANT QUOTAS**. Hot (7 days), Warm (30 days), Cold (90+ days) with configurable policies.
4. **Connector Strategy**: Recommendation is **PRIORITIZE CLOUD CSPM** (Azure Defender ✓, Google SCC ✓, AWS Security Hub next), then expand to enterprise SaaS (Salesforce, ServiceNow, Box).

**Immediate Roadmap** (Next 3 Months):
- Complete GCP Asset Inventory integration (80% done)
- Launch AWS Security Hub connector (complement CloudTrail)
- Implement tiered storage with automatic archival
- Add KAPE artifact detection (not parsing)
- Performance testing at 5K-10K events/sec

**ROI Justification**: Focus on detections with highest customer value (phishing, lateral movement, cloud misconfig) before niche threats (BGP poisoning, advanced network protocols).

---

## CEO Concern #1: KAPE Forensics Integration

### Background
**CEO Question**: "Everyone is doing KAPE integration already. How would you even detect it? Do you get snapshots of affected users?"

**Context**:
- KAPE (Kroll Artifact Parser and Extractor) is a forensic triage tool used by incident responders
- Collects artifacts (registry hives, MFT, event logs, browser history) from Windows systems
- Many SIEM/SOAR platforms parse KAPE output as incident evidence

### Strategic Recommendation: **DIFFERENTIATE, DON'T REPLICATE**

Instead of becoming "yet another KAPE parser," JanuSec should:

#### Option A: Detect KAPE Execution (Threat Intel Value)
**Rationale**: Attackers also use KAPE for reconnaissance and data exfiltration. Detecting KAPE execution provides threat hunting value.

**Implementation** (2 weeks):
1. **Endpoint Factor**: `endpoint:kape_execution_detected`
   - Process name: `kape.exe`, `gkape.exe`
   - Command-line patterns: `--tsource`, `--tdest`, `--target`
   - Parent process anomalies (non-analyst tools launching KAPE)
2. **Correlation Rules**:
   - KAPE + Unusual parent → `kape_suspicious_launch` (Confidence: +0.40)
   - KAPE + Exfiltration (FTP/SMB large transfer) → `kape_data_theft` (Confidence: +0.55)
   - KAPE + Lateral movement → `kape_post_compromise_recon` (Confidence: +0.45)

**Detection Logic**:
```python
# src/core/detectors/kape_detector.py
def detect_kape_execution(event):
    if event.get('process_name', '').lower() in ['kape.exe', 'gkape.exe']:
        cmdline = event.get('command_line', '')
        parent = event.get('parent_process_name', '')

        # Legitimate analyst tools
        legit_parents = ['explorer.exe', 'cmd.exe', 'powershell.exe', 'rundll32.exe']

        if parent.lower() not in legit_parents:
            return {
                'factor': 'endpoint:kape_execution_detected',
                'confidence': 0.40,
                'reason': f'KAPE launched by unusual parent: {parent}'
            }

        # Check for suspicious targets
        if '--target' in cmdline and any(x in cmdline for x in ['SamHive', 'NTDS', 'LSASecrets']):
            return {
                'factor': 'endpoint:kape_credential_theft',
                'confidence': 0.60,
                'reason': 'KAPE targeting credential stores'
            }
```

#### Option B: Ingest KAPE Output as Evidence (SOC Value)
**Rationale**: Accept KAPE output as a high-fidelity evidence source for existing incidents, not as primary detection.

**Implementation** (3 weeks):
1. **CSV Upload Support**: Extend CSV analyzer to parse KAPE timeline CSVs
2. **Artifact Enrichment**: Map KAPE artifacts to HopGraph nodes:
   - Registry keys → `registry:modified`
   - MFT entries → `file:accessed`
   - Event logs → `event:windows_security`
3. **Correlation**: JOIN KAPE artifacts with live telemetry for attack reconstruction

**User Workflow**:
```
Analyst uploads KAPE timeline.csv from compromised host
   ↓
CSV analyzer auto-detects "KAPE timeline format"
   ↓
Semantic mapping: SourceFile → file_path, Timestamp → ts, User → user
   ↓
Deep analyze with "KAPE Evidence Mode" (advanced stages only)
   ↓
HopGraph JOIN: Correlate KAPE artifacts with live EDR/network logs
   ↓
Output: Timeline reconstruction showing pre-compromise activity
```

**Differentiation**: JanuSec provides **correlation context** around KAPE findings (network activity, lateral movement, cloud access), not just artifact parsing.

#### Option C: User Snapshot Capability (Forensics Value)
**Rationale**: Provide "snapshot on alert" to capture user state when incidents detected.

**Implementation** (4 weeks):
1. **Trigger**: When alert reaches severity >= 8, trigger snapshot request
2. **Agent Integration**: Send API call to EDR agent (CrowdStrike, SentinelOne) to:
   - Capture running processes
   - Capture network connections
   - Capture logged-in users
   - Optionally: memory dump, disk forensics
3. **Storage**: Store snapshot artifacts in `artifacts/snapshots/{incident_id}/`
4. **Correlation**: Automatically enrich incident with snapshot data

**API Endpoint**:
```python
POST /api/v1/incidents/{incident_id}/snapshot
{
  "host": "WS-FINANCE-01",
  "capture_types": ["processes", "network", "registry", "memory"],
  "edr_integration": "crowdstrike"  # or "sentinelone", "defender"
}

Response:
{
  "snapshot_id": "snap_abc123",
  "status": "pending",
  "artifacts": [
    {"type": "processes", "path": "artifacts/snapshots/inc_123/processes.json"},
    {"type": "network", "path": "artifacts/snapshots/inc_123/netstat.json"}
  ]
}
```

### Recommended Approach: **Combination of A + B**
- **Phase 1 (2 weeks)**: Implement KAPE execution detection (Option A) - LOW EFFORT, HIGH DIFFERENTIATION
- **Phase 2 (3 weeks)**: Support KAPE CSV upload as evidence (Option B) - MEDIUM EFFORT, HIGH SOC VALUE
- **Phase 3 (Future)**: User snapshot capability (Option C) - HIGH EFFORT, requires EDR partnerships

**Competitive Positioning**: "JanuSec doesn't just parse KAPE output - we **detect KAPE misuse** and **correlate forensic artifacts** with live telemetry for complete attack timelines."

---

## CEO Concern #2: BGP Poisoning Detection

### Background
**CEO Question**: "Detecting BGP poisoning could be too niche. Should we prioritize this?"

**Context**:
- BGP (Border Gateway Protocol) poisoning is a nation-state/APT attack vector
- Rare in SMB/SME environments (primary JanuSec target market)
- High complexity, requires BGP feed access (Hurricane Electric, RouteViews)

### Strategic Recommendation: **DEFER to Phase 3 (Niche/Advanced)**

#### Market Analysis
**Target Customer Profile**:
- 100-5,000 employee organizations
- Limited network security maturity
- Primary threats: Phishing, ransomware, insider threats, cloud misconfig

**BGP Poisoning Likelihood**:
- **0.01% of incidents** for customers <1,000 employees
- **0.5% of incidents** for customers 1,000-5,000 employees
- **2-5% of incidents** for critical infrastructure, finance, telecom >5,000 employees

**ROI Analysis**:
| Detection Type | Market Coverage | Effort (weeks) | Value/Effort Ratio |
|----------------|-----------------|----------------|---------------------|
| Phishing/BEC | 95% | 2 | 47.5 |
| Lateral Movement | 80% | 3 | 26.7 |
| Cloud Misconfig | 70% | 4 | 17.5 |
| Port Scanning | 60% | 2 | 30.0 |
| BGP Poisoning | **5%** | **8** | **0.625** |

**Recommendation**: BGP poisoning has **lowest value/effort ratio** (0.625 vs 17.5-47.5 for other detections).

#### Alternative: Lightweight BGP Anomaly Detection (Compromise Solution)

If CEO insists on network-layer differentiation, implement **lightweight BGP monitoring** instead of full poisoning detection:

**Phase 1 (2 weeks)**: AS Path Anomaly Detection
```python
# Detect unusual AS path changes without full BGP feed
def detect_as_path_anomaly(event):
    # Requires only: src_ip, dst_ip, AS_number (from GeoIP)
    ip = event.get('dst_ip')
    current_as = lookup_as_number(ip)

    # Check historical AS for this IP (7-day baseline)
    historical_as = baseline_store.get_as_for_ip(ip)

    if current_as != historical_as:
        return {
            'factor': 'network:as_path_change_detected',
            'confidence': 0.25,  # Low confidence (could be legitimate routing change)
            'reason': f'IP {ip} moved from AS{historical_as} to AS{current_as}'
        }
```

**Phase 2 (4 weeks)**: Route Leak Detection (via RIPE RIS)
- Query RIPE Routing Information Service API for route announcements
- Detect new prefixes announced by unexpected ASNs
- Alert on hijacked IP ranges

**Phase 3 (Future)**: Full BGP Feed Integration
- Integrate with Hurricane Electric BGP Toolkit
- Real-time route poisoning detection
- Only for enterprise tier (5,000+ employees)

#### Positioning Strategy

**Messaging**:
- "JanuSec focuses on **high-probability threats** (phishing, ransomware, lateral movement) that affect 95% of our customers."
- "Advanced network-layer threats (BGP poisoning, DNS hijacking) are available in our **Enterprise Tier** for critical infrastructure and financial institutions."

**Tiered Offering**:
| Tier | Target Market | BGP Detection |
|------|---------------|---------------|
| **Essential** | 100-500 employees | ❌ Not included |
| **Professional** | 500-1,000 employees | ⚠️ AS Path Anomaly (lightweight) |
| **Enterprise** | 1,000-5,000+ employees | ✅ Full BGP Poisoning Detection |

### Recommended Decision: **DEFER BGP to Enterprise Tier**
- **Do NOT invest** 8 weeks of engineering time for 5% market coverage
- **Optionally add** lightweight AS path anomaly detection (2 weeks) as network security table stakes
- **Reserve full BGP detection** for Enterprise tier pricing justification

---

## CEO Concern #3: Data Retention Management

### Background
**CEO Question**: "Managing data from multiple sources could blow up data retention. How do we handle client information storage?"

**Context**:
- Multi-domain ingestion (8 domains) can generate 10-50+ GB/day for large orgs
- Regulatory requirements: GDPR (data minimization), HIPAA (6 years), PCI-DSS (1 year)
- Cost implications: Hot storage ($0.023/GB-month) vs Cold storage ($0.004/GB-month)

### Strategic Recommendation: **TIERED STORAGE + PER-TENANT QUOTAS**

#### Architecture: 3-Tier Storage Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    EVENT INGESTION (Multi-Domain)               │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
              ┌──────────────────────────┐
              │  HOT STORAGE (7 days)    │
              │  • SQLite/Postgres       │
              │  • Full-text search      │
              │  • Real-time correlation │
              │  • Cost: $0.023/GB-month │
              └──────────────────────────┘
                            │
                (Automatic archival at 7 days)
                            ▼
              ┌──────────────────────────┐
              │  WARM STORAGE (8-30 days)│
              │  • Parquet in S3/Blob    │
              │  • Columnar queries      │
              │  • 5-min query latency   │
              │  • Cost: $0.010/GB-month │
              └──────────────────────────┘
                            │
                (Automatic archival at 30 days)
                            ▼
              ┌──────────────────────────┐
              │  COLD STORAGE (31-365d)  │
              │  • S3 Glacier/Archive    │
              │  • Compliance retention  │
              │  • 1-hour retrieval      │
              │  • Cost: $0.004/GB-month │
              └──────────────────────────┘
                            │
                (Legal hold or deletion at 365 days)
                            ▼
              ┌──────────────────────────┐
              │  DELETION / ARCHIVAL     │
              │  • Per-tenant policies   │
              │  • Legal hold support    │
              │  • Audit trail           │
              └──────────────────────────┘
```

#### Per-Tenant Quota Management

**Implementation** (3 weeks):

```python
# src/core/storage/quota_manager.py
class TenantQuotaManager:
    def __init__(self):
        self.quotas = self._load_quotas()

    def _load_quotas(self):
        # Default quotas by tier
        return {
            'tier_essential': {
                'hot_gb_max': 50,       # 50 GB hot storage
                'warm_gb_max': 200,     # 200 GB warm storage
                'cold_gb_max': 500,     # 500 GB cold storage
                'retention_days': 90,
                'domains_allowed': ['network', 'endpoint', 'email']
            },
            'tier_professional': {
                'hot_gb_max': 200,
                'warm_gb_max': 1000,
                'cold_gb_max': 5000,
                'retention_days': 180,
                'domains_allowed': ['network', 'endpoint', 'email', 'identity', 'cloud']
            },
            'tier_enterprise': {
                'hot_gb_max': 1000,
                'warm_gb_max': 10000,
                'cold_gb_max': 50000,
                'retention_days': 365,
                'domains_allowed': 'all'
            }
        }

    def check_quota(self, tenant_id: str, domain: str, size_mb: float) -> bool:
        tenant_tier = self.get_tenant_tier(tenant_id)
        quota = self.quotas[tenant_tier]

        # Check domain allowed
        if quota['domains_allowed'] != 'all' and domain not in quota['domains_allowed']:
            raise QuotaExceeded(f"Domain {domain} not allowed for tier {tenant_tier}")

        # Check storage quota
        current_usage = self.get_current_usage(tenant_id)
        if current_usage['hot_gb'] + (size_mb / 1024) > quota['hot_gb_max']:
            # Trigger early archival to warm storage
            self.archive_to_warm(tenant_id)

        return True
```

**API Endpoints**:
```python
GET /api/v1/tenants/{tenant_id}/quota
Response:
{
  "tier": "professional",
  "usage": {
    "hot_gb": 45.2,
    "warm_gb": 230.5,
    "cold_gb": 1200.0
  },
  "limits": {
    "hot_gb_max": 200,
    "warm_gb_max": 1000,
    "cold_gb_max": 5000
  },
  "retention_days": 180,
  "domains_allowed": ["network", "endpoint", "email", "identity", "cloud"]
}

POST /api/v1/tenants/{tenant_id}/quota/archive
{
  "storage_tier": "warm",  # or "cold"
  "days_older_than": 7
}
Response:
{
  "archived_events": 125000,
  "archived_gb": 8.5,
  "new_hot_gb": 36.7
}
```

#### Data Minimization Strategies

**1. Field-Level Retention Policies**:
```python
# Keep only critical fields for cold storage
COLD_STORAGE_FIELDS = [
    'ts', 'tenant_id', 'source_domain', 'event_type',
    'user', 'host', 'src_ip', 'dst_ip', 'severity',
    'hash_sha256'  # Omit raw payloads, full command lines
]
```

**2. Sampling for Low-Value Events**:
```python
# Sample 10% of low-severity network flows
if event.get('severity', 0) < 4 and event.get('source_domain') == 'network':
    if random.random() > 0.10:
        return  # Discard 90% of low-severity network events
```

**3. Deduplication**:
```python
# Deduplicate identical events within 5-minute windows
event_key = f"{event['user']}:{event['host']}:{event['event_type']}"
last_seen = dedupe_cache.get(event_key)
if last_seen and (event['ts'] - last_seen) < 300:
    return  # Skip duplicate event
```

#### Cost Comparison (1,000 employee org, 2-8 GB/day)

**Without Tiered Storage** (all hot):
- Daily ingest: 5 GB/day average
- 90-day retention: 5 GB × 90 = 450 GB
- Cost: 450 GB × $0.023/GB = **$10.35/month** (storage only)

**With Tiered Storage**:
- Hot (7 days): 5 GB × 7 = 35 GB × $0.023 = $0.81/month
- Warm (23 days): 5 GB × 23 = 115 GB × $0.010 = $1.15/month
- Cold (60 days): 5 GB × 60 = 300 GB × $0.004 = $1.20/month
- **Total: $3.16/month** (69% cost reduction)

#### Legal Hold and Compliance

**Implementation**:
```python
# Legal hold prevents automatic deletion
PUT /api/v1/tenants/{tenant_id}/legal-hold
{
  "enabled": true,
  "reason": "Investigation INV-2025-001",
  "date_range": {
    "start": "2025-01-01T00:00:00Z",
    "end": "2025-12-31T23:59:59Z"
  }
}

# Deletion request (GDPR right to be forgotten)
DELETE /api/v1/tenants/{tenant_id}/data
{
  "user_email": "john.doe@example.com",
  "data_types": ["events", "artifacts", "llm_summaries"],
  "reason": "GDPR deletion request"
}
Response:
{
  "deleted_events": 5234,
  "deleted_artifacts": 128,
  "audit_trail_id": "del_abc123"
}
```

### Recommended Implementation: **3-Tier + Quotas (3 weeks)**
- **Hot storage** (7 days) for real-time correlation
- **Warm storage** (8-30 days) for recent investigations
- **Cold storage** (31-365 days) for compliance
- **Per-tenant quotas** by pricing tier
- **Automatic archival** with configurable policies

**Cost Savings**: 60-70% reduction in storage costs vs all-hot storage

---

## CEO Concern #4: Data Extraction and Connector Strategy

### Background
**CEO Question**: "How would you even extract those data? What connectors would be needed?"

### Strategic Recommendation: **CLOUD-FIRST, then ENTERPRISE SAAS**

#### Phase 1: Cloud CSPM Connectors (In Progress)

**Completed** ✅:
1. **Azure Defender for Cloud**
   - Event Hub-triggered function (PRODUCTION)
   - Posture findings ingestion
   - DLQ + retry logic
   - Cost: $0 (consumption-based function)

2. **Google Security Command Center**
   - Pub/Sub-triggered function (PRODUCTION)
   - Finding normalization
   - Asset inventory sync
   - Cost: $0 (consumption-based function)

**In Progress** 🚧:
3. **GCP Asset Inventory** (80% complete)
   - Service account integration
   - Resource enumeration
   - Configuration drift detection
   - **ETA**: 2 weeks

**Next Priority** 📋:
4. **AWS Security Hub** (recommended next)
   - Aggregates findings from GuardDuty, Inspector, Macie, Config
   - S3-based export + Lambda processor
   - Multi-account via AssumeRole
   - **Effort**: 3 weeks
   - **Value**: Completes "Big 3" cloud provider coverage

#### Phase 2: Identity Providers (High ROI)

**Priority Order**:
1. **Okta** (4 weeks)
   - System Log API for auth events
   - User provisioning/deprovisioning
   - MFA anomalies
   - **Market coverage**: 45% of SMB/SME

2. **Azure Active Directory** (3 weeks)
   - Microsoft Graph API (already have msgraph_connector.py)
   - Sign-in logs, audit logs
   - Conditional Access policy changes
   - **Market coverage**: 60% of SMB/SME

3. **Google Workspace** (3 weeks)
   - Admin SDK Reports API
   - Login events, admin activities
   - Drive file sharing
   - **Market coverage**: 30% of SMB/SME

#### Phase 3: SaaS Application Connectors

**Tier 1 (Most Requested)**:
1. **Salesforce** (5 weeks)
   - EventLogFile API
   - Login events, data exports
   - Permission changes
   - **Justification**: Critical for sales/CRM data protection

2. **ServiceNow** (4 weeks)
   - Audit logs, incident tickets
   - Privilege escalation detection
   - **Justification**: ITSM correlation

3. **Box / Dropbox** (3 weeks each)
   - File sharing events
   - External collaborator tracking
   - **Justification**: Data exfiltration detection

**Tier 2 (Future)**:
- Slack, Microsoft Teams (collaboration)
- GitHub, GitLab (code repository)
- Jira, Confluence (dev tools)

#### Data Extraction Methods by Connector Type

| Connector Type | Extraction Method | Frequency | Complexity |
|----------------|-------------------|-----------|------------|
| Cloud CSPM | Event Hub / Pub/Sub (push) | Real-time | Low |
| Cloud Audit | S3 / Storage Bucket (pull) | 5-15 min | Medium |
| Identity Provider | REST API polling (pull) | 1-5 min | Low |
| Email (OAuth) | Delta query (pull) | 5-15 min | Medium |
| SaaS Apps | Webhook (push) or REST API (pull) | Varies | Medium-High |
| Network | Syslog/NetFlow (push) | Real-time | Low |
| Endpoint | Agent integration (push) | Real-time | High |

**Recommended Approach**:
- **Push (real-time)**: Cloud events, network logs, endpoint telemetry
- **Pull (polling)**: SaaS apps, email, identity providers
- **Batch**: Forensic exports (KAPE, cloud billing)

#### Implementation Effort vs Value

```
High Value
    │
    │  Azure Defender ✓    AWS Security Hub
    │  Google SCC ✓        Okta
    │                      Azure AD
    │
    │  Salesforce          GCP Asset ✓
    │  ServiceNow
    │
    │                      Box/Dropbox
    │  Slack/Teams         GitHub/GitLab
    │
Low Value
    └──────────────────────────────────── Effort ───────────────►
       Low                                              High
```

**Prioritization Matrix**:
1. **High Value, Low Effort**: AWS Security Hub, Azure AD (NEXT)
2. **High Value, Medium Effort**: Okta, GCP Asset (IN PROGRESS)
3. **Medium Value, Medium Effort**: Salesforce, ServiceNow (DEFER 3 months)
4. **Low Value, High Effort**: Slack/Teams, GitHub (DEFER 6 months)

### Recommended Roadmap: **Complete Big 3 Cloud (Next 2 Months)**
- **Week 1-2**: Finish GCP Asset Inventory
- **Week 3-5**: AWS Security Hub connector
- **Week 6-8**: Okta integration
- **Week 9-11**: Azure AD deep integration
- **Week 12+**: Salesforce (if customer demand warrants)

**Justification**: Cloud CSPM + Identity covers 80% of SMB/SME security blind spots. SaaS apps are lower priority until customer base scales.

---

## Recommended Product Roadmap (Next 6 Months)

### Q1 2025 (January - March): Production Hardening

**Week 1-2: Critical Fixes (P0)**
- [ ] Add scipy to requirements.txt
- [ ] Create extended LOLBins catalog (`data/lolbins.yaml` with 200+ entries)
- [ ] Document OAuth2 setup guide for email connectors
- [ ] Performance testing: 1K events/sec sustained load

**Week 3-5: AWS Security Hub (P0)**
- [ ] Lambda function for Security Hub findings
- [ ] S3 export processor for historical data
- [ ] Multi-account AssumeRole support
- [ ] Posture API integration

**Week 6-8: Tiered Storage (P0)**
- [ ] Implement 3-tier storage (hot/warm/cold)
- [ ] Per-tenant quota manager
- [ ] Automatic archival scheduler
- [ ] Legal hold and deletion APIs

**Week 9-11: GCP Completion + Okta (P1)**
- [ ] Finish GCP Asset Inventory (remaining 20%)
- [ ] Okta System Log API integration
- [ ] MFA anomaly detection
- [ ] User provisioning/deprovisioning alerts

**Week 12-13: KAPE Detection (P1)**
- [ ] Endpoint factor: `kape_execution_detected`
- [ ] Correlation rules (suspicious launch, credential theft)
- [ ] CSV upload support for KAPE timelines
- [ ] Documentation and marketing materials

### Q2 2025 (April - June): Enterprise Features

**Week 14-17: Azure AD Deep Integration (P1)**
- [ ] Leverage existing msgraph_connector.py
- [ ] Sign-in logs with risk detection
- [ ] Conditional Access policy monitoring
- [ ] Privileged role assignment alerts

**Week 18-21: Advanced Pipeline Stages (P1)**
- [ ] Complete eBPF analysis stage (requires Falco)
- [ ] PCAP session reconstruction (basic)
- [ ] ML model scoring (requires training data)
- [ ] YARA scanning integration

**Week 22-25: Performance and Scale (P0)**
- [ ] Performance testing: 5K-10K events/sec
- [ ] Horizontal scaling validation (multi-node k8s)
- [ ] Database optimization (partitioning, indexes)
- [ ] Grafana dashboards for all metrics

**Week 26: Q2 Release Candidate**
- [ ] End-to-end testing with pilot customers
- [ ] Documentation complete (deployment, operations, API)
- [ ] Marketing collateral (datasheets, whitepapers)

### Q3 2025 (July - September): Market Expansion

**SaaS Connectors (Customer-Driven)**:
- [ ] Salesforce (if 3+ customer requests)
- [ ] ServiceNow (if 3+ customer requests)
- [ ] Box/Dropbox (if 2+ customer requests)

**Advanced Detections**:
- [ ] BEC supplier portal takeover (production-ready)
- [ ] Ransomware family detection (TTP-based)
- [ ] Insider threat scoring (behavioral analytics)

**Enterprise Tier Features**:
- [ ] AS Path Anomaly Detection (lightweight BGP)
- [ ] SOAR integration (Palo Alto XSOAR, Splunk Phantom)
- [ ] Custom playbook builder (no-code)

---

## Resource Requirements and Budget

### Engineering Team Allocation (Next 6 Months)

**Team Composition**:
- 2 Backend Engineers (Python, FastAPI, SQLite/Postgres)
- 1 Frontend Engineer (React, JavaScript, HTML/CSS)
- 1 DevOps/SRE (Kubernetes, CI/CD, observability)
- 0.5 Security Researcher (detection rules, threat intelligence)

**Time Allocation**:
| Phase | Duration | Backend | Frontend | DevOps | Security | Total Person-Weeks |
|-------|----------|---------|----------|--------|----------|---------------------|
| Q1 Critical Fixes | 2 weeks | 4 | 0 | 1 | 0 | 5 |
| Q1 AWS Security Hub | 3 weeks | 6 | 0 | 1.5 | 0 | 7.5 |
| Q1 Tiered Storage | 3 weeks | 6 | 0 | 1.5 | 0 | 7.5 |
| Q1 GCP + Okta | 3 weeks | 6 | 0 | 1.5 | 1 | 8.5 |
| Q1 KAPE Detection | 2 weeks | 3 | 0.5 | 0 | 1 | 4.5 |
| Q2 Azure AD | 4 weeks | 8 | 0 | 2 | 0 | 10 |
| Q2 Pipeline Stages | 4 weeks | 8 | 2 | 2 | 2 | 14 |
| Q2 Performance | 4 weeks | 4 | 0 | 6 | 0 | 10 |
| Q2 Release Prep | 1 week | 2 | 1 | 1 | 0.5 | 4.5 |
| **Q1-Q2 Total** | **26 weeks** | **47** | **3.5** | **17** | **4.5** | **72 person-weeks** |

### Budget Estimate (6 Months)

**Personnel** (US rates):
- Backend Engineer: $160K/year → $80K for 6 months × 2 = $160K
- Frontend Engineer: $140K/year → $70K for 6 months × 1 = $70K
- DevOps/SRE: $150K/year → $75K for 6 months × 1 = $75K
- Security Researcher (part-time): $130K/year → $32.5K for 6 months × 0.5 = $32.5K
- **Total Personnel**: $337.5K

**Infrastructure** (development + staging + production):
- Cloud hosting (AWS/Azure/GCP): $3K/month × 6 = $18K
- CI/CD (GitHub Actions, CircleCI): $500/month × 6 = $3K
- Monitoring (Grafana Cloud, Datadog): $1K/month × 6 = $6K
- LLM APIs (OpenAI, Anthropic testing): $2K/month × 6 = $12K
- **Total Infrastructure**: $39K

**External Services**:
- Threat Intelligence feeds (VirusTotal, AbuseIPDB): $5K
- GeoIP databases (MaxMind): $1K
- Legal/compliance review: $10K
- **Total External**: $16K

**Grand Total (6 Months)**: **$392.5K**

**Per Month**: $65.4K

---

## Competitive Positioning and Differentiation

### JanuSec vs Existing Players

| Feature | JanuSec | Splunk | Elastic SIEM | CrowdStrike | Microsoft Sentinel |
|---------|---------|--------|--------------|-------------|---------------------|
| Multi-Domain Ingestion | ✅ 8 domains | ✅ Unlimited | ✅ Unlimited | ❌ Endpoint only | ✅ Azure-centric |
| HopGraph Correlation | ✅ BFS JOIN | ❌ SPL queries | ❌ EQL queries | ✅ Falcon Graph | ✅ Entity graph |
| 2-Tier LLM Summaries | ✅ T1 + T2 | ❌ Manual | ❌ Manual | ❌ Manual | ⚠️ Copilot (limited) |
| KAPE Detection | ✅ Unique | ❌ No | ❌ No | ❌ No | ❌ No |
| Cloud CSPM | ✅ 3 providers | ⚠️ Via apps | ⚠️ Via beats | ❌ No | ✅ Azure only |
| Pricing (per GB/day) | $5-15 | $50-150 | $20-80 | $8-25/endpoint | $2-5 (Azure data) |
| Self-Hosted Option | ✅ Yes | ✅ Yes | ✅ Yes | ❌ SaaS only | ❌ SaaS only |

**Differentiation Pillars**:
1. **AI-Native**: 2-tier LLM summaries reduce analyst workload by 60%
2. **Graph-First**: HopGraph attack reconstruction vs query-based correlation
3. **Cost-Effective**: $5-15/GB vs $50-150/GB (Splunk)
4. **Multi-Cloud**: Native Azure, GCP, AWS integrations (not Azure-only like Sentinel)
5. **KAPE Detection**: Unique threat hunting capability (detect KAPE misuse)

### Target Customer Segments

**Segment 1: SMB Security Teams (100-500 employees)**
- **Pain Point**: Can't afford Splunk ($50K-200K/year)
- **JanuSec Fit**: Essential tier ($5K-20K/year), 3 domains (Network, Endpoint, Email)
- **Differentiation**: LLM summaries reduce need for expensive SOC analysts

**Segment 2: Mid-Market with Cloud-First (500-1,000 employees)**
- **Pain Point**: Microsoft Sentinel is Azure-only, lacks multi-cloud
- **JanuSec Fit**: Professional tier ($20K-80K/year), 5 domains (+Identity, Cloud)
- **Differentiation**: Native GCP and AWS support, not just Azure

**Segment 3: Regulated Industries (Finance, Healthcare)**
- **Pain Point**: Compliance requirements (HIPAA, PCI-DSS) for log retention
- **JanuSec Fit**: Enterprise tier ($80K-300K/year), tiered storage for cost control
- **Differentiation**: Legal hold, per-tenant data residency, audit trails

---

## Pricing Strategy (Recommended)

### Tiered Pricing Model

**Essential Tier** ($5K-20K/year):
- 100-500 employees
- 3 domains: Network, Endpoint, Email
- 50 GB hot + 200 GB warm + 500 GB cold
- 90-day retention
- Community support

**Professional Tier** ($20K-80K/year):
- 500-1,000 employees
- 5 domains: +Identity, Cloud
- 200 GB hot + 1 TB warm + 5 TB cold
- 180-day retention
- Email + chat support
- 2-Tier LLM (200 events/month)

**Enterprise Tier** ($80K-300K/year):
- 1,000-5,000+ employees
- 8 domains: All domains
- 1 TB hot + 10 TB warm + 50 TB cold
- 365-day retention
- 24/7 phone support
- Unlimited LLM analysis
- Custom playbooks
- Advanced detections (BGP, SOAR)
- Multi-tenant management

**Add-Ons**:
- Additional LLM analysis: $0.02/event (Tier 1), $0.05/event (Tier 2)
- Professional services: $200/hour
- Custom connector development: $10K-25K per connector
- Managed detection and response (MDR): +50% annual fee

---

## Success Metrics and KPIs

### Product Metrics (6 Months)
- [ ] 95% uptime SLA for event ingestion
- [ ] <5 second p99 latency for Tier 1 LLM summaries
- [ ] <15 second p99 latency for Tier 2 LLM summaries
- [ ] 5K-10K events/sec sustained throughput
- [ ] <5% false positive rate on correlation rules
- [ ] 90%+ customer satisfaction (NPS > 50)

### Business Metrics (6 Months)
- [ ] 10 pilot customers signed (Essential + Professional tiers)
- [ ] $100K ARR (Annual Recurring Revenue)
- [ ] 3 case studies published
- [ ] 2 industry conference presentations
- [ ] 1 security vendor partnership (EDR or CSPM)

### Engineering Metrics (6 Months)
- [ ] 80%+ test coverage (unit + integration)
- [ ] <1% critical bug escape rate
- [ ] <24 hour mean-time-to-fix (MTTF) for P0 issues
- [ ] 100% documentation coverage for APIs
- [ ] 2 week sprint velocity (8-10 story points/sprint)

---

## Risk Analysis and Mitigation

### Technical Risks

**Risk 1: LLM API Outages**
- **Probability**: Medium (5% monthly)
- **Impact**: High (no Tier 2 summaries)
- **Mitigation**: Deterministic fallback mode, multi-provider (OpenAI + Anthropic + Ollama)

**Risk 2: Performance at Scale (10K+ events/sec)**
- **Probability**: High (untested at this scale)
- **Impact**: High (lost events, customer churn)
- **Mitigation**: Load testing in Q2, horizontal scaling validation, backpressure handling

**Risk 3: Data Loss During Archival**
- **Probability**: Low (2%)
- **Impact**: Critical (compliance violation)
- **Mitigation**: Atomic writes, checksum validation, backup before archival

### Business Risks

**Risk 1: Competitive Response (Splunk, Elastic lower pricing)**
- **Probability**: Medium (30% in next 12 months)
- **Impact**: High (price war)
- **Mitigation**: Focus on differentiation (LLM, HopGraph, KAPE), not just price

**Risk 2: Slow Customer Adoption (Sales Cycle >6 months)**
- **Probability**: High (typical for enterprise security)
- **Impact**: Medium (delayed revenue)
- **Mitigation**: Pilot programs, free trials, proof-of-value in 30 days

**Risk 3: Data Residency Regulations (GDPR, CCPA)**
- **Probability**: Medium (25% of customers affected)
- **Impact**: Medium (per-region deployment required)
- **Mitigation**: Multi-region support (US, EU, APAC), customer-managed keys

---

## Recommendations and Decision Points

### Decision Point 1: KAPE Integration Strategy
**Options**:
- A) Detect KAPE execution (2 weeks, high differentiation)
- B) Parse KAPE output (3 weeks, medium value)
- C) User snapshot capability (4 weeks, high effort)

**Recommendation**: **A + B (5 weeks total)** - Detect KAPE misuse AND support KAPE CSV upload for correlation. Defer user snapshot to Q3.

**CEO Approval**: ☐ Approved ☐ Rejected ☐ Modify

---

### Decision Point 2: BGP Poisoning Detection
**Options**:
- A) Full BGP feed integration (8 weeks, 5% market coverage)
- B) Lightweight AS path anomaly (2 weeks, table stakes)
- C) Defer to Enterprise tier (0 weeks, focus on high-ROI detections)

**Recommendation**: **C (Defer to Enterprise)** - Add lightweight AS path anomaly in Q3 if customer demand warrants. Focus Q1-Q2 on high-probability threats (phishing, lateral movement, cloud misconfig).

**CEO Approval**: ☐ Approved ☐ Rejected ☐ Modify

---

### Decision Point 3: Data Retention Strategy
**Options**:
- A) All hot storage (simple, expensive)
- B) 2-tier (hot + cold, medium complexity)
- C) 3-tier (hot + warm + cold, optimal cost)

**Recommendation**: **C (3-tier)** - Implement hot (7d) + warm (30d) + cold (365d) with per-tenant quotas. 60-70% cost savings vs all-hot.

**CEO Approval**: ☐ Approved ☐ Rejected ☐ Modify

---

### Decision Point 4: Connector Roadmap Priority
**Options**:
- A) Cloud-first (AWS Security Hub → Okta → Azure AD)
- B) SaaS-first (Salesforce → ServiceNow → Box)
- C) Balanced (Cloud + Identity simultaneously)

**Recommendation**: **A (Cloud-first)** - Complete "Big 3" cloud providers (Azure ✓, GCP ✓, AWS next), then add Okta/Azure AD for identity. SaaS apps deferred to Q3 based on customer demand.

**CEO Approval**: ☐ Approved ☐ Rejected ☐ Modify

---

### Decision Point 5: Budget Allocation
**6-Month Budget**: $392.5K ($65.4K/month)
- Personnel: $337.5K
- Infrastructure: $39K
- External Services: $16K

**Recommendation**: **Approve full budget** - Lean team (4.5 FTE) focused on high-ROI features. Deferring any component risks missing market window.

**CEO Approval**: ☐ Approved ☐ Rejected ☐ Modify (specify budget cap: $__________)

---

## Appendix: GCP and Azure Next Steps

### GCP Asset Inventory (In Progress - 80% Complete)

**Remaining Work** (2 weeks):
1. **Service Account Credentials**:
   - [ ] Document setup guide for GCP service account JSON
   - [ ] Key rotation automation
   - [ ] Workload Identity support (GKE)

2. **Resource Enumeration**:
   - [ ] Add pagination for large projects (>1000 resources)
   - [ ] Filter by asset types (compute, storage, IAM)
   - [ ] Delta sync (only changed resources)

3. **Configuration Drift**:
   - [ ] Baseline snapshot storage
   - [ ] Drift detection rules (IAM changes, firewall rules, storage ACLs)
   - [ ] Alert on critical drifts

4. **Testing**:
   - [ ] Multi-project testing (3+ GCP projects)
   - [ ] Performance test (5K+ resources)
   - [ ] Integration test with posture API

**Deployment**:
```bash
# Install dependencies
pip install google-cloud-asset tenacity

# Configure service account
export GCP_CREDENTIALS_JSON=/path/to/service-account.json
export GCP_PROJECT_ID=my-project-123

# Run collector
python src/collectors/cloud_gcp_asset_adapter.py
```

### Azure Defender Enhancements (Future)

**Phase 1 Complete** ✅:
- Event Hub ingestion
- Posture finding normalization
- DLQ and retry logic

**Phase 2** (Q2 2025):
- [ ] Defender for Storage (blob access anomalies)
- [ ] Defender for SQL (injection attempts)
- [ ] Defender for Key Vault (secret access patterns)
- [ ] Defender for Containers (runtime threats)

**Phase 3** (Q3 2025):
- [ ] Secure Score tracking (monthly trends)
- [ ] Recommendation remediation automation
- [ ] Cost optimization insights

---

## Conclusion and Next Steps

**Strategic Positioning**: JanuSec focuses on **high-probability, high-impact threats** (phishing, lateral movement, cloud misconfig) that affect 95% of our target market (100-5,000 employee orgs). Advanced/niche detections (BGP poisoning, advanced network protocols) are reserved for Enterprise tier.

**Data Management**: **3-tier storage** (hot/warm/cold) with **per-tenant quotas** provides 60-70% cost savings while meeting compliance requirements (GDPR, HIPAA, PCI-DSS).

**Connector Strategy**: **Cloud-first** approach completes "Big 3" cloud providers (Azure ✓, GCP ✓, AWS next), then identity (Okta, Azure AD), then SaaS apps (Salesforce, ServiceNow) based on customer demand.

**KAPE Differentiation**: **Detect KAPE misuse** (not just parse output) + **correlate KAPE artifacts** with live telemetry for complete attack timelines. This is unique in the market.

**6-Month Budget**: **$392.5K** for lean team (4.5 FTE) to deliver production-ready platform with 10 pilot customers and $100K ARR.

**CEO Decisions Required**:
1. Approve KAPE detection strategy (Detect + Parse, defer User Snapshot)
2. Approve BGP deferral to Enterprise tier (focus on high-ROI detections)
3. Approve 3-tier storage with per-tenant quotas
4. Approve cloud-first connector roadmap
5. Approve 6-month budget ($392.5K)

**Immediate Next Steps** (Week 1):
- [ ] CEO approval on 5 decision points above
- [ ] Hire 0.5 FTE Security Researcher (start Q1)
- [ ] Begin AWS Security Hub connector (3-week sprint)
- [ ] Finalize GCP Asset Inventory (2-week sprint)
- [ ] Performance testing plan (5K-10K events/sec target)

---

**Prepared by**: JanuSec Engineering Team
**Last Updated**: December 23, 2025
**Version**: 1.0
**Status**: Awaiting CEO Approval
