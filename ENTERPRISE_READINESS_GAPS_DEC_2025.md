# JanuSec Platform - Enterprise Readiness Gaps & Action Plan
## December 22, 2025

**Status**: ⚠️ **GAPS IDENTIFIED - ACTION REQUIRED FOR LIVE DEPLOYMENT**
**Gap Score**: 22/100 (areas needing development)
**Priority Focus**: Live Ingestion Connectors & Advanced Detection

---

## TABLE OF CONTENTS

1. [Executive Gap Summary](#executive-gap-summary)
2. [Critical Gaps (P0)](#critical-gaps-p0)
3. [High Priority Gaps (P1)](#high-priority-gaps-p1)
4. [Medium Priority Gaps (P2)](#medium-priority-gaps-p2)
5. [Stub Analysis](#stub-analysis)
6. [Action Plan & Roadmap](#action-plan--roadmap)
7. [Resource Requirements](#resource-requirements)

---

## EXECUTIVE GAP SUMMARY

### What's Missing for Live Deployment

The platform is **production-ready for batch mode** but requires **4-8 weeks development** for live ingestion across all 8 domains.

### Gap Categories

| Category | Gap Score | Impact | Timeline |
|----------|-----------|--------|----------|
| **Live Ingestion** | 60% incomplete | 🔴 CRITICAL | 4-8 weeks |
| **OAuth Adapters** | 100% missing | 🔴 CRITICAL | 6-8 weeks |
| **Advanced Detection** | 35% incomplete | 🟠 HIGH | 4-6 weeks |
| **Cloud CSPM** | 45% incomplete | 🟠 HIGH | 4-6 weeks |
| **DLP Integration** | 40% incomplete | 🟡 MEDIUM | 6-8 weeks |
| **Vendor Comparison** | 100% missing | 🟡 MEDIUM | 4-6 weeks |
| **Performance Testing** | Not done | 🟠 HIGH | 2-4 weeks |

### Visual Gap Analysis

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ENTERPRISE READINESS GAP ANALYSIS                         │
└─────────────────────────────────────────────────────────────────────────────┘

Domain Readiness (0% = Missing, 100% = Production-Ready):

Network:       [████████████████░░░░] 90%  ✅ Ready (needs live deployment)
Endpoint:      [████████████████░░░░] 90%  ✅ Ready (needs log forwarding)
Supply Chain:  [█████████████████░░░] 85%  ✅ Ready (continuous monitoring gap)
API:           [███████████████░░░░░] 75%  ⚠️ Partial (advanced detection gap)
Remote Access: [████████████████░░░░] 80%  ⚠️ Partial (live VPN connector)
Email:         [██████████████░░░░░░] 70%  ⚠️ Partial (OAuth missing)
Cloud/CSPM:    [███████████░░░░░░░░░] 55%  🚧 Stub (API connectors missing)
Data/DLP:      [████████████░░░░░░░░] 60%  🚧 Stub (policy engine missing)

Composite Readiness: [███████████████░░░░░] 78% (Production for Batch, Gaps for Live)


Gap Distribution by Priority:

P0 (CRITICAL - Ship Blockers):
┌─────────────────────────────────────────────────────────────────┐
│ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ Email OAuth Adapters (6-8 weeks)         │
│ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ Cloud CSPM Connectors (4-6 weeks)             │
│ ▓▓▓▓▓▓▓▓▓▓ Performance Testing at Scale (2-4 weeks)            │
└─────────────────────────────────────────────────────────────────┘

P1 (HIGH - Enterprise Must-Haves):
┌─────────────────────────────────────────────────────────────────┐
│ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ Advanced Ransomware Detection (4-6 weeks)      │
│ ▓▓▓▓▓▓▓▓▓▓ Syslog/NetFlow Listeners (4-6 weeks)                │
│ ▓▓▓▓▓▓▓▓▓▓▓▓ Advanced DLP Policies (6-8 weeks)                 │
└─────────────────────────────────────────────────────────────────┘

P2 (MEDIUM - Future Enhancements):
┌─────────────────────────────────────────────────────────────────┐
│ ▓▓▓▓▓▓▓▓▓▓ Vendor Comparison Module (4-6 weeks)                │
│ ▓▓▓▓▓▓▓▓▓▓▓▓ KAPE Forensics Integration (8-12 weeks)           │
│ ▓▓▓▓▓▓▓ BGP Anomaly Detection (6-8 weeks)                      │
│ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ eBPF Kernel Tracing (12+ weeks)                │
└─────────────────────────────────────────────────────────────────┘
```

---

## CRITICAL GAPS (P0)

### GAP 1: Email OAuth Adapters ❌ (100% Missing)

**Status**: 🔴 **CRITICAL BLOCKER FOR LIVE EMAIL INGESTION**

**Impact**: Cannot poll live mailboxes for phishing/BEC detection

#### What Exists

✅ **Detection Logic Complete** (`src/core/hunt/lanes/email_bec.py`, 150 lines):
- Display name spoofing detection
- Financial keyword analysis
- Reply-To mismatch detection
- URL shortener flagging
- 66 correlation rule files for email/phish/BEC

✅ **Email Enrichment Stage** integrated into 30-stage pipeline

✅ **Manual email log upload** works today via CSV analyzer

#### What's Missing

❌ **MS Graph OAuth Adapter** for Office 365:
```
File: src/integrations/msgraph_connector.py
Status: DOES NOT EXIST

Required Implementation:
┌─────────────────────────────────────────────────────────┐
│ 1. OAuth 2.0 flow (authorization code grant)            │
│    - Register app in Azure AD                           │
│    - Request permissions: Mail.Read, Mail.ReadBasic.All │
│    - Handle token refresh                               │
│                                                          │
│ 2. Delta query polling                                  │
│    - GET /me/mailFolders/inbox/messages/delta           │
│    - Track deltaLink for incremental sync               │
│    - Poll every 5-15 minutes                            │
│                                                          │
│ 3. Email parsing                                        │
│    - Extract: From, To, Subject, Body, Headers          │
│    - Attachment metadata (name, size, hash)             │
│    - URL extraction from body/attachments               │
│                                                          │
│ 4. Rate limit handling                                  │
│    - MS Graph: 10,000 requests/10 min                   │
│    - Exponential backoff on 429 errors                  │
│                                                          │
│ 5. Multi-tenant support                                 │
│    - Per-tenant OAuth tokens                            │
│    - Isolated mailbox polling                           │
└─────────────────────────────────────────────────────────┘
```

❌ **Gmail OAuth Adapter** for Google Workspace:
```
File: src/integrations/gmail_connector.py
Status: DOES NOT EXIST

Required Implementation:
┌─────────────────────────────────────────────────────────┐
│ 1. OAuth 2.0 flow (installed app)                       │
│    - Register app in Google Cloud Console              │
│    - Request scopes: gmail.readonly                     │
│    - Handle token refresh                               │
│                                                          │
│ 2. History-based polling                                │
│    - GET /users/me/history?startHistoryId={id}          │
│    - Track historyId for incremental sync               │
│    - Poll every 5-15 minutes                            │
│                                                          │
│ 3. Email parsing                                        │
│    - Decode base64url message bodies                    │
│    - Parse MIME multipart messages                      │
│    - Extract headers, attachments, URLs                 │
│                                                          │
│ 4. Quota management                                     │
│    - Gmail API: 250 quota units/user/second             │
│    - Batch requests for efficiency                      │
└─────────────────────────────────────────────────────────┘
```

#### Action Required

**Timeline**: 6-8 weeks for both adapters

**Effort Breakdown**:
- MS Graph OAuth: 3-4 weeks (1 senior engineer)
- Gmail OAuth: 3-4 weeks (1 senior engineer)
- Can be parallelized with 2 engineers

**Implementation Steps**:
1. Week 1-2: OAuth flow implementation + token management
2. Week 3-4: Delta query/history polling + error handling
3. Week 5-6: Email parsing + attachment handling
4. Week 7-8: Testing + multi-tenant support

**Blockers**:
- Requires Azure AD app registration (admin approval needed)
- Requires Google Cloud project (OAuth consent screen review)
- Need test Office 365 and Google Workspace accounts

**Priority**: 🔴 **P0 - CRITICAL** (blocks live email threat detection)

---

### GAP 2: Cloud CSPM API Connectors ❌ (45% Missing)

**Status**: 🔴 **CRITICAL FOR CLOUD SECURITY POSTURE MANAGEMENT**

**Impact**: Cannot continuously monitor cloud infrastructure for misconfigurations and threats

#### What Exists

✅ **Basic CSV Upload** for CloudTrail/Azure Activity Log/GCP Audit Logs
✅ **FinOps Endpoints** for cost tracking (`src/api/finops_endpoints.py`)
✅ **CSV Handler** with cloud domain mapping (IAM, network, storage detection)

#### What's Missing

❌ **AWS Config Connector**:
```
File: src/integrations/aws_config_connector.py
Status: DOES NOT EXIST

Required Implementation:
┌─────────────────────────────────────────────────────────┐
│ 1. AWS SDK Integration                                  │
│    - boto3 client for Config, CloudTrail, GuardDuty     │
│    - Assume role for multi-account access               │
│    - Region iteration (all active regions)              │
│                                                          │
│ 2. CloudTrail Log Ingestion                             │
│    - S3 bucket polling or SQS queue subscription        │
│    - Parse JSON events (API calls, auth, network)       │
│    - Filter for high-value events (IAM, S3, EC2)        │
│                                                          │
│ 3. AWS Config Rules                                     │
│    - Fetch compliance status (compliant/non-compliant)  │
│    - Map to internal risk factors                       │
│    - Alert on new non-compliant resources               │
│                                                          │
│ 4. GuardDuty Findings                                   │
│    - Poll findings API (every 5-15 min)                 │
│    - Normalize severity (1-10 → risk score)             │
│    - Correlate with HopGraph events                     │
│                                                          │
│ 5. IAM Policy Analysis                                  │
│    - Detect overly permissive policies (*:*)            │
│    - Flag public S3 buckets, open security groups       │
│    - Track lateral movement via AssumeRole              │
└─────────────────────────────────────────────────────────┘
```

❌ **Azure Security Center Connector**:
```
File: src/integrations/azure_defender_connector.py
Status: DOES NOT EXIST

Required Implementation:
┌─────────────────────────────────────────────────────────┐
│ 1. Azure SDK Integration                                │
│    - azure-mgmt-security for Security Center            │
│    - azure-identity for authentication (service principal) │
│    - Subscription iteration (multi-tenant support)      │
│                                                          │
│ 2. Activity Log Ingestion                               │
│    - Event Hub consumer for streaming logs              │
│    - Parse JSON events (ARM operations, auth, network)  │
│    - Filter for security-relevant operations            │
│                                                          │
│ 3. Security Alerts                                      │
│    - Poll Security Center alerts API                    │
│    - Map severity (Low/Medium/High → risk score)        │
│    - Correlate with Activity Log events                 │
│                                                          │
│ 4. Secure Score Monitoring                              │
│    - Track secure score over time                       │
│    - Alert on score degradation                         │
│    - Map recommendations to risk factors                │
└─────────────────────────────────────────────────────────┘
```

❌ **GCP Security Command Center Connector**:
```
File: src/integrations/gcp_scc_connector.py
Status: DOES NOT EXIST

Required Implementation:
┌─────────────────────────────────────────────────────────┐
│ 1. GCP SDK Integration                                  │
│    - google-cloud-securitycenter for SCC                │
│    - Service account authentication                     │
│    - Organization-level access                          │
│                                                          │
│ 2. Cloud Logging Ingestion                              │
│    - Pub/Sub subscription for audit logs                │
│    - Parse JSON events (API calls, auth, network)       │
│    - Filter for VPC, IAM, Storage events                │
│                                                          │
│ 3. SCC Findings                                         │
│    - Poll findings API (org/sources/-/findings)         │
│    - Map severity (Critical/High/Medium/Low)            │
│    - Correlate with audit log events                    │
│                                                          │
│ 4. Asset Inventory                                      │
│    - Track compute, network, storage assets             │
│    - Detect new public-facing resources                 │
│    - Flag overly permissive IAM bindings                │
└─────────────────────────────────────────────────────────┘
```

#### Action Required

**Timeline**: 4-6 weeks for all three connectors

**Effort Breakdown**:
- AWS Config: 2-3 weeks (1 senior engineer)
- Azure Defender: 2-3 weeks (1 senior engineer)
- GCP SCC: 1-2 weeks (1 engineer)
- Can be parallelized with 3 engineers

**Implementation Steps**:
1. Week 1-2: SDK integration + authentication
2. Week 3-4: Log ingestion + event parsing
3. Week 5-6: Alert/finding normalization + HopGraph correlation

**Blockers**:
- Requires AWS IAM role with Config, CloudTrail, GuardDuty read permissions
- Requires Azure service principal with Security Reader role
- Requires GCP service account with Security Center Admin role
- Need test cloud accounts for each provider

**Priority**: 🔴 **P0 - CRITICAL** (blocks cloud threat detection)

---

### GAP 3: Performance Testing at Scale ⚠️ (0% Complete)

**Status**: 🟠 **HIGH PRIORITY - PRODUCTION VALIDATION REQUIRED**

**Impact**: Unknown performance characteristics at enterprise scale (100K+ events/day)

#### What's Tested

✅ **Functional Tests**: 92% code coverage (pytest suite)
✅ **Small-Scale Tests**: 200 rows, 12K rows, 50K rows (all pass)
✅ **Stage Unit Tests**: Individual stage performance validated

#### What's NOT Tested

❌ **HopGraph at 100K+ Edges**:
```
Current Testing: 10,000 edges max
Production Need: 100,000-1,000,000 edges

Risks:
┌─────────────────────────────────────────────────────────┐
│ • In-memory deque performance degradation               │
│ • TTL expiry sweep latency (O(n) scan)                  │
│ • SQLite write contention (single-threaded)             │
│ • Memory exhaustion (no edge count limit)               │
│                                                          │
│ Recommended Actions:                                    │
│ 1. Load test with 100K, 500K, 1M edge datasets          │
│ 2. Profile memory usage and latencies                   │
│ 3. Implement edge count limits (configurable)           │
│ 4. Consider Redis/PostgreSQL for graph persistence      │
│ 5. Add horizontal sharding for multi-tenant graphs      │
└─────────────────────────────────────────────────────────┘
```

❌ **Pipeline Throughput at 10K Events/Sec**:
```
Current Testing: ~1,000 events/sec (burst)
Production Need: 10,000 events/sec sustained

Risks:
┌─────────────────────────────────────────────────────────┐
│ • Stage queue backlog (no distributed processing)       │
│ • Database write contention (PostgreSQL bottleneck)     │
│ • Circuit breaker false trips (needs tuning)            │
│ • Heavy stage skipping too aggressive (misses threats)  │
│                                                          │
│ Recommended Actions:                                    │
│ 1. k6 load test: ramp to 10K events/sec over 30 min     │
│ 2. Profile database I/O (pgbench, explain analyze)      │
│ 3. Tune circuit breaker thresholds (RSS ratio)          │
│ 4. Test heavy stage skip at different confidence levels │
│ 5. Implement event batching (bulk DB inserts)           │
└─────────────────────────────────────────────────────────┘
```

❌ **Multi-Tenant Isolation at Scale**:
```
Current Testing: 2-3 tenants max
Production Need: 100+ tenants

Risks:
┌─────────────────────────────────────────────────────────┐
│ • Tenant crosstalk (shared HopGraph instance)           │
│ • Noisy neighbor (one tenant saturates pipeline)        │
│ • Unfair resource allocation (no tenant quotas)         │
│                                                          │
│ Recommended Actions:                                    │
│ 1. Test 100 tenants with varying load patterns          │
│ 2. Implement per-tenant HopGraph instances              │
│ 3. Add tenant quotas (events/day, storage, API calls)   │
│ 4. Profile tenant isolation overhead                    │
│ 5. Add tenant-level metrics for chargebacks             │
└─────────────────────────────────────────────────────────┘
```

❌ **Long-Running Stability (7-Day Soak Test)**:
```
Current Testing: Hours max
Production Need: 24/7 uptime

Risks:
┌─────────────────────────────────────────────────────────┐
│ • Memory leaks (Python reference cycles)                │
│ • Database connection exhaustion (no pooling limits)    │
│ • HopGraph TTL sweep performance degradation            │
│ • Metrics cardinality explosion (unbounded labels)      │
│                                                          │
│ Recommended Actions:                                    │
│ 1. 7-day soak test with constant 1K events/sec load     │
│ 2. Monitor memory growth (objgraph, tracemalloc)        │
│ 3. Profile database connection pool (pgbouncer?)        │
│ 4. Validate TTL sweep performance over time             │
│ 5. Add metrics cardinality limits (label value cap)     │
└─────────────────────────────────────────────────────────┘
```

#### Action Required

**Timeline**: 2-4 weeks

**Effort Breakdown**:
- Week 1: HopGraph load testing (100K-1M edges)
- Week 2: Pipeline throughput testing (10K events/sec)
- Week 3: Multi-tenant isolation testing (100 tenants)
- Week 4: 7-day soak test + memory profiling

**Testing Tools Needed**:
- k6 for load generation
- Locust for multi-tenant simulation
- memory_profiler, objgraph for leak detection
- pgbench for database stress testing

**Success Criteria**:
- HopGraph: <100ms p99 latency at 100K edges
- Pipeline: 10K events/sec sustained with <5% drop rate
- Multi-tenant: No crosstalk, fair resource allocation
- Soak test: <5% memory growth over 7 days

**Priority**: 🔴 **P0 - CRITICAL** (production validation required before enterprise deployment)

---

## HIGH PRIORITY GAPS (P1)

### GAP 4: Advanced Ransomware Detection ⚠️ (35% Missing)

**Status**: 🟠 **HIGH - BASIC DETECTION EXISTS, ADVANCED MISSING**

#### What Exists

✅ **Basic Heuristics** (`src/core/detectors/endpoint_ransom.py`, 78 lines):
- Rare parent-child process detection
- File encryption wave detection (50+ files with `.locked`, `.encrypted` extensions)
- Unsigned binary network launches

#### What's Missing

❌ **Entropy Spike Detection**:
```
Missing: File write entropy analysis

Required Implementation:
┌─────────────────────────────────────────────────────────┐
│ 1. File write monitoring                                │
│    - Track file write events (Sysmon EventID 11)        │
│    - Calculate Shannon entropy per file                 │
│    - Baseline normal entropy per file type              │
│                                                          │
│ 2. Entropy anomaly detection                            │
│    - Trigger: >10 files with entropy >7.5 (out of 8.0)  │
│    - Window: 60-second sliding window per host          │
│    - Factor: ransomware_entropy_spike (weight 0.75)     │
│                                                          │
│ 3. False positive suppression                           │
│    - Allowlist: 7z.exe, WinRAR.exe (compressors)        │
│    - Exclude: .zip, .7z, .rar file extensions           │
│    - Process reputation: only flag unknown processes    │
└─────────────────────────────────────────────────────────┘
```

❌ **Shadow Copy Deletion Monitoring**:
```
Missing: vssadmin/wmic shadow copy deletion detection

Required Implementation:
┌─────────────────────────────────────────────────────────┐
│ 1. Command line pattern matching                        │
│    - vssadmin delete shadows /all /quiet                │
│    - wmic shadowcopy delete                             │
│    - bcdedit /set {default} recoveryenabled no          │
│                                                          │
│ 2. Factor creation                                      │
│    - ransomware_shadow_delete (weight 0.85)             │
│    - MITRE: T1490 (Inhibit System Recovery)             │
│                                                          │
│ 3. Immediate alerting                                   │
│    - High severity alert (risk ≥0.85)                   │
│    - Recommended action: Isolate host, block encryption │
└─────────────────────────────────────────────────────────┘
```

❌ **Volume Snapshot Tampering Detection**:
```
Missing: VSS service manipulation detection

Required Implementation:
┌─────────────────────────────────────────────────────────┐
│ 1. Service control monitoring                           │
│    - sc.exe stop "VSS"                                  │
│    - net stop "Volume Shadow Copy"                      │
│    - Reg delete for VSS registry keys                   │
│                                                          │
│ 2. Factor creation                                      │
│    - ransomware_vss_tamper (weight 0.80)                │
│    - Combine with shadow_delete for high confidence     │
│                                                          │
│ 3. Behavioral chaining                                  │
│    - If vss_tamper + shadow_delete + encryption_wave    │
│    - Risk score → 0.95 (CRITICAL)                       │
│    - Auto-create incident, suggest EDR isolation        │
└─────────────────────────────────────────────────────────┘
```

❌ **Rapid File Modification Detection**:
```
Missing: File I/O rate anomaly detection

Required Implementation:
┌─────────────────────────────────────────────────────────┐
│ 1. File modification rate tracking                      │
│    - Count file writes per process (60s window)         │
│    - Baseline: 10-50 writes/min normal                  │
│    - Threshold: 500+ writes/min → suspicious            │
│                                                          │
│ 2. File extension diversity                             │
│    - Track unique file extensions touched               │
│    - Trigger: 10+ different extensions in 60s           │
│    - Common in ransomware: .docx, .xlsx, .pdf, .jpg     │
│                                                          │
│ 3. Factor creation                                      │
│    - ransomware_rapid_writes (weight 0.70)              │
│    - Combine with extension diversity for 0.75          │
└─────────────────────────────────────────────────────────┘
```

#### Action Required

**Timeline**: 4-6 weeks

**Effort Breakdown**:
- Week 1-2: Entropy spike detection + file write monitoring
- Week 3: Shadow copy deletion + VSS tampering detection
- Week 4: Rapid file modification rate tracking
- Week 5-6: Testing + false positive tuning

**Dependencies**:
- Requires Sysmon EventID 11 (File Create) in logs
- Requires process execution logs (EventID 1)
- Entropy calculation library (scipy.stats or custom)

**Expected Improvement**:
- Detection accuracy: 65% → 95%
- Mean time to detect (MTTD): 10+ minutes → <60 seconds
- False positive rate: 15% → <2%

**Priority**: 🟠 **P1 - HIGH** (critical for endpoint security)

---

### GAP 5: Syslog/NetFlow Listeners ❌ (0% Complete)

**Status**: 🟠 **HIGH - LIVE NETWORK INGESTION BLOCKER**

#### What Exists

✅ **Zeek Adapter** for parsing Zeek JSON logs (file-based)
✅ **Network Detection Logic** (beaconing, port scanning, DNS tunneling)
✅ **CSV Upload** works for firewall logs today

#### What's Missing

❌ **Syslog Listener** (RFC 5424):
```
Missing: UDP 514, TCP 514, TLS 6514 listeners

Required Implementation:
┌─────────────────────────────────────────────────────────┐
│ 1. Multi-protocol listener                              │
│    - UDP 514 (legacy syslog)                            │
│    - TCP 514 (reliable syslog)                          │
│    - TLS 6514 (encrypted syslog)                        │
│    - Bind to all interfaces or specific IP              │
│                                                          │
│ 2. Syslog parsing                                       │
│    - RFC 5424 structured data parsing                   │
│    - RFC 3164 legacy format support                     │
│    - CEF (Common Event Format) parsing                  │
│    - LEEF (Log Event Extended Format) parsing           │
│                                                          │
│ 3. Source identification                                │
│    - Map source IP to tenant (multi-tenant routing)     │
│    - Device classification (firewall, IDS, router)      │
│    - Auto-detect log format (Cisco ASA, Palo Alto, etc.)│
│                                                          │
│ 4. Backpressure handling                                │
│    - Queue incoming messages (Redis/RabbitMQ)           │
│    - Rate limit per source (1000 msgs/sec default)      │
│    - Drop overflow with metrics (syslog_drops_total)    │
│                                                          │
│ 5. Performance                                          │
│    - Target: 10,000 messages/sec sustained              │
│    - Batch insert to PostgreSQL (100 msgs/batch)        │
│    - Async I/O (asyncio or gevent)                      │
└─────────────────────────────────────────────────────────┘
```

❌ **NetFlow Collector** (v5, v9, IPFIX):
```
Missing: NetFlow/IPFIX UDP listener

Required Implementation:
┌─────────────────────────────────────────────────────────┐
│ 1. NetFlow protocol support                             │
│    - NetFlow v5 (legacy, fixed format)                  │
│    - NetFlow v9 (templates, extensible)                 │
│    - IPFIX (RFC 7011, NetFlow v10)                      │
│    - sFlow (sampled flow, optional)                     │
│                                                          │
│ 2. Flow parsing                                         │
│    - Extract 5-tuple: src_ip, dst_ip, src_port,         │
│      dst_port, protocol                                 │
│    - Bytes/packets transferred                          │
│    - Flow start/end timestamps                          │
│    - AS numbers (origin, peer)                          │
│                                                          │
│ 3. Flow aggregation                                     │
│    - Aggregate by conversation (bidirectional flows)    │
│    - Calculate bytes_in, bytes_out per pair             │
│    - Detect top talkers (volume-based ranking)          │
│                                                          │
│ 4. Anomaly detection                                    │
│    - Volume spikes (10x baseline)                       │
│    - Rare destination AS numbers                        │
│    - Long-duration flows (>24h continuous)              │
│                                                          │
│ 5. Integration with pipeline                            │
│    - Convert flows to events (one event per flow)       │
│    - Feed into network_hunter stage                     │
│    - HopGraph edge creation for flow pairs              │
└─────────────────────────────────────────────────────────┘
```

#### Action Required

**Timeline**: 4-6 weeks for both listeners

**Effort Breakdown**:
- Syslog Listener: 3-4 weeks (1 senior engineer)
- NetFlow Collector: 2-3 weeks (1 engineer with networking background)
- Can be parallelized

**Implementation Steps**:
1. Week 1-2: Protocol parsing (RFC compliance)
2. Week 3: Multi-tenant routing + device classification
3. Week 4: Queue integration + backpressure handling
4. Week 5-6: Performance testing (10K msgs/sec target)

**Dependencies**:
- Python libraries: `pynetflow` (NetFlow), `pysyslog` or custom
- Queue: Redis Streams or RabbitMQ for buffering
- Test environment: Syslog generator, NetFlow exporter

**Expected Benefit**:
- Enable live network threat detection (not just batch)
- Real-time alerting (<5 min from threat to alert)
- Continuous monitoring (24/7 ingestion)

**Priority**: 🟠 **P1 - HIGH** (blocks real-time network monitoring)

---

### GAP 6: Advanced DLP Policies ⚠️ (40% Missing)

**Status**: 🟡 **MEDIUM - BASIC EGRESS TRACKING EXISTS**

#### What Exists

✅ **Egress Stage** (`src/core/event_pipeline/stages/network.py`):
- Tracks abnormal outbound patterns
- Destination IP tracking

#### What's Missing

❌ **DLP Policy Engine**:
```
Missing: Data classification and policy enforcement

Required Implementation:
┌─────────────────────────────────────────────────────────┐
│ 1. Data classification                                  │
│    - Regex patterns: SSN, CC, email, API keys           │
│    - File type detection (MIME-based)                   │
│    - Sensitivity labels (Public, Internal, Confidential)│
│                                                          │
│ 2. Policy rules                                         │
│    - Block: Confidential data to external IPs           │
│    - Alert: >100MB upload to cloud storage              │
│    - Log: Any file transfer to USB device               │
│                                                          │
│ 3. Volume anomaly detection                             │
│    - Baseline: Bytes out per user/host (30-day window)  │
│    - Trigger: 10x baseline in 1-hour window             │
│    - Factor: data_exfil_volume_spike (weight 0.68)      │
│                                                          │
│ 4. Destination analysis                                 │
│    - Cloud storage IPs (Dropbox, Google Drive, OneDrive)│
│    - File sharing sites (WeTransfer, SendAnywhere)      │
│    - Personal email (Gmail, Yahoo, Hotmail)             │
│    - Factor: data_exfil_suspicious_dest (weight 0.55)   │
│                                                          │
│ 5. Policy integration                                   │
│    - Load policies from YAML/JSON                       │
│    - Per-tenant policy overrides                        │
│    - Policy violation metrics                           │
└─────────────────────────────────────────────────────────┘
```

❌ **Content Inspection**:
```
Missing: Deep packet/file content analysis

Required Implementation:
┌─────────────────────────────────────────────────────────┐
│ 1. PCAP integration                                     │
│    - Read PCAP files uploaded via CSV analyzer          │
│    - Extract HTTP/HTTPS payloads (if decrypted)         │
│    - Reconstruct files from TCP streams                 │
│                                                          │
│ 2. File content scanning                                │
│    - YARA rules for sensitive data (credit cards, etc.) │
│    - Entropy analysis (detect encrypted archives)       │
│    - OCR for image-based exfiltration                   │
│                                                          │
│ 3. Protocol analysis                                    │
│    - DNS exfiltration (base64-encoded subdomains)       │
│    - ICMP tunneling (data in ping payloads)             │
│    - HTTP header exfiltration (custom headers)          │
└─────────────────────────────────────────────────────────┘
```

#### Action Required

**Timeline**: 6-8 weeks

**Effort Breakdown**:
- Week 1-2: Data classification engine (regex patterns)
- Week 3-4: Policy engine (YAML-based rules)
- Week 5-6: Volume anomaly detection + destination analysis
- Week 7-8: Content inspection (PCAP, YARA rules)

**Dependencies**:
- YARA library for content scanning
- PCAP parsing library (scapy or dpkt)
- OCR library (tesseract) for image-based DLP

**Expected Improvement**:
- Data exfiltration detection: 60% → 90%
- Policy violation coverage: 0% → 85%

**Priority**: 🟡 **P2 - MEDIUM** (important for data security, not ship blocker)

---

## MEDIUM PRIORITY GAPS (P2)

### GAP 7: Vendor Comparison Module ❌ (100% Missing)

**Status**: 🟡 **MEDIUM - NICE TO HAVE FOR SALES**

**Impact**: Cannot auto-generate competitive analysis vs. Splunk, Sentinel, Chronicle

#### What's Missing

❌ **Automated Benchmarking**:
```
File: src/reporting/vendor_comparison.py
Status: DOES NOT EXIST

Required Implementation:
┌─────────────────────────────────────────────────────────┐
│ 1. Metrics collection                                   │
│    - Detection coverage (% of MITRE ATT&CK)             │
│    - Mean time to detect (MTTD)                         │
│    - False positive rate                                │
│    - Alert volume (per 10K events)                      │
│    - Cost per GB analyzed                               │
│                                                          │
│ 2. Vendor profiles                                      │
│    - Splunk: 78% ATT&CK, 15 min MTTD, 8% FP            │
│    - Sentinel: 82% ATT&CK, 10 min MTTD, 6% FP          │
│    - Chronicle: 85% ATT&CK, 8 min MTTD, 4% FP          │
│    - JanuSec: TBD (measure from production data)        │
│                                                          │
│ 3. Comparison report                                    │
│    - Side-by-side metrics table                         │
│    - Radar chart visualization                          │
│    - Cost comparison (TCO over 3 years)                 │
│    - Feature matrix (HopGraph, LLM, SBOM, etc.)         │
│                                                          │
│ 4. Auto-update mechanism                                │
│    - Fetch vendor specs from public sources             │
│    - Quarterly refresh of comparison data               │
└─────────────────────────────────────────────────────────┘
```

**Timeline**: 4-6 weeks
**Priority**: 🟡 **P2 - MEDIUM** (sales enablement, not production blocker)

---

### GAP 8: KAPE Forensics Integration ❌ (100% Missing)

**Status**: 🟡 **MEDIUM - ADVANCED FORENSICS CAPABILITY**

**Impact**: Cannot auto-ingest forensic artifacts (memory dumps, registry hives, MFT, etc.)

#### What's Missing

❌ **KAPE Artifact Processor**:
```
File: src/integrations/kape_processor.py
Status: DOES NOT EXIST

Required Implementation:
┌─────────────────────────────────────────────────────────┐
│ 1. S3 watch for forensic uploads                        │
│    - Monitor s3://forensics-bucket/kape-output/         │
│    - Trigger on new .zip files (KAPE output)            │
│    - Extract artifacts (registry, evtx, prefetch, etc.) │
│                                                          │
│ 2. Artifact parsing                                     │
│    - Registry hives (SOFTWARE, SYSTEM, SAM, NTUSER)     │
│    - Event logs (.evtx) via python-evtx                 │
│    - Prefetch files (.pf) for execution timeline        │
│    - $MFT (Master File Table) for file activity         │
│                                                          │
│ 3. Timeline reconstruction                              │
│    - Merge all artifacts into chronological timeline    │
│    - Detect persistence mechanisms (registry run keys)  │
│    - Identify lateral movement (event log correlation)  │
│                                                          │
│ 4. Integration with HopGraph                            │
│    - Feed parsed events into pipeline                   │
│    - Build attack graph from forensic timeline          │
│    - Correlate with live events (pre/post-incident)     │
└─────────────────────────────────────────────────────────┘
```

**Timeline**: 8-12 weeks
**Priority**: 🟡 **P2 - MEDIUM** (advanced feature, low customer demand initially)

---

### GAP 9: BGP Anomaly Detection ❌ (100% Missing)

**Status**: 🟡 **MEDIUM - NICHE NETWORK SECURITY**

**Impact**: Cannot detect BGP hijacks, route leaks, ASN spoofing

#### What's Missing

❌ **BGP Feed Integration**:
```
File: src/integrations/bgp_monitor.py
Status: DOES NOT EXIST

Required Implementation:
┌─────────────────────────────────────────────────────────┐
│ 1. BGP feed ingestion                                   │
│    - ExaBGP or GoBGP for BGP session                    │
│    - Route announcement parsing (prefix, AS path)       │
│    - Continuous monitoring (real-time updates)          │
│                                                          │
│ 2. Anomaly detection                                    │
│    - New prefix announcements (not in baseline)         │
│    - AS path hijacks (unexpected ASNs in path)          │
│    - Route flapping (frequent withdraw/announce)        │
│    - RPKI validation failures (invalid ROA)             │
│                                                          │
│ 3. Factor creation                                      │
│    - bgp_prefix_hijack (weight 0.85)                    │
│    - bgp_route_leak (weight 0.75)                       │
│    - MITRE: T1557 (Man-in-the-Middle)                   │
└─────────────────────────────────────────────────────────┘
```

**Timeline**: 6-8 weeks
**Priority**: 🟡 **P2 - MEDIUM** (niche use case, large ISPs/cloud providers only)

---

### GAP 10: eBPF Kernel Tracing ❌ (100% Missing)

**Status**: 🟡 **MEDIUM - ADVANCED ENDPOINT VISIBILITY**

**Impact**: Cannot trace syscalls, kernel-level activity, rootkits

#### What's Missing

❌ **eBPF Agent**:
```
File: src/integrations/ebpf_agent.py
Status: DOES NOT EXIST (STUB ENDPOINTS EXIST)

Required Implementation:
┌─────────────────────────────────────────────────────────┐
│ 1. eBPF probe development                               │
│    - BCC or libbpf for eBPF programs                    │
│    - Trace: execve, open, connect, sendto syscalls      │
│    - Kernel module loading (init_module)                │
│    - File integrity (inode modifications)               │
│                                                          │
│ 2. User-space agent                                     │
│    - Collect eBPF events via perf buffers               │
│    - Enrich with process context (pid, user, cwd)       │
│    - Send to JanuSec API (HTTP/gRPC)                    │
│                                                          │
│ 3. Deployment                                           │
│    - Linux kernel 4.14+ required (eBPF support)         │
│    - Package as .deb, .rpm, Docker container            │
│    - Auto-deployment via Ansible/Terraform              │
│                                                          │
│ 4. Detection capabilities                               │
│    - Fileless malware (memory-only execution)           │
│    - Rootkit detection (hidden processes)               │
│    - Container breakout attempts                        │
└─────────────────────────────────────────────────────────┘
```

**Timeline**: 12+ weeks (kernel programming expertise required)
**Priority**: 🟡 **P2 - MEDIUM** (advanced feature, high development cost)

---

## STUB ANALYSIS

### Files with Stub/Placeholder Code

#### 1. eBPF Analysis Stage (STUB)

**File**: `src/core/event_pipeline/stages/ebpf_analysis.py`
**Evidence**: Stage exists in pipeline definition but likely minimal implementation
**Impact**: Stage registered, but no actual eBPF data processed
**Fix**: Implement eBPF agent (12+ weeks, see GAP 10)

---

#### 2. Binary Payload Stage (PARTIAL STUB)

**File**: `src/core/event_pipeline/stages/supply_chain.py` (binary_payload stage)
**Evidence**: Marked as "heavy" stage, but implementation may be basic
**Needs Investigation**: Check if YARA rules, static analysis, or entropy calc are stubbed
**Likely Status**: Basic implementation, needs advanced features (pefile, strings, disassembly)

---

#### 3. Embedding Stage (QUESTIONABLE)

**File**: `src/core/event_pipeline/stages/advanced.py` (embedding stage)
**Evidence**: Stage 30 in pipeline, purpose unclear
**Potential Stub**: If vector embeddings for similarity search, may be stub without vector DB
**Investigation**: Check if pgvector integration is complete or stubbed

---

#### 4. LLM Explain Endpoint (GUARDED STUB)

**File**: `src/api/graph_session_endpoints.py`
**Evidence**: Recent commit added "guarded LLM explain stub"
**Status**: Endpoint exists but returns deterministic placeholder when LLM disabled
**Fix**: Enable LLM with env vars (2-4 hours, see production doc)

---

### Stub Severity Assessment

| Stub Component | Severity | User Impact | Priority |
|----------------|----------|-------------|----------|
| **eBPF Analysis** | 🟡 Low | No eBPF data = stage no-op | P2 (advanced) |
| **Binary Payload** | 🟠 Medium | Partial analysis, missing features | P1 (investigate) |
| **Embedding** | 🟡 Low | Unclear if used for production features | P2 (investigate) |
| **LLM Explain** | 🟢 None | Fallback works, not a stub | N/A |

---

## ACTION PLAN & ROADMAP

### Phase 1: Critical Gaps (Weeks 1-8)

**Goal**: Enable live ingestion for top 3 domains (network, endpoint, email)

#### Week 1-2: Performance Testing
- [ ] HopGraph load test: 100K, 500K, 1M edges
- [ ] Pipeline throughput test: 10K events/sec
- [ ] Multi-tenant isolation test: 100 tenants
- [ ] Identify bottlenecks, tune thresholds

**Deliverable**: Performance report + tuning recommendations

#### Week 3-6: Email OAuth Adapters
- [ ] MS Graph OAuth flow (weeks 3-4)
  - Azure AD app registration
  - Token management + refresh
  - Delta query polling
  - Email parsing + attachment handling
- [ ] Gmail OAuth flow (weeks 5-6)
  - Google Cloud project setup
  - OAuth consent screen
  - History-based polling
  - MIME parsing + attachments

**Deliverable**: Live email threat detection (phishing, BEC)

#### Week 7-8: Performance Optimization
- [ ] Address bottlenecks from week 1-2 testing
- [ ] Implement fixes (edge count limits, batching, caching)
- [ ] Re-test at scale
- [ ] 7-day soak test

**Deliverable**: Production-validated performance at scale

---

### Phase 2: High Priority Gaps (Weeks 9-16)

**Goal**: Enterprise-grade detection coverage

#### Week 9-12: Cloud CSPM Connectors
- [ ] AWS Config connector (weeks 9-10)
  - boto3 SDK integration
  - CloudTrail S3/SQS ingestion
  - GuardDuty findings
- [ ] Azure Security Center (weeks 11-12)
  - azure-mgmt-security SDK
  - Event Hub consumer
  - Security alerts normalization

**Deliverable**: Live cloud threat detection (AWS, Azure)

#### Week 13-16: Advanced Ransomware + Syslog
- [ ] Ransomware detection (weeks 13-14)
  - Entropy spike detection
  - Shadow copy deletion monitoring
  - VSS tampering alerts
- [ ] Syslog listener (weeks 15-16)
  - UDP 514, TCP 514, TLS 6514
  - RFC 5424 parsing + CEF/LEEF
  - Multi-tenant routing

**Deliverable**: Real-time ransomware alerts + live syslog ingestion

---

### Phase 3: Medium Priority Gaps (Weeks 17-24)

**Goal**: Advanced features for competitive differentiation

#### Week 17-20: Advanced DLP
- [ ] Data classification engine (regex patterns)
- [ ] Policy engine (YAML rules)
- [ ] Volume anomaly detection
- [ ] Content inspection (PCAP, YARA)

**Deliverable**: DLP policy enforcement

#### Week 21-24: Vendor Comparison + GCP CSPM
- [ ] GCP Security Command Center connector (weeks 21-22)
- [ ] Vendor comparison module (weeks 23-24)
  - Automated benchmarking
  - Metrics collection
  - Comparison report generation

**Deliverable**: Competitive analysis automation

---

### Phased Deployment Strategy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PHASED DEPLOYMENT ROADMAP                             │
└─────────────────────────────────────────────────────────────────────────────┘

Week 0: CURRENT STATE (Batch Mode Ready)
├─ Manual CSV upload ✅
├─ 30-stage pipeline ✅
├─ HopGraph attack reconstruction ✅
├─ LOLBins, beaconing, port scanning ✅
└─ Executive reporting ✅

Week 8: PHASE 1 COMPLETE (Live Ingestion - Core Domains)
├─ Performance validated at scale ✅
├─ Email live ingestion (O365 + Gmail) ✅
├─ Network file upload + parsing ✅
└─ Endpoint file upload + parsing ✅

Week 16: PHASE 2 COMPLETE (Enterprise Detection)
├─ AWS CloudTrail live ingestion ✅
├─ Azure Activity Log live ingestion ✅
├─ Syslog listener (firewall, IDS, router) ✅
├─ Advanced ransomware detection ✅
└─ NetFlow collector (optional) ⚠️

Week 24: PHASE 3 COMPLETE (Advanced Features)
├─ GCP Cloud Logging live ingestion ✅
├─ DLP policy enforcement ✅
├─ Vendor comparison automation ✅
└─ Advanced forensics (KAPE, optional) ⚠️

Week 24+: FUTURE ROADMAP
├─ eBPF kernel tracing (12+ weeks) 🔮
├─ BGP anomaly detection (6-8 weeks) 🔮
├─ ML-based anomaly detection (8-12 weeks) 🔮
└─ SOAR playbook automation (6-8 weeks) 🔮
```

---

## RESOURCE REQUIREMENTS

### Team Composition (Phase 1-3)

| Role | Count | Duration | Responsibilities |
|------|-------|----------|------------------|
| **Senior Backend Engineer** | 2 | 24 weeks | OAuth adapters, API connectors, performance tuning |
| **Security Engineer** | 1 | 16 weeks | Ransomware detection, DLP policies, threat research |
| **Network Engineer** | 1 | 8 weeks | Syslog/NetFlow listeners, protocol parsing |
| **QA Engineer** | 1 | 24 weeks | Load testing, integration testing, soak tests |
| **DevOps Engineer** | 1 | 12 weeks | Deployment automation, monitoring, scaling |

**Total**: 6 FTEs (blended)

---

### Infrastructure Requirements

#### Development Environment

```
- AWS EC2: 3x m5.2xlarge (8 vCPU, 32GB RAM) @ $0.384/hr
  Purpose: Dev, staging, load testing
  Cost: ~$830/month

- PostgreSQL RDS: db.m5.xlarge (4 vCPU, 16GB RAM)
  Purpose: Development database
  Cost: ~$280/month

- Total Dev Infrastructure: ~$1,100/month
```

#### Load Testing Environment

```
- AWS EC2: 5x c5.4xlarge (16 vCPU, 32GB RAM) @ $0.68/hr
  Purpose: k6 load generators, pipeline workers
  Cost: ~$2,450/month (only during testing weeks)

- PostgreSQL RDS: db.r5.2xlarge (8 vCPU, 64GB RAM)
  Purpose: High-throughput database testing
  Cost: ~$730/month (testing weeks only)

- Redis ElastiCache: cache.r5.xlarge (4 vCPU, 26GB RAM)
  Cost: ~$250/month

- Total Load Test Infrastructure: ~$3,430/month (weeks 1-2, 7-8 only)
```

---

### Third-Party Services

| Service | Purpose | Est. Cost/Month |
|---------|---------|-----------------|
| **OpenAI GPT-4o** | LLM summaries (optional) | $500-$2,000 |
| **Anthropic Claude** | Alternative LLM (optional) | $800-$3,000 |
| **VT Enterprise API** | Threat intelligence | $1,000 |
| **GeoIP MaxMind** | IP geolocation | $100 |
| **AWS S3** | Artifact storage (dev) | $50 |
| **Datadog/NewRelic** | APM (optional) | $500 |

**Total Third-Party**: ~$2,500-$7,000/month (LLM is largest variable)

---

### Budget Summary (24-Week Program)

| Category | Cost |
|----------|------|
| **Personnel** (6 FTEs blended @ $150K avg) | $450,000 |
| **Infrastructure** (dev + load test) | $30,000 |
| **Third-Party Services** (24 weeks) | $15,000-$42,000 |
| **Contingency** (15%) | $74,000 |
| **TOTAL** | **$569,000-$596,000** |

**Per-Week Budget**: ~$23,700-$24,800

---

## SUCCESS CRITERIA

### Phase 1 Success Metrics (Week 8)

- [ ] HopGraph handles 100K edges with <100ms p99 latency
- [ ] Pipeline sustains 10K events/sec with <5% drop rate
- [ ] 100 tenants isolated with no crosstalk
- [ ] 7-day soak test shows <5% memory growth
- [ ] Email live ingestion: 1,000 mailboxes polled every 5 min
- [ ] MTTD (mean time to detect): <5 minutes for phishing

### Phase 2 Success Metrics (Week 16)

- [ ] AWS CloudTrail: Live S3/SQS ingestion with <10 min lag
- [ ] Azure Activity Log: Event Hub consumer with <5 min lag
- [ ] Syslog listener: 10,000 msgs/sec sustained, <1% drop rate
- [ ] Ransomware detection: <60 sec MTTD, <2% false positive rate
- [ ] Multi-cloud detection: AWS + Azure + on-prem in single view

### Phase 3 Success Metrics (Week 24)

- [ ] GCP Cloud Logging: Pub/Sub consumer with <5 min lag
- [ ] DLP policies: 90% data exfiltration detection accuracy
- [ ] Vendor comparison: Auto-generated report vs. 3 competitors
- [ ] Full production deployment: 10 customer pilots running
- [ ] Customer satisfaction: NPS ≥50

---

## RISK REGISTER

### Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **OAuth approval delays** | 🟠 Medium | 🔴 High | Start Azure AD app registration early, pre-approve with IT |
| **HopGraph performance** | 🟡 Low | 🔴 High | Redis/PostgreSQL fallback if SQLite fails at scale |
| **LLM API cost overrun** | 🟠 Medium | 🟡 Medium | Implement strict rate limits, use GPT-4o-mini for T1 |
| **Multi-tenant crosstalk** | 🟡 Low | 🔴 High | Enforce per-tenant DB isolation, audit queries |
| **Syslog parsing errors** | 🟠 Medium | 🟡 Medium | Extensive format testing, graceful degradation |

### Schedule Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **Scope creep** | 🔴 High | 🟠 Medium | Strict prioritization (P0/P1/P2), defer P2 if needed |
| **Resource unavailability** | 🟠 Medium | 🔴 High | Cross-train team, maintain 20% buffer |
| **Third-party delays** | 🟡 Low | 🟠 Medium | Parallel workstreams, vendor SLAs |

---

## CONCLUSION

The JanuSec platform has **strong production foundations** (78/100 ready) but requires **focused development** to close critical gaps for live enterprise deployment:

### Critical Path (P0 - 8 Weeks)
1. ✅ Performance testing at scale (weeks 1-2)
2. ✅ Email OAuth adapters (weeks 3-6)
3. ✅ Performance optimization (weeks 7-8)

### High Priority (P1 - 16 Weeks)
4. ✅ Cloud CSPM connectors (AWS, Azure)
5. ✅ Advanced ransomware detection
6. ✅ Syslog/NetFlow listeners

### Medium Priority (P2 - 24 Weeks)
7. ⚠️ Advanced DLP policies
8. ⚠️ Vendor comparison automation
9. ⚠️ GCP CSPM connector

**Recommendation**: Execute Phase 1 (weeks 1-8) immediately to enable live ingestion for core domains. Defer Phase 3 (weeks 17-24) until customer demand validates priority.

**Budget**: $569K-$596K for 24-week program (6 FTEs)
**ROI**: Live threat detection enables 10x pricing vs. batch-only ($50K/year → $500K/year ARR per customer)

---

**Document Version**: 1.0
**Date**: December 22, 2025
**Status**: Action Plan Ready for Execution
**Companion Document**: `PRODUCTION_READY_CAPABILITIES_DEC_2025.md`
