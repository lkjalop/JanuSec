# JanuSec Platform Deep Dive - Part 1: Capabilities & Connectors

## Executive Summary

JanuSec is an **AI-powered Extended Detection and Response (XDR)** platform designed to solve alert fatigue through:
- **98% false positive reduction** via multi-stage progressive detection
- **Multi-domain attack reconstruction** across 8 security domains
- **Explainable verdicts** with factor provenance and chain-of-custody
- **Self-tuning detection** via TF-IDF rarity scoring and feedback-driven weighting

**Business Value**: Reduce analyst workload by 70%, detect threats 10x faster (minutes vs hours), achieve ROI in 3-6 months.

---

## 1. Platform Architecture Overview

```
+------------------------------------------------------------------+
|           INGESTION LAYER (8 Domains)                            |
|  Endpoint | Network | IAM | Cloud | Email | SBOM | API | Remote  |
+------------------------------------------------------------------+
                              |
+------------------------------------------------------------------+
|        EVENT PIPELINE (33-Stage Progressive)                      |
|                                                                   |
|  Stages 1-13:   Core (Baseline, Regex, Identity)         <10ms   |
|  Stages 14-17:  Adaptive (TF-IDF, Beacon, Egress)       10-50ms  |
|  Stages 18-23:  Heavy (Binary, PCAP, Hunt Lanes)       50-200ms  |
|  Stages 24-28:  Correlation (HopGraph, Quality)        20-100ms  |
|  Stages 29-33:  External AI (LLM Tier-1, Tier-2)     500-5000ms  |
+------------------------------------------------------------------+
                              |
+------------------------------------------------------------------+
|         DECISION ENGINE & SCORING                                 |
|                                                                   |
|  - DREAD Risk Framework (5 factors: 0-10 scale)                  |
|  - Factor Fusion (5-20 factors per event)                        |
|  - Adaptive Confidence Blending (add/max/weighted)               |
|  - Feedback-Driven Weighting (analyst votes)                     |
+------------------------------------------------------------------+
                              |
+------------------------------------------------------------------+
|       OUTPUT & ANALYST TOOLS                                      |
|                                                                   |
|  REST API | SSE Stream | React Console | Playbooks               |
|  Evidence Exports | HTML/PDF Reports | Custody Chain             |
+------------------------------------------------------------------+
```

---

## 2. Supported Security Domains

| Domain | Data Sources | Key Detectors | Typical Latency |
|--------|--------------|---------------|-----------------|
| **Endpoint** | CrowdStrike, SentinelOne, Wazuh, Sysmon | Malware, LOLBins, Process injection, Memory access | <10ms |
| **Network** | Zeek, Suricata, firewall logs | C2 beaconing, port scans, DNS exfil, JA3/JA3S fingerprinting | <5ms |
| **IAM** | Okta, Azure AD, AWS IAM | Privilege escalation, impossible travel, OAuth abuse | <50ms |
| **Cloud** | AWS CloudTrail, Azure Activity Log, GCP Audit | Lateral movement, data exfil, config tampering | <100ms |
| **Email** | M365, Google Workspace, Mimecast, Proofpoint | Phishing, BEC, macro malware, header injection | <100ms |
| **SBOM** | npm audit, Snyk, Trivy | Supply chain attacks, vulnerable dependencies | <500ms |
| **Supply Chain** | Binary analysis, package metadata | Signed-to-unsigned transitions, repo anomalies | 50-200ms |
| **eBPF** | Kernel monitoring, Falco | Container escape, privilege escalation, syscall anomalies | 1-5ms |

---

## 3. Connector Assessment Matrix

### Legend
- **Production-Grade**: Full implementation with error handling, retry logic, pagination, auth, metrics
- **Partial/Beta**: Works but missing features or limited API coverage
- **Stub/Placeholder**: Framework only, no real implementation

---

### 3.1 Security Tool Integrations

| Connector | Status | Implementation Details |
|-----------|--------|------------------------|
| **CrowdStrike Falcon** | **Production-Grade** | Real API with token auth, checkpoint persistence (V2), full pagination, retry with exponential backoff (3 retries, 0.5s base, 25% jitter), metrics: `events_ingested_total`, `ingest_errors_total`, `retry_attempts_total` |
| **Qualys VMDR** | **Production-Grade** | HTTP Basic Auth, XML parsing for KB queries, disk-persisted vuln cache, rate limiting (300 req/hr), CVE/QID mapping with CVSS scores, stub mode fallback |
| **Tenable.io VPR** | **Production-Grade** | X-ApiKeys auth, disk-persisted VPR cache, pagination (50k safety limit), rate limiting (200 req/min), CVE to VPR mapping |
| **SentinelOne** | Partial/Beta | Framework exists, limited endpoint coverage |
| **Wazuh** | Partial/Beta | Integration points defined, agent-based data collection |

---

### 3.2 Email Integrations

| Connector | Status | Implementation Details |
|-----------|--------|------------------------|
| **Mimecast** | **Production-Grade** | OAuth 2.0 client credentials, token store with expiry, pagination with cursor, retry logic, full normalization to `NormalizedEmailEvent`, SPF/DKIM/DMARC parsing |
| **Gmail** | **Production-Grade** | OAuth2 installed/web app flow, token exchange + refresh, history-based polling (startHistoryId), MIME parsing, pagination support |
| **Proofpoint TAP** | **Partial/Beta** | HMAC-SHA256 signature verification works, webhook parsing complete, BUT `fetch_events()` returns empty (no REST polling) |
| **Microsoft Graph (O365)** | **Stub/Placeholder** | Config class exists, `fetch_security_events()` returns empty list - template only |
| **Cofense Vision** | **Stub/Placeholder** | Config class with API token, all fetch methods return empty |

---

### 3.3 AWS Integrations

| Connector | Status | Implementation Details |
|-----------|--------|------------------------|
| **CloudTrail** | **Production-Grade** | boto3 with credential assumption, LookupEvents API pagination, checkpoint persistence, metrics, canonical envelope normalization |
| **GuardDuty** | **Production-Grade** | Detector discovery with caching, findings pagination, checkpoint persistence, metrics |
| **CloudWatch** | **Production-Grade** | Uses boto3 with assume-role support, checkpoint-based incremental fetch |
| **VPC Flow Logs** | **Production-Grade** | Part of AWS connector base infrastructure |
| **Security Hub** | **Production-Grade** | Part of AWS connector base infrastructure |
| **Config Snapshot** | **Production-Grade** | Configuration compliance tracking |
| **IAM Changes** | **Production-Grade** | IAM activity tracking |
| **CloudTrail S3** | **Production-Grade** | S3 object reading for CloudTrail logs |

**AWS Base Infrastructure** (`src/connectors/aws/base.py`): Production-Grade
- AWSConnectorConfig class
- boto3 client factory with assume-role
- File-based checkpoint persistence
- Pagination helpers
- Canonical envelope creation

---

### 3.4 SIEM Integrations

| Connector | Status | Implementation Details |
|-----------|--------|------------------------|
| **Splunk Client** | **Production-Grade** | SavedSearch execution with job polling, result pagination, HEC ack/send, checkpoint persistence, exponential backoff, metrics |
| **Splunk Adapter** | **Stub** | Returns synthetic event, cursor tracking, no real polling |
| **Sentinel Client** | **Production-Grade** | Azure ARM + Graph API modes, OAuth 2.0 token exchange with refresh, pagination via nextLink, rate limiting |
| **Sentinel Adapter** | **Stub** | Returns synthetic incident, no real polling |

---

### 3.5 Threat Intelligence

| Connector | Status | Implementation Details |
|-----------|--------|------------------------|
| **MISP Client** | **Production-Grade** | Real PyMISP integration, pagination, retry logic, SSRF protection, auth error detection |
| **MISP Adapter** | **Stub** | Returns hardcoded domain/IP list for test determinism |
| **OpenCTI Client** | **Production-Grade** | Observable fetching with pagination, SSRF protection, retry logic |
| **OpenCTI Service** | **Partial** | Service wrapper with status/config/sync, no actual network calls in stub mode |
| **KEV Feed** | **Production-Grade** | Local JSON loading, background refresher thread (1hr), component lookup |
| **Abuse.CH** | **Stub** | Basic URL config only |

---

### 3.6 Network Integrations

| Connector | Status | Implementation Details |
|-----------|--------|------------------------|
| **Zeek** | **Production-Grade** | Queue-based ingestion with backpressure, TSV/JSON normalization (conn/dns/http/ssl logs), JA3/JA3S fingerprinting, heartbeat reporting |
| **Falco** | **Production-Grade** | JSON line stream parsing, eBPF event correlation, SBOM/KEV/EPSS enrichment, batch processing |
| **Syslog/NetFlow/IPFIX** | **Stub** | Queue-based design, backpressure handling, BUT no actual UDP/TCP socket binding |

---

### 3.7 IAM & Identity

| Connector | Status | Implementation Details |
|-----------|--------|------------------------|
| **Okta** | **Partial/Beta** | IAM adapter exists, synthetic event generator for testing, provider-agnostic config |
| **Azure AD** | **Partial/Beta** | Mapping helpers for Azure signin events, token management stubs |
| **AWS IAM** | **Partial/Beta** | CloudTrail IAM event mapping helpers |

---

### 3.8 Infrastructure & Support

| Connector | Status | Implementation Details |
|-----------|--------|------------------------|
| **CheckpointStore V1** | **Production-Grade** | Single-file JSON persistence, legacy API |
| **CheckpointStore V2** | **Production-Grade** | Multi-source stream checkpointing, hierarchical keys |
| **ConnectorBase** | **Production-Grade** | Abstract base class, async methods, canonical event builder with 20+ fields |
| **Connector Registry** | **Production-Grade** | Policy-based management, rate limiting (TokenBucket), config persistence, cost caps |
| **Email Transports** | **Production-Grade** | Gmail, M365Graph, EWS transports, DKIM/SPF/DMARC verification, ARC/BIMI support |
| **Google OAuth** | **Production-Grade** | Full OAuth provider implementation |
| **MSAL/Azure Auth** | **Production-Grade** | Azure AD authentication |
| **Webhook Verifier** | **Production-Grade** | HMAC signature verification, multi-provider |
| **Slack Notifier** | **Production-Grade** | Webhook posting, message formatting |
| **Vector DB** | **Production-Grade** | pgvector integration for embeddings, similarity search |
| **SBOM Parser** | **Production-Grade** | Software Bill of Materials parsing, vulnerability lookup |
| **Vuln Enrichment** | **Production-Grade** | CVSS, KEV, EPSS lookup, component mapping |

---

### 3.9 Connector Summary Statistics

| Category | Production-Grade | Partial/Beta | Stub/Placeholder |
|----------|------------------|--------------|------------------|
| Security Tools | 3 | 2 | 0 |
| Email | 2 | 1 | 2 |
| AWS | 8 | 0 | 0 |
| SIEM | 2 (clients) | 0 | 2 (adapters) |
| Threat Intel | 3 | 1 | 1 |
| Network | 2 | 0 | 1 |
| IAM | 0 | 3 | 0 |
| Infrastructure | 12 | 0 | 0 |
| **TOTALS** | **32** | **7** | **6** |

**Overall Completion Rate: ~71% production-grade, 16% partial, 13% stubs**

---

## 4. Frontend & Analyst Tools

**70+ HTML pages** covering:

### Core Consoles
- `investigate.html` - Main triage interface with SSE stream, factor details
- `attack_graph.html` - HopGraph visualization
- `csv_analyzer.html` - Offline forensics (file upload)
- `csv_deep_analysis.html` - Enriched CSV analysis
- `csv_multi_analyzer.html` - Batch CSV processing

### Specialized Views
- `admin.html` - Configuration, allowlists, rules
- `baseline.html` - Baseline tuning
- `compliance.html` - MITRE ATT&CK coverage, audit trails
- `cspm.html` - Cloud security posture
- `iam.html` - Identity attack analysis
- `hunt_endpoint.html`, `hunt_network.html` - Threat hunting
- `hopgraph_ux.html` - Graph traversal UI
- `llm_adjudicate.html` - Manual LLM decision override
- `labeling.html` - Ground-truth labeling for training
- `metrics.html` - Precision, recall, performance dashboards
- `reports.html` - Executive summaries, evidence export
- `timeline_composer.html` - Attack timeline builder

---

## 5. Deployment Options

### Option 1: Cloud (Azure/AWS/GCP)
- App Service + PostgreSQL Flex + Redis
- Estimated: ~$430/month for 100K events/day

### Option 2: Kubernetes / OpenShift
- Helm charts (production-ready)
- Auto-scaling (3-10 replicas)
- StatefulSet for PostgreSQL (Patroni HA)
- Redis Cluster (3 masters, 3 replicas)

### Option 3: Edge / Bare Metal (Air-Gapped)
- Docker Compose single-box
- Wazuh + Suricata local IDS
- Ollama for local LLM (GPU optional)

### Minimum Hardware
- CPU: 8 cores (16 recommended)
- RAM: 32 GB (16 minimum)
- Storage: 500 GB SSD
- Network: 1 Gbps

---

## 6. Key Module Structure

```
src/
├── api/                           # 115+ endpoint modules
│   ├── routes/events.py          # Event ingest & streaming
│   ├── alerts_endpoints.py       # Alert management
│   ├── deep_analyze_endpoints.py # Tier 2 LLM analysis
│   ├── graph_sessions.py         # HopGraph queries
│   ├── csv_endpoints.py          # CSV analysis
│   └── (... 100+ more)
│
├── core/
│   ├── event_pipeline/
│   │   ├── pipeline.py           # Main EventPipeline (2,038 lines)
│   │   └── stages/               # 33 detection stages
│   ├── decision_engine.py        # DREAD scoring, routing
│   ├── graph/
│   │   └── hopgraph_lite.py      # Attack reconstruction (1,004 lines)
│   ├── correlation/
│   │   ├── hunt_correlation.py   # Multi-domain linking
│   │   └── rules/                # 79 correlation rule files
│   └── detectors/                # 50+ specialized detectors
│
├── integrations/
│   ├── llm_client.py             # LLM abstraction (917 lines)
│   ├── crowdstrike_client.py     # CrowdStrike integration
│   ├── qualys_client.py          # Qualys VMDR
│   ├── tenable_client.py         # Tenable VPR
│   └── (... connectors ...)
│
├── connectors/
│   ├── aws/                      # AWS connectors
│   ├── email/                    # Email connectors
│   └── registry.py               # Connector registry
│
├── security/
│   └── auth.py                   # API key + JWT, scope-based RBAC
│
└── db/
    └── database.py               # PostgreSQL + migrations
```

---

## 7. Configuration System

### Three-Tier Configuration
1. **Static Config** (`config/main.yaml`): Pipeline settings, thresholds
2. **Tenant Overrides** (`config/api_stage_tenants.json`): Per-customer tuning
3. **Factor Weights** (`config/factor_weights/*.yaml`): ML model weights

### Key Environment Variables
```bash
# Pipeline
PIPELINE_ALLOWLIST_ENABLED=1
REDIS_URL=redis://localhost:6379

# LLM
LLM_PROVIDER=ollama|openai|anthropic
OLLAMA_HOST=http://127.0.0.1:11434
OPENAI_API_KEY=sk-...

# Database
DATABASE_URL=postgresql://...
```

---

## 8. Security & Compliance Features

### Auth & Access Control
- API key + JWT scope-based model
- Scopes: `nlp.query`, `factors.search`, `feedback.write`, `approvals.admin`
- OIDC integration (optional)

### Data Protection
- PII redaction (configurable)
- Encrypted at rest (TLS in transit)
- Multi-tenancy isolation
- GDPR-compliant retention policies

### Compliance
- Audit trails (all decisions)
- Chain-of-custody hashing (SHA-256)
- MITRE ATT&CK coverage tracking
- CVSS/EPSS vulnerability enrichment

---

## Next: Part 2 - Core Engines (HopGraph, Pipeline, Deep Analyze, LLM)
