# Platform Enhancement Roadmap (Q4 2025 → Q1 2026)

Purpose: Provide a prioritized, bounded roadmap of platform improvements across detection efficacy, correlation depth, performance guardrails, data quality, and observability.

## 1. Correlation Engine Evolution
Current State:
- HopGraph Lite with weighted edges, age-decay scoring, `explain_chain` API.
- Factors feeding graph: network (beacon, dns, ssl, port scan), endpoint (lineage, persistence, LSASS, LOLBins, TF-IDF rarity), incident enrichment with framework mapping.
- Basic synergy rules (e.g., rare JA3 + macro spawn) (partial / prototype).

Gaps & Next Steps:
| Priority | Enhancement | Description | Outcome Metric |
|----------|-------------|-------------|----------------|
| P0 | Temporal Multi-hop Correlation | Sliding window correlation (N events across lanes within T) with decay | Increase true positive chain recall +10% |
| P0 | Factor Co-occurrence Scoring | Learn weights for factor pairs (e.g., beacon + rare lineage) via frequency vs expected | + Precision (reduce single-factor FP) |
| P1 | Cross-Lane Campaign Graphs | Aggregate incidents into “campaign” node when sharing ≥K coherent pivots | Campaign clustering coverage |
| P1 | Lateral Movement Sequence Patterns | Template detection (auth anomaly → service exec → credential access) | Recall of lateral scenarios |
| P2 | Negative Correlation (Suppression) | Use benign pattern chains to down-score noisy combos | FP reduction baseline |
| P2 | ML-Assisted Path Ranking | Train embedding or GNN over hop chains (offline) to calibrate path scores | Path ranking AUC |

## 2. Performance & Resource Guardrails
| Priority | Enhancement | Rationale | KPI |
|----------|-------------|-----------|-----|
| P0 | Adaptive Time Budget per Lane | Dynamically shrink heavy analyses under load | p95 latency stability under 2× load |
| P0 | Graph Memory Watermarks | Warn & prune with metrics when edge or node count exceed thresholds | No OOM events, graceful prune |
| P1 | Explain Cache Hit/Miss Metrics | Observability of cache sizing | Target ≥70% hit rate |
| P1 | Async Batch Ingestion Buffering | Coalesce small events to reduce per-event overhead | CPU utilization reduction |
| P2 | SIMD / Vectorized Tokenization | Accelerate TF-IDF & factor extraction | 20–30% CPU drop for endpoint lane |

## 3. Data Quality & Normalization
| Priority | Enhancement | Description | KPI |
|----------|-------------|-------------|-----|
| P0 | Unified Event Schema Validator | JSON schema + fast validation (optional strict mode) | Schema drift incidents detected |
| P0 | Field Confidence Layer | Track confidence per parsed field for downstream weighting | Confidence usage in scoring |
| P1 | Entity Canonicalization Service | Central service for host/process/domain normalization (cache) | Duplicate entity rate ↓ |
| P2 | Automatic PII Redaction Pipeline | Structured redaction for logs & exported reports | Compliance readiness |

## 4. Observability & Metrics
| Priority | Enhancement | Description |
|----------|-------------|------------|
| P0 | Active Beacon Gauge (DONE) | Gauge for flow key count (capacity guard) |
| P0 | HopGraph Cache Hit/Miss Metrics | Add `hopgraph_explain_cache_hits_total/misses_total` |
| P1 | Lane Saturation Dashboard | Derived metrics: queue depth, backlog age |
| P1 | Factor Emission Distribution Export | Histogram of per-factor emission rates over time |
| P2 | Incident Resolution SLA Metrics | Track detection → incident creation time |

## 5. Threat Intel & Enrichment Expansion
| Priority | Enhancement | Description |
|----------|-------------|------------|
| P0 | Lightweight Geo-IP & ASN Enrichment | Add context to network factors |
| P1 | Malware Family Heuristic Tags | Simple rule-based tagging from process & network patterns |
| P1 | Framework Coverage Matrix Export | Export current factor → framework mapping as CSV API |
| P2 | External Abuse Feed Correlation | Overlay external abuse scores on inbound IPs |

## 6. ML Instrumentation & Feedback Loop
| Priority | Enhancement | Description | KPI |
|----------|-------------|-------------|-----|
| P0 | Decision Feedback Ingestion API | Accept analyst verdict overrides (TP/FP tags) | Feedback ingestion rate |
| P1 | Online Factor Weight Tuning | Periodic re-calibration from feedback window | Precision/recall delta |
| P1 | Replay Drift Dashboard | Compare historical snapshot vs latest factor distributions | Drift detection counts |
| P2 | Active Learning Suggestion Queue | Highlight low-confidence events for labeling | Label efficiency |

## 7. Security & Governance
| Priority | Enhancement | Description |
|----------|-------------|------------|
| P0 | Factor Governance Linter (Extended) | Enforce naming + class coverage rules |
| P1 | Cost Guardrails (Per-Tenant Budgets) | Hard ceilings with degrade mode |
| P1 | Policy-as-Code DSL | Manage gating & escalation policies declaratively |
| P2 | Audit Trail Tamper Evident WAL | Hash chain for WAL records |

## 8. API & UX Enhancements
| Priority | Enhancement | Description |
|----------|-------------|------------|
| P0 | Incident Enrichment Panel (DONE base) | Display framework + beacon explain |
| P1 | Interactive Graph Explorer | On-demand k-hop UI + path highlighting |
| P1 | Factor Timeline View | Chronological factor emission per entity |
| P2 | Custom Detection Rule Authoring UI | Low-code factor injection |

## Sequencing (Quarter View)
| Quarter | Focus | Key Deliverables |
|---------|-------|------------------|
| Q4 2025 (current) | Correlation Depth Phase 1 | Temporal multi-hop, factor co-occurrence scoring, schema validator |
| Q1 2026 | Feedback & Adaptive Scoring | Decision feedback API, online weight tuning, hopgraph cache metrics |
| Q2 2026 | Campaigns & Advanced Suppression | Campaign graph clustering, negative correlation, entity canon service |

## Risks & Mitigations
| Risk | Impact | Mitigation |
|------|--------|-----------|
| Metric Cardinality Creep | Prometheus instability | Pre-review checklist + CI cardinality diff smoke test |
| Graph Memory Growth | OOM / latency | TTL pruning & watermarks; active beacon gauge (done) |
| Feedback Data Sparsity | Slower ML gains | Active learning suggestion queue |
| False Positive Regression | Analyst fatigue | Negative correlation & suppression rules early |

## Acceptance for Each P0
- Tests updated (unit + minimal integration)
- Metrics documented in `METRICS_CARDINALITY.md`
- Feature flag & safe fallback path
- Added to CHANGELOG / release notes

---
Owner: Platform Architecture Team
Review Cadence: Bi-weekly# 🚀 JanuSec Platform - Comprehensive Enhancement Roadmap

**Document Version**: 1.0
**Date**: 2025-10-10
**Purpose**: Detailed roadmap for closing gaps and achieving market leadership

---

## Executive Summary

This document provides a **comprehensive, prioritized roadmap** for transforming JanuSec from an 88% production-ready platform to a **market-leading threat detection solution**. Each enhancement is analyzed for:
- **Business impact** (revenue, differentiation, competitive advantage)
- **Technical complexity** (effort estimation, dependencies)
- **Risk mitigation** (security, reliability, scalability)
- **Strategic value** (market positioning, unique capabilities)

**Current State**: 88% production-ready, $3M-6M valuation
**Target State**: 100% production-ready, $10M-25M valuation
**Timeline**: 6-12 months (phased approach)

---

## 📋 Enhancement Priority Framework

### Priority Levels

| Level | Criteria | Impact | Examples |
|-------|----------|--------|----------|
| **P0** | Production blocker, no workaround | Business-critical | Threat intel integration, multi-tenant validation |
| **P1** | Significant competitive gap, high ROI | High value | Certificate analysis, correlation scale, DREAD scoring |
| **P2** | Market differentiation, medium ROI | Medium value | LOLBin detection, EVTX parsing, STRIDE completion |
| **P3** | Nice-to-have, low ROI | Low value | Syslog/CEF, advanced ML models |

---

## 🎯 Phase 1: Critical Gaps (Weeks 1-8) - **Production Readiness**

**Goal**: Close P0 blockers, achieve 100% production readiness
**Timeline**: 8 weeks
**Investment**: $120K-150K (2 senior engineers)
**Outcome**: Deployable to first 3-5 beta customers

---

### 1.1 Threat Intelligence Integration (P0)

**Status**: ❌ Critical gap (0% complete)
**Effort**: 4 weeks (160 hours)
**Impact**: **BLOCKING** - No community intelligence, stale IoC lists
**Complexity**: Medium-High (API integration, data normalization, incremental sync)

#### **Implementation Plan**

##### **Week 1: MISP Integration**

**Objective**: Sync MISP threat intelligence platform for community IoC feeds

**Tasks**:
1. **MISP API Client** (20 hours)
   - Install `pymisp` library
   - Implement MISP API authentication (API key, SSL cert)
   - Build async API client wrapper
   ```python
   # src/integrations/misp_client.py
   from pymisp import PyMISP

   class MISPClient:
       def __init__(self, url: str, api_key: str, verify_ssl: bool = True):
           self.client = PyMISP(url, api_key, verify_ssl)

       async def fetch_recent_attributes(self, days: int = 7) -> List[Dict]:
           # Fetch attributes (IPs, domains, hashes) from last N days
           # Filter by type (ip-dst, domain, md5, sha256)
           # Return normalized attribute list

       async def fetch_event_by_id(self, event_id: str) -> Dict:
           # Fetch full event with context (threat actor, campaign)
   ```

2. **Incremental Sync Logic** (16 hours)
   - Track last sync timestamp (store in DB: `misp_sync_metadata` table)
   - Fetch only new/updated attributes since last sync
   - Handle pagination (MISP API returns 1000 attributes per page)
   - Deduplication logic (skip already-synced attributes)

3. **Baseline Module Integration** (12 hours)
   - Populate bloom filters from MISP attributes
   - Map MISP types to baseline categories:
     - `ip-dst` → malicious IP bloom filter
     - `domain` → malicious domain bloom filter
     - `md5`, `sha256` → malicious hash bloom filter
   - Add MISP source tag to factors: `misp:malicious_ip:192.0.2.1`

4. **Sync Scheduler** (8 hours)
   - Background task (asyncio loop)
   - Configurable sync interval (default: hourly)
   - Metrics: `misp_attributes_synced_total`, `misp_sync_duration_seconds`

**Deliverables**:
- MISP client library (`src/integrations/misp_client.py`)
- Sync scheduler (`src/integrations/misp_sync_scheduler.py`)
- Database migration (`migrations/0014_misp_sync.sql`)
- Unit tests (`tests/test_misp_integration.py`)

---

##### **Week 2: OpenCTI Integration**

**Objective**: Enrich factors with MITRE ATT&CK techniques and threat actor attribution

**Tasks**:
1. **OpenCTI API Client** (20 hours)
   - Install `pycti` library
   - Implement GraphQL query builder
   - Authentication (API token)
   ```python
   # src/integrations/opencti_client.py
   from pycti import OpenCTIApiClient

   class OpenCTIClient:
       def __init__(self, url: str, token: str):
           self.client = OpenCTIApiClient(url, token)

       async def get_techniques_by_indicator(self, ioc: str) -> List[Dict]:
           # Query OpenCTI for MITRE techniques linked to IoC
           # Return: [{"technique_id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}]

       async def get_threat_actor_by_technique(self, technique_id: str) -> List[Dict]:
           # Query for threat actors using technique
           # Return: [{"name": "APT28", "aliases": ["Fancy Bear"], "country": "Russia"}]
   ```

2. **Factor Enrichment** (16 hours)
   - After correlation stage, enrich factors with OpenCTI context
   - Add MITRE technique tags: `mitre:T1059.001:PowerShell`
   - Add threat actor context: `threat_actor:APT28:Russia`
   - Store enrichment metadata in decision record

3. **Explain API Enhancement** (12 hours)
   - Extend `/api/v1/risk/{event_id}/explain` to include OpenCTI context
   - Response format:
     ```json
     {
       "factors": [
         {
           "factor": "regex:ps_obfuscation",
           "mitre_techniques": ["T1059.001", "T1027"],
           "threat_actors": ["APT28", "APT29"],
           "confidence_contribution": 0.08
         }
       ]
     }
     ```

4. **Campaign Detection** (12 hours)
   - Track factors associated with known campaigns (via OpenCTI)
   - Alert when multiple factors from same campaign detected
   - New correlation rule: `CAMPAIGN_MATCH` (multiple factors + same campaign) → High confidence boost

**Deliverables**:
- OpenCTI client (`src/integrations/opencti_client.py`)
- Enrichment stage (`src/core/enrichment/opencti_enrichment.py`)
- Enhanced explain API
- Campaign correlation rule

---

##### **Week 3: Abuse.ch Feeds**

**Objective**: Integrate community threat feeds (URLhaus, MalwareBazaar, ThreatFox)

**Tasks**:
1. **Feed Downloaders** (20 hours)
   - URLhaus CSV feed: `https://urlhaus.abuse.ch/downloads/csv_recent/`
   - MalwareBazaar CSV feed: `https://mb-api.abuse.ch/downloads/`
   - ThreatFox JSON feed: `https://threatfox-api.abuse.ch/api/v1/`
   - Implement async HTTP downloaders with retry logic
   - Parse CSV/JSON formats
   - Extract IoCs (URLs, domains, IPs, hashes, C2 servers)

2. **Feed Normalization** (16 hours)
   - Normalize to internal IoC schema:
     ```python
     {
       "type": "ip" | "domain" | "url" | "hash",
       "value": "192.0.2.1",
       "source": "urlhaus" | "malwarebazaar" | "threatfox",
       "threat_type": "malware_download" | "c2" | "phishing",
       "malware_family": "Emotet" | "Cobalt Strike" | None,
       "confidence": 0.9,  # Abuse.ch confidence
       "first_seen": "2025-10-10T12:00:00Z",
       "last_seen": "2025-10-10T14:30:00Z"
     }
     ```

3. **Malware Family Tagging** (12 hours)
   - Extract malware family from Abuse.ch feeds
   - Add to factors: `malware_family:Emotet`, `malware_family:Cobalt_Strike`
   - Correlation rule: Known malware family + suspicious behavior → High confidence

4. **Feed Sync Scheduler** (12 hours)
   - Sync every 4 hours (Abuse.ch updates frequently)
   - Metrics: `abusech_iocs_synced_total{source}`
   - Rate limiting (respect Abuse.ch API limits)

**Deliverables**:
- Abuse.ch feed clients (`src/integrations/abusech_feeds.py`)
- Malware family correlation rule
- Feed sync scheduler

---

##### **Week 4: AlienVault OTX & Threat Intel Management**

**Objective**: Add AlienVault OTX pulses + unified threat intel management layer

**Tasks**:
1. **AlienVault OTX Integration** (16 hours)
   - Install `OTXv2` library
   - Fetch subscribed pulses (user-curated threat intel)
   - Extract indicators from pulses
   - Map pulse tags to JanuSec factors

2. **Unified Threat Intel Manager** (20 hours)
   - Centralized manager for all threat intel sources
   ```python
   # src/modules/threat_intel_manager.py
   class ThreatIntelManager:
       def __init__(self):
           self.sources = [MISPClient(), OpenCTIClient(), AbusechFeeds(), OTXClient()]

       async def sync_all_sources(self):
           # Parallel sync all sources
           # Deduplicate across sources (same IoC from multiple feeds)
           # Aggregate confidence (weighted average)

       async def lookup_ioc(self, ioc: str, ioc_type: str) -> Optional[ThreatContext]:
           # Query all sources for context
           # Return: ThreatContext(source, confidence, malware_family, threat_actor, mitre_techniques)
   ```

3. **IoC Confidence Aggregation** (12 hours)
   - When same IoC appears in multiple feeds, aggregate confidence
   - Formula: `weighted_avg = (c1*w1 + c2*w2 + ... + cn*wn) / (w1+w2+...+wn)`
   - Weights: MISP=1.0, OpenCTI=1.0, Abuse.ch=0.9, OTX=0.7 (configurable)

4. **Threat Intel UI** (12 hours)
   - Frontend page: `/intel`
   - Show IoC statistics (total IPs, domains, hashes)
   - Recent syncs (source, timestamp, new IoCs)
   - Search interface (lookup IoC across all feeds)

**Deliverables**:
- AlienVault OTX client
- Unified threat intel manager
- Threat intel dashboard page
- Configuration file (`config/threat_intel.yaml`)

---

#### **Success Metrics**

| Metric | Target | Measurement |
|--------|--------|-------------|
| **IoC Coverage** | >1M indicators | Count of unique IPs/domains/hashes in baseline |
| **Sync Freshness** | <4 hours | Time since last successful sync |
| **Attribution Accuracy** | >80% | % of malicious verdicts with correct malware family/actor |
| **Baseline Hit Rate** | +20% | Increase in baseline stage matches |
| **False Positive Reduction** | -15% | Fewer benign alerts due to better context |

---

#### **Risks & Mitigations**

| Risk | Mitigation |
|------|------------|
| **API Rate Limits** | Implement exponential backoff, respect rate limits, cache responses |
| **Data Quality** | Filter low-confidence IoCs, implement confidence thresholds (>0.7) |
| **Sync Failures** | DLQ for failed syncs, alerting on consecutive failures, manual retry endpoint |
| **Storage Growth** | Implement IoC TTL (expire old IoCs after 90 days), compression |
| **Performance Impact** | Async sync (non-blocking), batch bloom filter updates, incremental updates only |

---

### 1.2 Multi-Tenant Isolation Validation (P0)

**Status**: ⚠️ Harness exists, not executed under production load
**Effort**: 1 week (40 hours)
**Impact**: **BLOCKING** - Risk of cross-tenant data leaks
**Complexity**: Low-Medium (execution + fixes)

#### **Implementation Plan**

##### **Week 5: Stress Test Execution & Leak Fixes**

**Tasks**:
1. **Execute Isolation Harness** (8 hours)
   - Run `scripts/tenant_isolation_stress.py` with production-like load
   - Parameters:
     - 10 tenants
     - 1000 events per tenant (10K total)
     - Concurrent ingestion (simulate real load)
   - Capture results: `cross_tenant_leaks`, `factor_contamination`

2. **Fix Cross-Tenant Leaks** (16 hours - contingency)
   - If leaks detected, trace root cause:
     - Shared cache keys (missing tenant_id prefix)
     - Global state in modules
     - Correlation window mixing tenants
   - Apply fixes:
     - Prefix all cache keys with `tenant_id:`
     - Scope all in-memory state by tenant
     - Filter correlation windows by tenant

3. **Database Isolation Validation** (8 hours)
   - Verify all DB queries include `WHERE tenant_id = $1`
   - Audit all repositories for missing tenant filters
   - Add DB-level row-level security (RLS) policies:
     ```sql
     ALTER TABLE decisions ENABLE ROW LEVEL SECURITY;
     CREATE POLICY tenant_isolation ON decisions
       USING (tenant_id = current_setting('app.current_tenant')::text);
     ```

4. **Documentation** (8 hours)
   - Document isolation guarantees
   - Multi-tenant deployment guide
   - Tenant onboarding checklist
   - Isolation testing runbook

**Deliverables**:
- Stress test report (`reports/tenant_isolation_stress_report.json`)
- Isolation fixes (if needed)
- Database RLS policies
- Multi-tenant deployment guide

---

#### **Success Metrics**

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Cross-Tenant Leaks** | 0 | Events/factors appearing in wrong tenant context |
| **Factor Contamination** | 0 | Tenant A factors influencing Tenant B decisions |
| **Isolation Test Pass Rate** | 100% | All isolation assertions pass |
| **Performance Impact** | <5% | Overhead from tenant scoping |

---

### 1.3 Network Hunter Certificate Analysis (P1)

**Status**: ⚠️ Missing (MVP has JA3/DNS/beaconing, no certificates)
**Effort**: 3 weeks (120 hours)
**Impact**: High - Detect C2 infrastructure, TLS interception, weak crypto
**Complexity**: Medium (Zeek SSL log parsing, X.509 validation)

#### **Implementation Plan**

##### **Week 6-8: TLS/SSL Certificate Analysis**

**Tasks**:
1. **Zeek SSL Log Parser** (24 hours)
   - Parse Zeek `ssl.log` JSON format
   - Extract fields:
     - `id.orig_h`, `id.resp_h`, `id.resp_p` (connection tuple)
     - `server_name` (SNI)
     - `ja3`, `ja3s` (already handled by network hunter)
     - `validation_status` (ok, self signed, expired, etc.)
     - `cert_chain` (array of X.509 DER-encoded certs)
     - `issuer`, `subject`
     - `not_valid_before`, `not_valid_after`
     - `signature_algorithm` (sha256WithRSAEncryption, etc.)

2. **Certificate Validation Logic** (32 hours)
   - **Self-Signed Detection**:
     - Issuer == Subject → `ssl:self_signed_cert`
     - Confidence delta: +0.10
   - **Expired Certificate**:
     - `not_valid_after < now()` → `ssl:expired_cert`
     - Confidence delta: +0.08
   - **Not Yet Valid**:
     - `not_valid_before > now()` → `ssl:not_yet_valid_cert`
     - Confidence delta: +0.06
   - **Weak Signature Algorithm**:
     - `signature_algorithm in [md5WithRSAEncryption, sha1WithRSAEncryption]` → `ssl:weak_signature`
     - Confidence delta: +0.05
   - **Short Validity Period** (potential C2):
     - `(not_valid_after - not_valid_before) < 30 days` → `ssl:short_validity`
     - Confidence delta: +0.04
   - **SNI Mismatch**:
     - `server_name != cert.subject.commonName` → `ssl:sni_mismatch`
     - Confidence delta: +0.07

3. **Issuer Anomaly Detection** (24 hours)
   - Track issuer frequency (common CAs: Let's Encrypt, DigiCert, etc.)
   - Rare issuer detection:
     - Issuer seen <10 times globally → `ssl:rare_issuer`
     - Confidence delta: +0.03
   - Known-malicious CA detection:
     - Maintain list of blacklisted issuers (from threat intel)
     - Match → `ssl:blacklisted_ca`
     - Confidence delta: +0.15

4. **Certificate Fingerprinting** (20 hours)
   - Compute SHA-256 hash of certificate DER encoding
   - Track certificate hash frequency
   - Known-malicious certificate detection:
     - Match against threat intel (MISP, Abuse.ch)
     - → `ssl:known_malicious_cert`
     - Confidence delta: +0.20
   - Rare certificate detection (seen <5 times):
     - → `ssl:rare_certificate`
     - Confidence delta: +0.04

5. **Integration into Network Hunter** (16 hours)
   - Add certificate analysis to network hunter stage
   - If Zeek SSL log available:
     - Parse and analyze certificates
     - Append certificate factors to event
   - Bounded confidence cap: 0.15 (prevents over-weighting)

6. **Metrics & Observability** (4 hours)
   - `ssl_certs_analyzed_total`
   - `ssl_self_signed_total`
   - `ssl_expired_total`
   - `ssl_weak_signature_total`
   - `ssl_rare_issuer_total`

**Deliverables**:
- Zeek SSL log parser (`src/live/zeek_ssl_adapter.py`)
- Certificate validation module (`src/modules/certificate_analysis.py`)
- Integration into network hunter
- Unit tests (`tests/test_certificate_analysis.py`)

---

#### **Success Metrics**

| Metric | Target | Measurement |
|--------|--------|-------------|
| **C2 Detection Lift** | +15% | Increase in C2 detections via certificate anomalies |
| **Self-Signed Cert Alerts** | >50/day | Known indicator of C2/malware infrastructure |
| **False Positive Rate** | <5% | Self-signed certs on internal infrastructure (allowlist) |
| **Certificate Coverage** | >80% | % of TLS connections with certificate analysis |

---

#### **Risks & Mitigations**

| Risk | Mitigation |
|------|------------|
| **High Volume** | Sample SSL log (e.g., 1 in 10 connections) for large environments |
| **False Positives** | Allowlist internal CAs, corporate certificates |
| **Zeek Dependency** | Graceful degradation if SSL log unavailable (skip stage) |
| **Certificate Parsing** | Use `cryptography` library for robust X.509 parsing |

---

## 🚀 Phase 2: Competitive Differentiation (Weeks 9-16) - **Market Leadership**

**Goal**: Expand detection capabilities, scale correlation, add DREAD scoring
**Timeline**: 8 weeks
**Investment**: $120K-150K (2 senior engineers)
**Outcome**: Market-leading detection platform with unique SBOM+explainability+DREAD

---

### 2.1 Correlation Rule Expansion (P1)

**Status**: ⚠️ 20+ rules present, need 100+ for production
**Effort**: 2 weeks (80 hours)
**Impact**: High - Detect multi-stage attacks, reduce FP via context
**Complexity**: Medium (rule authoring, testing, tuning)

#### **Implementation Plan**

##### **Weeks 9-10: Correlation Rule Library**

**Objective**: Expand from 20 rules to 100+ production-grade correlation rules

**Rule Categories**:

1. **Initial Access** (15 rules)
   - Phishing + credential use
   - Drive-by download + execution
   - Exploit + payload delivery
   - VPN from rare geo + sensitive access
   - Brute force success + lateral movement

2. **Execution** (20 rules)
   - Office macro + PowerShell + network connection
   - Script execution + persistence
   - Scheduled task + suspicious binary
   - WMI execution + lateral movement
   - Service creation + DLL hijacking

3. **Persistence** (15 rules)
   - Registry run key + network beacon
   - Startup folder + suspicious hash
   - Service creation + rare binary
   - WMI subscription + PowerShell
   - Account creation + privilege escalation

4. **Privilege Escalation** (10 rules)
   - UAC bypass + admin token
   - Exploit + SYSTEM privileges
   - Token manipulation + lateral movement
   - Scheduled task elevation + persistence
   - Service abuse + privilege escalation

5. **Defense Evasion** (15 rules)
   - Log tampering + persistence
   - Process injection + network connection
   - Signed binary abuse + execution
   - Obfuscation + suspicious behavior
   - Timestomping + file modification

6. **Credential Access** (10 rules)
   - LSASS access + network connection
   - Credential dumping + lateral movement
   - Kerberoasting + privilege escalation
   - Password spray + successful login
   - Keylogging + data staging

7. **Discovery** (5 rules)
   - Network scan + lateral movement
   - AD enumeration + privilege escalation
   - File/directory discovery + exfiltration
   - System info gathering + C2 beacon
   - Account discovery + credential access

8. **Lateral Movement** (10 rules)
   - RDP + rare destination
   - SMB + admin share access + execution
   - WMI + remote execution
   - PsExec + lateral movement
   - Pass-the-hash + privilege escalation

9. **Collection** (5 rules)
   - Data staging + compression + exfiltration
   - Clipboard capture + keylogging
   - Screen capture + data staging
   - Email collection + exfiltration
   - Database query + data staging

10. **Exfiltration** (10 rules)
    - DNS tunneling + large data volume
    - HTTPS upload + rare destination
    - Cloud storage + sensitive data
    - FTP upload + compression
    - Email attachment + sensitive data

**Rule Implementation**:
```python
# src/core/correlation/rules/initial_access.py
PHISHING_CREDENTIAL_USE = CorrelationRule(
    name="phishing_credential_use",
    description="Phishing email opened followed by credential use from same user",
    factors_required=[
        "email:phishing_opened",
        "auth:credential_use"
    ],
    temporal_window=3600,  # 1 hour
    same_user=True,
    confidence_boost=0.15,
    output_factor="corr:phishing_credential_use",
    mitre_techniques=["T1566.001", "T1078"],
    severity="high"
)
```

**Tasks**:
1. **Rule Authoring** (40 hours)
   - Write 80+ new correlation rules (100 total)
   - Cover all MITRE tactics (14 tactics)
   - Map each rule to MITRE techniques
   - Define confidence boosts (0.05-0.20)

2. **Temporal Correlation Enhancement** (20 hours)
   - Support multiple time windows (5min, 30min, 1hr, 24hr)
   - Implement sliding windows (not just fixed)
   - Add decay factor (older events lower weight)

3. **Statistical Correlation** (20 hours)
   - Bayesian correlation (prior probability + evidence)
   - Co-occurrence frequency (factors that appear together)
   - Anomaly-based correlation (unusual factor combinations)

**Deliverables**:
- 100+ correlation rules (`src/core/correlation/rules/*.py`)
- Enhanced correlation engine
- Rule testing framework
- MITRE ATT&CK coverage report

---

#### **Success Metrics**

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Correlation Lift (TP)** | 1.8x | Improvement in true positive detection rate |
| **Correlation FP Impact** | <+10% | FP increase due to correlation |
| **Attack Chain Detection** | >90% | % of multi-stage attacks detected |
| **MITRE Coverage** | >70% | % of ATT&CK techniques covered |

---

### 2.2 DREAD Risk Scoring (P1)

**Status**: ❌ Not implemented
**Effort**: 2 weeks (80 hours)
**Impact**: High - Prioritize alerts, improve SOC analyst workflow
**Complexity**: Medium (scoring framework, asset context)

#### **Implementation Plan**

##### **Weeks 11-12: DREAD Framework Implementation**

**Objective**: Implement DREAD risk scoring for alert prioritization

**DREAD Components**:
- **D**amage potential (0-3)
- **R**eproducibility (0-3)
- **E**xploitability (0-3)
- **A**ffected users (0-3)
- **D**iscoverability (0-3)

**Tasks**:
1. **DREAD Scoring Engine** (32 hours)
   ```python
   # src/core/risk/dread_scorer.py
   class DREADScorer:
       def score_event(self, event: Dict, factors: List[str], asset_context: AssetContext) -> DREADScore:
           damage = self._assess_damage(factors, asset_context)
           reproducibility = self._assess_reproducibility(factors)
           exploitability = self._assess_exploitability(factors)
           affected_users = self._estimate_affected_users(event, asset_context)
           discoverability = self._assess_discoverability(factors)

           total = damage + reproducibility + exploitability + affected_users + discoverability
           dread_score = total / 15.0  # Normalize to 0-1

           return DREADScore(
               damage=damage,
               reproducibility=reproducibility,
               exploitability=exploitability,
               affected_users=affected_users,
               discoverability=discoverability,
               total_score=dread_score
           )
   ```

2. **Damage Assessment** (12 hours)
   - Map factors to damage levels:
     - `credential_access`, `data_exfiltration` → Damage: 3
     - `privilege_escalation`, `lateral_movement` → Damage: 2
     - `reconnaissance`, `discovery` → Damage: 1
   - Amplify by asset criticality:
     - Crown jewel asset → Damage × 1.5
     - Business-critical → Damage × 1.2
     - Standard → Damage × 1.0

3. **Reproducibility Assessment** (8 hours)
   - Known exploit available → Reproducibility: 3
   - PoC available → Reproducibility: 2
   - Theoretical → Reproducibility: 1
   - Not reproducible → Reproducibility: 0

4. **Exploitability Assessment** (8 hours)
   - Automated tool available → Exploitability: 3
   - Basic skills required → Exploitability: 2
   - Advanced skills required → Exploitability: 1
   - Expert skills required → Exploitability: 0

5. **Affected Users Estimation** (8 hours)
   - Map event to asset scope:
     - Domain controller → Affected: 3 (all users)
     - File server → Affected: 2 (department)
     - Workstation → Affected: 1 (individual)
     - Isolated system → Affected: 0

6. **Discoverability Assessment** (8 hours)
   - Factor visibility:
     - `public_exploit`, `known_vulnerability` → Discoverability: 3
     - `internal_scan_detectable` → Discoverability: 2
     - `advanced_hunting_required` → Discoverability: 1
     - `stealth_technique` → Discoverability: 0

7. **Integration** (4 hours)
   - Add DREAD scoring to decision pipeline (after correlation)
   - Enrich decision record with DREAD score
   - Alert prioritization:
     - DREAD ≥ 0.8 → Critical priority
     - DREAD ≥ 0.6 → High priority
     - DREAD < 0.6 → Medium/Low priority

**Deliverables**:
- DREAD scoring engine (`src/core/risk/dread_scorer.py`)
- Asset criticality database (`config/asset_criticality.yaml`)
- Enhanced decision records (with DREAD scores)
- DREAD-based alert prioritization

---

#### **Success Metrics**

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Alert Prioritization Accuracy** | >85% | % of high-DREAD alerts confirmed as high-impact |
| **Analyst Time Savings** | 30% | Reduction in time spent triaging low-priority alerts |
| **Mean Time to Respond (MTTR)** | -40% | Faster response to critical (high-DREAD) alerts |
| **False Positive Impact** | <5% | % of high-DREAD alerts that are false positives |

---

### 2.3 LOLBin Detection (P2)

**Status**: ⚠️ Minimal coverage
**Effort**: 1 week (40 hours)
**Impact**: Medium-High - Detect fileless malware, post-exploitation
**Complexity**: Low-Medium (pattern library, detection logic)

#### **Implementation Plan**

##### **Week 13: Living-off-the-Land Binary Detection**

**Objective**: Detect abuse of legitimate Windows binaries for malicious purposes

**LOLBin Categories**:
1. **Download/Transfer** - `certutil`, `bitsadmin`, `curl`, `wget`
2. **Execution** - `mshta`, `rundll32`, `regsvr32`, `msiexec`
3. **Encoding/Decoding** - `certutil -decode`, `PowerShell FromBase64String`
4. **Persistence** - `schtasks`, `sc`, `reg add`
5. **Credential Harvesting** - `procdump`, `comsvcs.dll`
6. **Bypass** - `InstallUtil`, `regasm`, `regsvcs`

**Tasks**:
1. **LOLBin Pattern Library** (16 hours)
   ```python
   # src/modules/lolbin_patterns.py
   LOLBIN_PATTERNS = {
       "certutil": {
           "suspicious_args": ["-decode", "-urlcache", "-f", "http"],
           "confidence_delta": 0.10,
           "factor": "lolbin:certutil_abuse",
           "mitre": ["T1105", "T1140"]
       },
       "regsvr32": {
           "suspicious_args": ["/s", "/u", "/i:http", "scrobj.dll"],
           "confidence_delta": 0.12,
           "factor": "lolbin:regsvr32_abuse",
           "mitre": ["T1218.010"]
       },
       "mshta": {
           "suspicious_args": ["http", "javascript:", "vbscript:"],
           "confidence_delta": 0.15,
           "factor": "lolbin:mshta_abuse",
           "mitre": ["T1218.005"]
       },
       "rundll32": {
           "suspicious_args": ["javascript:", "vbscript:", "http"],
           "confidence_delta": 0.10,
           "factor": "lolbin:rundll32_abuse",
           "mitre": ["T1218.011"]
       },
       "powershell": {
           "suspicious_args": ["-enc", "-encodedcommand", "-w hidden", "-nop", "bypass", "IEX", "DownloadString"],
           "confidence_delta": 0.08,
           "factor": "lolbin:powershell_abuse",
           "mitre": ["T1059.001", "T1027"]
       },
       "wmic": {
           "suspicious_args": ["process call create", "/node:", "shadowcopy"],
           "confidence_delta": 0.12,
           "factor": "lolbin:wmic_abuse",
           "mitre": ["T1047"]
       },
       "bitsadmin": {
           "suspicious_args": ["/transfer", "/download", "http"],
           "confidence_delta": 0.10,
           "factor": "lolbin:bitsadmin_abuse",
           "mitre": ["T1197"]
       }
   }
   ```

2. **Detection Logic** (12 hours)
   - Parse process name and command line from event
   - Check if process name in LOLBin patterns
   - Check if any suspicious args present in command line
   - If match:
     - Add factor: `lolbin:{binary}_abuse`
     - Add confidence delta
     - Add MITRE technique tags

3. **Integration into Endpoint Hunter** (8 hours)
   - Add LOLBin detection to endpoint hunter stage
   - Execute after persistence detection
   - Bounded confidence impact: cumulative <0.15

4. **Allowlist Support** (4 hours)
   - Some LOLBin usage is legitimate (IT admins)
   - Support process path allowlist:
     ```yaml
     lolbin_allowlist:
       - process: "certutil.exe"
         path: "C:\\IT\\Scripts\\*"
         reason: "Legitimate IT scripts"
     ```

**Deliverables**:
- LOLBin pattern library
- Detection module (`src/modules/lolbin_detector.py`)
- Integration into endpoint hunter
- Allowlist configuration

---

#### **Success Metrics**

| Metric | Target | Measurement |
|--------|--------|-------------|
| **LOLBin Detection Rate** | >80% | % of known LOLBin abuse detected |
| **False Positive Rate** | <10% | Legitimate LOLBin use flagged |
| **Fileless Malware Detection** | +25% | Increase in fileless attack detections |

---

## 🔬 Phase 3: Advanced Capabilities (Weeks 17-24) - **Innovation**

**Goal**: ML-assisted correlation, advanced fingerprinting, attack graphs
**Timeline**: 8 weeks
**Investment**: $150K-180K (2 senior engineers + ML specialist)
**Outcome**: Market-leading advanced detection, AI-assisted hunting

---

### 3.1 ML-Assisted Correlation (P2)

**Status**: ❌ Not implemented (current: rule-based only)
**Effort**: 3 weeks (120 hours)
**Impact**: High - Discover unknown attack patterns, adaptive correlation
**Complexity**: High (ML model training, feature engineering)

#### **Implementation Plan**

##### **Weeks 17-19: Machine Learning Correlation Engine**

**Objective**: Augment rule-based correlation with ML pattern discovery

**Approaches**:

1. **Bayesian Network Correlation** (40 hours)
   - Model factor co-occurrence probabilities
   - Learn: P(Factor_B | Factor_A)
   - Detect unusual factor combinations (low joint probability)
   - Output: Anomalous factor chains → Correlation candidate

2. **Frequent Pattern Mining** (40 hours)
   - Use Apriori algorithm to discover frequent factor sequences
   - Example: `{suspicious_parent_child, dns_tunnel, beacon}` appears in 80% of C2 cases
   - Auto-generate correlation rules from frequent patterns
   - Human-in-the-loop: Analyst reviews and approves generated rules

3. **Graph Neural Network (GNN)** (40 hours)
   - Model attack graphs (nodes=factors, edges=temporal co-occurrence)
   - Train GNN on labeled attack chains
   - Predict: "Given factors A, B, what's probability of factor C next?"
   - Use for attack path prediction and early detection

**Tasks**:
1. **Feature Engineering** (24 hours)
   - Extract features from historical decisions:
     - Factor sequences (temporal order)
     - Factor co-occurrence counts
     - Time deltas between factors
     - Factor graph embeddings

2. **Model Training** (32 hours)
   - Collect labeled training data:
     - True positive attack chains
     - False positive factor sequences
     - Benign baseline (normal activity)
   - Train models:
     - Bayesian network (scikit-learn, pgmpy)
     - Frequent pattern mining (mlxtend)
     - GNN (PyTorch Geometric)

3. **Inference Integration** (24 hours)
   - Add ML correlation stage after rule-based correlation
   - Inference:
     - Input: Current factor set
     - Output: ML-predicted correlation factors + confidence
   - Bounded confidence: ML correlations capped at +0.10

4. **Model Retraining Pipeline** (20 hours)
   - Periodic retraining (weekly) on new labeled data
   - Analyst feedback loop (mark FP/TP) → Training labels
   - A/B testing: Rule-based vs. ML-assisted correlation
   - Metrics: Precision, recall, F1 score

5. **Explainability** (20 hours)
   - SHAP values for ML correlation decisions
   - Example: "Factor X contributed +0.08 to ML correlation confidence because it co-occurs with Factor Y in 85% of known attacks"
   - Add to explain API

**Deliverables**:
- ML correlation engine (`src/core/correlation/ml_correlation.py`)
- Model training pipeline (`scripts/train_ml_correlation.py`)
- Explainability module (SHAP integration)
- A/B testing framework

---

#### **Success Metrics**

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Unknown Attack Detection** | +15% | Attacks detected by ML but not rule-based |
| **False Positive Rate** | <+5% | ML correlation FP increase vs. rule-based |
| **Pattern Discovery** | 20+ new rules/month | Auto-generated correlation rules from ML |

---

### 3.2 Advanced HTTP Header Analysis (P2)

**Status**: ⚠️ User-Agent covered, other headers missing
**Effort**: 1 week (40 hours)
**Impact**: Medium - Detect malware C2, web shells, injection attacks
**Complexity**: Medium (header parsing, anomaly detection)

#### **Implementation Plan**

##### **Week 20: HTTP Header Fingerprinting**

**Objective**: Analyze HTTP headers for malware, web shells, injection

**Header Analysis Categories**:

1. **Content-Type Mismatch** (8 hours)
   - Detect: `Content-Type: text/html` but body is binary (malware download)
   - Factor: `http:content_type_mismatch`
   - Confidence delta: +0.06

2. **Suspicious Accept Headers** (8 hours)
   - Non-browser Accept headers (malware C2 often uses simple HTTP clients)
   - Example: `Accept: */*` (cURL default)
   - Rare Accept header → `http:rare_accept`
   - Confidence delta: +0.03

3. **Referer Anomalies** (8 hours)
   - Missing Referer on form submissions (CSRF attack)
   - Referer domain != current domain (open redirect)
   - Factor: `http:referer_anomaly`
   - Confidence delta: +0.05

4. **Custom/Unusual Headers** (8 hours)
   - Malware often adds custom headers (`X-Bot-ID`, `X-Session`)
   - Detect: Headers not in common header list (200 known headers)
   - Factor: `http:custom_header:{name}`
   - Confidence delta: +0.04

5. **Injection Patterns in Headers** (8 hours)
   - SQL injection in User-Agent, Referer, Cookie
   - Command injection (e.g., `$(whoami)`)
   - XSS payloads (`<script>`)
   - Factor: `http:header_injection`
   - Confidence delta: +0.10

**Deliverables**:
- HTTP header analysis module (`src/modules/http_header_analysis.py`)
- Integration into network hunter
- Common header whitelist

---

#### **Success Metrics**

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Web Shell Detection** | +20% | Increase in web shell detections |
| **C2 Callback Detection** | +10% | HTTP-based C2 detections |
| **Injection Attack Detection** | +15% | SQLi/XSS in headers detected |

---

### 3.3 Attack Graph Generation (P3)

**Status**: ❌ Not implemented
**Effort**: 2 weeks (80 hours)
**Impact**: Medium - Visualize attack chains, analyst investigation
**Complexity**: High (graph algorithms, visualization)

#### **Implementation Plan**

##### **Weeks 21-22: Attack Path Reconstruction**

**Objective**: Automatically reconstruct and visualize attack paths

**Tasks**:
1. **Graph Builder** (32 hours)
   - Build directed graph from correlated factors
   - Nodes: Factors (with timestamps, confidence)
   - Edges: Temporal correlation (factor A → factor B within window)
   - Weights: Correlation strength

2. **Attack Path Extraction** (24 hours)
   - Use graph algorithms to find attack paths:
     - Source nodes: Initial access factors
     - Sink nodes: Exfiltration/impact factors
     - Find all paths from source to sink
   - Rank paths by:
     - Total path confidence (sum of node confidences)
     - Path length (shorter = more direct attack)
     - MITRE tactic coverage (more tactics = more sophisticated)

3. **Visualization API** (16 hours)
   - Generate GraphViz DOT format
   - JSON graph export (for frontend rendering)
   - HTML report with embedded graph
   - Example:
     ```json
     {
       "nodes": [
         {"id": "phishing_email", "type": "initial_access", "confidence": 0.9},
         {"id": "credential_use", "type": "credential_access", "confidence": 0.8},
         {"id": "lateral_movement", "type": "lateral_movement", "confidence": 0.85}
       ],
       "edges": [
         {"source": "phishing_email", "target": "credential_use", "weight": 0.9},
         {"source": "credential_use", "target": "lateral_movement", "weight": 0.85}
       ]
     }
     ```

4. **Frontend Integration** (8 hours)
   - Attack graph viewer (D3.js or Cytoscape.js)
   - Interactive exploration (zoom, pan, node details)
   - Export to PNG/SVG

**Deliverables**:
- Attack graph builder (`src/core/graph/attack_graph_builder.py`)
- Visualization API (`/api/v1/attack_graph/{event_id}`)
- Frontend graph viewer

---

#### **Success Metrics**

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Attack Path Accuracy** | >85% | % of reconstructed paths match actual attack |
| **Analyst Investigation Time** | -30% | Faster incident investigation with visual graphs |

---

## 🌐 Phase 4: Ecosystem & Integration (Weeks 25-32) - **Adoption**

**Goal**: Integrate with SIEM/SOAR/ticketing, build ecosystem
**Timeline**: 8 weeks
**Investment**: $100K-120K (2 engineers)
**Outcome**: Seamless integration into SOC workflows

---

### 4.1 SIEM Export Integration (P2)

**Status**: ❌ Not implemented
**Effort**: 2 weeks (80 hours)
**Impact**: High - Enable existing SIEM users to adopt JanuSec
**Complexity**: Medium (API integration, format mapping)

#### **Supported SIEMs**:
- Splunk (HTTP Event Collector)
- Elastic (Elasticsearch Bulk API)
- QRadar (Syslog CEF)
- Microsoft Sentinel (Log Analytics API)
- ArcSight (CEF Syslog)

#### **Implementation Plan**

##### **Weeks 25-26: SIEM Export Framework**

**Tasks**:
1. **Generic SIEM Exporter** (24 hours)
   ```python
   # src/integrations/siem/base_exporter.py
   class SIEMExporter(ABC):
       @abstractmethod
       async def export_decision(self, decision: DecisionRecord) -> bool:
           # Export decision to SIEM

       @abstractmethod
       async def export_alert(self, alert: Alert) -> bool:
           # Export alert to SIEM
   ```

2. **Splunk HEC Integration** (16 hours)
   - Install `requests` library
   - Implement Splunk HTTP Event Collector client
   - Map decision record to Splunk event format
   - Batch export (100 events per batch)

3. **Elastic Integration** (16 hours)
   - Install `elasticsearch` library
   - Implement Elasticsearch bulk API client
   - Map to Elastic Common Schema (ECS)
   - Index: `janusec-decisions-{date}`

4. **QRadar/Sentinel CEF Integration** (16 hours)
   - Implement CEF (Common Event Format) serializer
   - Map decision fields to CEF extensions
   - Syslog UDP/TCP transport
   - TLS support (SIEM → JanuSec)

5. **Configuration** (8 hours)
   - SIEM export config (`config/siem_export.yaml`)
   - Per-tenant SIEM destination (multi-tenant support)
   - Rate limiting (respect SIEM ingestion limits)

**Deliverables**:
- SIEM exporter framework
- Splunk, Elastic, QRadar, Sentinel integrations
- Configuration schema
- Export metrics (`siem_export_total{siem_type, status}`)

---

### 4.2 SOAR Integration (P2)

**Status**: ⚠️ Playbook stubs present, no SOAR execution
**Effort**: 2 weeks (80 hours)
**Impact**: High - Automated response, analyst workflow automation
**Complexity**: Medium-High (API integration, playbook DSL)

#### **Supported SOAR Platforms**:
- Splunk SOAR (Phantom)
- Palo Alto Cortex XSOAR
- IBM Resilient
- Swimlane
- TheHive

#### **Implementation Plan**

##### **Weeks 27-28: SOAR Playbook Execution**

**Tasks**:
1. **Playbook DSL Parser** (24 hours)
   - Parse YAML playbook definitions
   - Example:
     ```yaml
     playbook:
       name: "High-Severity Alert Response"
       triggers:
         - verdict: "malicious"
           confidence_min: 0.9
       actions:
         - type: "enrich"
           source: "virustotal"
           fields: ["file_hash"]
         - type: "notify"
           channel: "slack"
           message: "Critical alert: {{event_id}}"
         - type: "ticket"
           system: "jira"
           project: "SEC"
           summary: "Malicious activity detected"
         - type: "containment"
           action: "isolate_host"
           host: "{{source_ip}}"
     ```

2. **SOAR Platform Integrations** (32 hours)
   - **Splunk SOAR (Phantom)**:
     - REST API client
     - Create container (case) → Add artifacts (evidence) → Run playbook
   - **Cortex XSOAR**:
     - REST API client
     - Create incident → Add indicators → Execute playbook
   - **TheHive**:
     - REST API client
     - Create case → Add observables → Execute responder

3. **Action Executors** (16 hours)
   - **Enrich**: Query external sources (VirusTotal, threat intel)
   - **Notify**: Send to Slack, email, SMS
   - **Ticket**: Create Jira, ServiceNow ticket
   - **Containment**: Execute containment action (via SOAR API)

4. **Playbook Execution Engine** (8 hours)
   - Async execution (non-blocking)
   - Retry logic (exponential backoff)
   - Execution tracking (playbook_executions table)
   - Metrics: `playbook_executions_total{playbook, status}`

**Deliverables**:
- Playbook DSL parser
- SOAR platform integrations (Phantom, XSOAR, TheHive)
- Action executor framework
- Playbook execution engine

---

### 4.3 Ticketing Integration (P2)

**Status**: ❌ Not implemented
**Effort**: 1 week (40 hours)
**Impact**: Medium - Analyst workflow integration
**Complexity**: Low-Medium (API integration)

#### **Supported Ticketing Systems**:
- Jira
- ServiceNow
- GitHub Issues
- PagerDuty (for on-call)

#### **Implementation Plan**

##### **Week 29: Ticketing Automation**

**Tasks**:
1. **Jira Integration** (16 hours)
   - Install `jira` library
   - Create issue on high-severity alert
   - Fields: Summary, Description, Priority, Labels
   - Link to JanuSec decision (URL in description)

2. **ServiceNow Integration** (16 hours)
   - REST API client
   - Create incident on malicious verdict
   - Map severity: JanuSec confidence → ServiceNow priority

3. **Auto-Ticket Configuration** (8 hours)
   - Config: When to create tickets
     - Confidence ≥ 0.9 → Auto-create
     - DREAD ≥ 0.8 → Auto-create
     - Correlation match → Auto-create

**Deliverables**:
- Jira/ServiceNow integrations
- Auto-ticket configuration
- Ticket creation metrics

---

## 📊 Success Metrics & KPIs

### Overall Platform KPIs

| Category | Metric | Current | Target (Post-Roadmap) |
|----------|--------|---------|---------------------|
| **Detection** | True Positive Rate | 85% | 95% |
| **Detection** | False Positive Rate | 12/1000 | <5/1000 |
| **Detection** | MITRE Coverage | 40% | 80% |
| **Performance** | P95 Latency | 420ms | <300ms |
| **Correlation** | Attack Chain Detection | 70% | 95% |
| **Explainability** | Factor Attribution | 100% | 100% (maintained) |
| **Cost Efficiency** | Heavy Stage Skip Rate | 65% | 75% |
| **Governance** | Replay Determinism | 100% | 100% (maintained) |

### Business Impact KPIs

| Metric | Current | Target (12 months) |
|--------|---------|-------------------|
| **Customers** | 0 (pre-revenue) | 15-25 |
| **ARR** | $0 | $1M-2M |
| **Analyst Time Savings** | N/A | 40% (vs. manual triage) |
| **MTTR** | N/A | -50% (vs. baseline) |
| **NRR (Net Revenue Retention)** | N/A | >120% |

---

## 🎯 Strategic Recommendations

### Immediate Priorities (Weeks 1-8)

1. **Close P0 Blockers**:
   - Threat intel integration (4 weeks)
   - Multi-tenant validation (1 week)
   - Certificate analysis (3 weeks)

2. **Customer Acquisition**:
   - Acquire 3-5 beta customers while closing gaps
   - Offer discounted pricing ($10K-25K/year) for early adopters
   - Focus on detection engineering teams, DevSecOps shops

### Medium-Term Strategy (Weeks 9-24)

1. **Market Differentiation**:
   - Expand correlation (100+ rules)
   - Add DREAD scoring (unique SOC analyst value)
   - ML-assisted correlation (innovation story)

2. **Revenue Growth**:
   - Expand to 10-15 customers
   - Launch SBOM-specific SKU ($75K-150K/year)
   - Partner with CISA SBOM initiative

### Long-Term Vision (6-12 months)

1. **Market Leadership**:
   - Position as **the explainable threat platform**
   - Unique SBOM fusion + DREAD scoring + ML correlation
   - Target: Top 3 in Gartner/Forrester SIEM/XDR reports

2. **Exit Strategy**:
   - Strategic acquisition by:
     - **Splunk/Elastic** (add explainability to SIEM)
     - **Snyk/Sonatype** (add runtime threat to SBOM)
     - **CrowdStrike/SentinelOne** (add supply chain to XDR)
   - Target valuation: $25M-50M (3-5 years)

---

## 🚨 Risk Register

### Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **Threat Intel API Rate Limits** | High | Medium | Implement caching, respect limits, fallback to cached data |
| **ML Model Accuracy** | Medium | High | A/B testing, human-in-loop validation, gradual rollout |
| **Multi-Tenant Leaks** | Low | Critical | Thorough testing, DB RLS, code audit, bug bounty |
| **Performance Degradation** | Medium | Medium | Load testing, profiling, horizontal scaling |
| **Integration Complexity** | High | Medium | Prioritize top 3 integrations (Splunk, Elastic, Phantom) |

### Business Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **Slow Customer Acquisition** | Medium | High | Open-source core (community edition), freemium model |
| **Competitive Response** | High | Medium | Patent SBOM fusion, rapid feature velocity |
| **Talent Shortage** | Medium | Medium | Remote-first hiring, competitive comp, equity grants |
| **Funding Gap** | Low | Critical | Raise seed early (Week 8-12), extend runway to 18 months |

---

## 💰 Investment & ROI Analysis

### Development Investment

| Phase | Duration | FTE | Cost | Deliverables |
|-------|----------|-----|------|--------------|
| **Phase 1** (P0 Gaps) | 8 weeks | 2 | $120K | Threat intel, multi-tenant, certificates |
| **Phase 2** (Differentiation) | 8 weeks | 2 | $120K | Correlation, DREAD, LOLBin |
| **Phase 3** (Innovation) | 8 weeks | 2.5 | $150K | ML correlation, advanced fingerprinting |
| **Phase 4** (Ecosystem) | 8 weeks | 2 | $100K | SIEM/SOAR integrations |
| **Total** | 32 weeks | Avg 2.1 | **$490K** | Production-ready, market-leading platform |

### Revenue Projection (12 months)

| Milestone | Timing | Customers | ARPU | ARR |
|-----------|--------|-----------|------|-----|
| Beta Launch | Month 3 | 3-5 | $15K | $45K-75K |
| Product-Market Fit | Month 6 | 8-12 | $50K | $400K-600K |
| Scale | Month 12 | 15-25 | $75K | $1.1M-1.9M |

### ROI Analysis

- **Investment**: $490K (development) + $200K (sales/marketing) = **$690K**
- **Year 1 ARR**: $1M-2M
- **Valuation**: $10M-20M (10-20x ARR)
- **ROI**: 14x-29x (2-year horizon)

---

## 📅 Gantt Chart (High-Level)

```
Phase 1: Critical Gaps (Weeks 1-8)
├─ MISP Integration               ████████
├─ OpenCTI Integration            ████████
├─ Abuse.ch Feeds                 ████████
├─ AlienVault OTX                 ████████
├─ Multi-Tenant Validation        ████
└─ Certificate Analysis           ████████████

Phase 2: Differentiation (Weeks 9-16)
├─ Correlation Expansion          ████████
├─ DREAD Scoring                  ████████
├─ LOLBin Detection               ████
└─ STRIDE Completion              ████

Phase 3: Innovation (Weeks 17-24)
├─ ML Correlation                 ████████████
├─ HTTP Header Analysis           ████
└─ Attack Graphs                  ████████

Phase 4: Ecosystem (Weeks 25-32)
├─ SIEM Export                    ████████
├─ SOAR Integration               ████████
├─ Ticketing                      ████
└─ Documentation                  ████████
```

---

## 🎓 Learning & Resources

### Recommended Reading

1. **Threat Intelligence**:
   - *The Diamond Model of Intrusion Analysis* (Sergio Caltagirone)
   - *Intelligence-Driven Incident Response* (Scott Roberts, Rebekah Brown)

2. **Correlation & Detection**:
   - *Practical Threat Detection Engineering* (Crafting Detection Logic)
   - *Blue Team Handbook: Incident Response Edition* (Don Murdoch)

3. **SBOM & Supply Chain**:
   - *SBOM at a Glance* (CISA)
   - *Software Supply Chain Security* (Cassie Crossley)

### Training & Certifications

- **SANS SEC555**: SIEM with Tactical Analytics
- **SANS FOR508**: Advanced Incident Response
- **MITRE ATT&CK Defender (MAD)**: ATT&CK framework certification

---

## 🏁 Conclusion

This roadmap provides a **comprehensive, actionable plan** to transform JanuSec from 88% production-ready to **market-leading threat detection platform** in 6-12 months.

**Key Success Factors**:
1. ✅ **Execute Phase 1 flawlessly** (close P0 gaps in 8 weeks)
2. ✅ **Acquire 3-5 beta customers** (validate product-market fit)
3. ✅ **Differentiate with SBOM+DREAD+ML** (unique market position)
4. ✅ **Build ecosystem integrations** (reduce adoption friction)
5. ✅ **Maintain governance excellence** (replay determinism, factor governance)

**Expected Outcome**:
- **100% production-ready** platform
- **$10M-25M valuation** (strategic premium)
- **Market leader** in explainable threat detection + SBOM fusion
- **Clear path** to $5M+ ARR and strategic exit

---

**Document Version**: 1.0
**Last Updated**: 2025-10-10
**Next Review**: 2025-11-10 (monthly updates)
