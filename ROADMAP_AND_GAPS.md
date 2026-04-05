# JanuSec Platform: Roadmap & Gaps Analysis

## Executive Summary

JanuSec has **strong core capabilities** but faces **specific gaps** in enterprise connectors, advanced deployment modes, and compliance features. This roadmap prioritizes **production completeness** over architectural changes.

**Critical Gaps: 8-10 key items**
**Timeline to Enterprise Ready: 4-6 weeks**

---

## SECTION 1: PRODUCTION GAPS

### 1.1 Missing Vulnerability Connectors (P0 - CRITICAL)

**Gap**: Qualys & Tenable APIs not integrated
- No automated vulnerability scanning orchestration
- Can't correlate patches with incidents
- Missing CVSS enrichment for malicious executables

**Impact**:
- Organizations can't track remediation
- Threat modeling loses fidelity
- Supply chain domain incomplete

**Solution**:
```python
# src/adapters/qualys_connector.py (NEW)
- OAuth token fetch
- VM (Vulnerability Management) API
- AssetView API
- Pagination + cursor-based sync
- Vuln → artifact mapping

# src/adapters/tenable_connector.py (NEW)
- Nessus Professional API
- Tenable.io asset/vuln export
- Similar contract to Qualys adapter
```

**Effort**: 3-5 days
**Priority**: P0 (Enterprise requirement)

---

### 1.2 RBAC & Audit Logging (P1 - HIGH)

**Gap**: No fine-grained role-based access control
- All authenticated users see all data
- No tenant isolation enforcement
- No API audit trail

**Current State**:
- Basic auth (API keys)
- Tenant ID passed in request (not enforced)
- No logging of who accessed what

**Solution**:
```python
# src/security/rbac.py (NEW)
- Role definitions (analyst, manager, admin, compliance)
- Permission matrix
- Endpoint decorators for scope checking

# src/api/audit_endpoints.py (ENHANCE)
- All API calls logged with user, tenant, resource, action
- 90-day retention
- Queryable audit log endpoints
- Export for compliance

# Middleware
- Enforce tenant isolation
- Check scopes before returning data
```

**Effort**: 1-2 weeks
**Priority**: P1 (Compliance requirement)

---

### 1.3 Multi-Tenancy Hardening (P1 - HIGH)

**Gap**: Soft multi-tenancy, data leakage risks possible
- Tenant ID embedded in requests, not validated server-side
- Cache keys not tenant-scoped
- Factor synthesis context mixes tenants

**Solution**:
```python
# src/core/config/tenant_overrides.py (ENHANCE)
- Tenant context injected into all stages
- Cache keys include tenant_id
- Database queries filtered by tenant
- Redis namespacing per tenant

# tests/test_multitenancy_isolation.py (NEW)
- Ensure no cross-tenant data leakage
- Cache isolation verification
- Permission enforcement
```

**Effort**: 3-5 days
**Priority**: P1 (Security requirement)

---

### 1.4 Compliance Frameworks (P1 - HIGH)

**Gap**: No automated compliance mapping or reporting
- Controls can be mapped manually, not in-app
- No evidence collection for audits
- No CIS/NIST/ISO27001 dashboard

**Solution**:
```python
# src/core/compliance/framework_mapper.py (NEW)
- CIS Controls v8 mapping
- NIST Cybersecurity Framework
- ISO/IEC 27001:2022
- SOC 2 Type II controls

# src/api/compliance_endpoints.py (NEW)
- List applicable controls
- Show evidence (incidents tied to controls)
- Generate compliance reports
- Export for auditors

# Frontend
- Compliance dashboard
- Control status tracking
```

**Effort**: 2-3 weeks
**Priority**: P1 (Enterprise sales requirement)

---

### 1.5 Database & Performance Tuning (P2 - MEDIUM)

**Gap**: No query optimization, potential N+1 issues
- Tests pass locally, may fail at scale
- No database indexing strategy documented
- Cache invalidation may cause stale data

**Solution**:
```python
# Database optimization
- Index all frequently-queried columns (tenant_id, timestamp, status)
- Partition large tables (events, incidents) by tenant + date
- Connection pooling (PgBouncer)

# Caching strategy
- Redis with TTL for factor synthesis
- Invalidation on incident update
- Cascade invalidation for related records

# Monitoring
- Slow query logs
- Connection pool exhaustion alerts
- Cache hit ratio tracking
```

**Effort**: 1-2 weeks
**Priority**: P2 (Performance)

---

### 1.6 Error Handling & Observability (P2 - MEDIUM)

**Gap**: Limited distributed tracing, hard to debug production issues
- Logs scattered across files, no centralized logging
- No request tracing across services
- LLM errors not well captured

**Solution**:
```python
# src/core/telemetry/ (NEW)
- OpenTelemetry integration
- Distributed tracing (spans for each stage, API call, LLM request)
- Context propagation across async workers

# Structured logging
- JSON logs with trace_id, span_id
- Sent to ELK/Splunk/CloudWatch

# LLM error tracking
- Capture fallback events
- Track model failure rates
- Cost overruns alerting
```

**Effort**: 1 week
**Priority**: P2 (Observability)

---

## SECTION 2: CONNECTOR GAPS

### 2.1 Qualys & Tenable Integration (P0)

**See Section 1.1**

---

### 2.2 Cloud Posture Management (P1)

**Gap**: Incomplete CSPM implementation
- AWS Config only partially integrated
- Azure Defender missing enforcement rules
- GCP Security Command Center not connected

**Solution**:
```python
# src/adapters/cloud_posture_adapter.py (ENHANCE)
- AWS Config Rules + CloudTrail
- Azure Policy Compliance
- GCP Org Policy + Security Command Center

# Risk scoring
- Map posture findings to DREAD
- Aggregate to org-level risk
- Trend analysis
```

**Effort**: 1-2 weeks
**Priority**: P1 (Cloud organizations need this)

---

### 2.3 EDR Integration (P2)

**Gap**: Limited endpoint agent integration
- Can ingest Sysmon, but not native agent APIs
- No CrowdStrike, Sentinel One API

**Solution**:
```python
# src/adapters/crowdstrike_adapter.py (NEW)
- CrowdStrike Falcon API
- Real-time process tracking
- Behavioral indicators (IOA)

# src/adapters/sentinelone_adapter.py (NEW)
- SentinelOne Management API
- Agent telemetry export
```

**Effort**: 2-3 weeks
**Priority**: P2 (Nice-to-have, not blocking)

---

### 2.4 SIEM Integration (P2)

**Gap**: Can send to Splunk but can't consume from it
- No native Splunk connector
- No Elasticsearch ingest

**Solution**:
```python
# src/adapters/splunk_hec_receiver.py (NEW)
- HTTP Event Collector receiver
- Accept Splunk-formatted events
- Transform + ingest into pipeline

# src/adapters/elasticsearch_ingest.py (NEW)
- Elasticsearch 8.x + OpenSearch compatibility
```

**Effort**: 1 week
**Priority**: P2 (Integration convenience)

---

## SECTION 3: DOMAIN MATURITY GAPS

### 3.1 Cloud/CSPM Domain (Current: BETA → Target: PRODUCTION)

**What's Missing**:
- Resource-based permissions audit
- Data encryption at rest/in-transit
- Network segmentation rules
- Secure-by-default configurations

**Rules Needed**:
- Public S3 bucket exposure
- Overpermissioned IAM roles
- Unencrypted RDS
- VPC flow log gaps
- EBS encryption failures

**Effort**: 2 weeks
**Tests**: 15+ new rules + integration tests

---

### 3.2 eBPF/Container Domain (Current: BETA → Target: PRODUCTION)

**What's Missing**:
- Container escape detection hardening
- Kubernetes API audit integration
- Privilege escalation in containers
- Suspicious syscall patterns

**Rules Needed**:
- ptrace(2) abuse
- mprotect(2) on libc
- capset() privilege changes
- namespace isolation violations

**Effort**: 2-3 weeks
**Tests**: Container lab environment

---

### 3.3 Supply Chain Domain Enhancements (Current: PRODUCTION → Target: ADVANCED)

**What to Add**:
- Transitive dependency resolution
- License compliance tracking (GPL, AGPL warnings)
- Provenance verification (signed artifacts)
- Dependency drift detection (pinned version violations)

**Effort**: 2 weeks

---

### 3.4 API Security Domain (Current: PRODUCTION → Target: ADVANCED)

**What to Add**:
- GraphQL injection patterns
- OpenAPI spec validation
- Rate limiting bypass patterns
- API key exposure in logs/responses

**Rules Needed**: 3-5 new rules
**Effort**: 1 week

---

## SECTION 4: FEATURE ROADMAP

### Phase 1: Production Hardening (WEEKS 1-2)

- [ ] Qualys/Tenable connectors
- [ ] RBAC enforcement
- [ ] Multi-tenancy isolation validation
- [ ] Database indexing
- [ ] Stress testing at scale (10K events/sec)

### Phase 2: Compliance (WEEKS 3-4)

- [ ] CIS/NIST/ISO27001 control mapping
- [ ] Compliance reporting dashboard
- [ ] Audit log export
- [ ] Evidence collection for controls

### Phase 3: Enterprise Features (WEEKS 5-6)

- [ ] CSPM enhancement
- [ ] eBPF hardening
- [ ] EDR connector (CrowdStrike/SentinelOne)
- [ ] SIEM forwarding (Splunk HEC)
- [ ] Advanced supply chain analysis

### Phase 4: AI/ML Enhancements (WEEKS 7-8)

- [ ] Anomaly detection (unsupervised learning)
- [ ] Factor weights auto-tuning
- [ ] Custom model training on org data
- [ ] Tier 3 "forensic report" generation

---

## SECTION 5: INFRASTRUCTURE & SCALING

### 5.1 Kubernetes Deployment (MISSING)

**Current**: Docker Compose for dev/test
**Needed**: Production K8s manifests

```yaml
# Deploy patterns
- API stateless (horizontal scale)
- Event pipeline workers (process pool)
- LLM inference pod (GPU-accelerated)
- PostgreSQL (managed RDS)
- Redis (managed ElastiCache)
- Vector DB (Weaviate/Milvus)

# Helm chart
- Configurable replicas
- Resource limits/requests
- Network policies
- Pod security policies
```

**Effort**: 1-2 weeks
**Priority**: P1 (Enterprise requirement)

---

### 5.2 High Availability (MISSING)

**Gaps**:
- No load balancer configuration
- No database failover
- No Redis HA
- Single LLM client connection

**Solution**:
- Load balancer (ALB/NLB)
- Database replication + failover
- Redis Sentinel
- LLM client connection pooling + circuit breaker

**Effort**: 1 week
**Priority**: P2

---

### 5.3 Cost Optimization (PARTIAL)

**What's Tracked**: External LLM API calls
**Missing**: Full infrastructure cost model

**Solution**:
- GPU utilization metrics
- Bandwidth costs
- Database transaction costs
- Cache hit ratio optimization

**Effort**: 3-5 days
**Priority**: P3 (Nice-to-have)

---

## SECTION 6: COMPETITIVE POSITIONING GAPS

### What Competitors Have That JanuSec Doesn't

| Feature | Splunk | Sentinel | CrowdStrike | JanuSec | Gap |
|---|---|---|---|---|---|
| Live ingestion | ✓ | ✓ | ✓ | ✓ | None |
| Manual CSV analysis | ✗ | ✗ | ✗ | ✓ | **ADVANTAGE** |
| Multi-domain correlation | Partial | Partial | EDR-only | ✓ | **ADVANTAGE** |
| LLM-powered triage | ✗ | Limited | ✗ | ✓ | **ADVANTAGE** |
| Attack graph | Limited | ✓ | ✗ | ✓ | Tie |
| Cloud-agnostic | ✓ | ✗ | ✗ | ✓ | **ADVANTAGE** |
| CSPM | Limited | ✓ | Limited | Partial | **GAP** |
| EDR native | ✗ | ✗ | ✓ | Partial | Gap |
| Compliance auto-mapping | ✗ | Limited | ✗ | ✗ | **GAP** |
| Analyst-friendly UI | ✓ | ✓ | ✓ | Partial | Gap |
| Cost visibility | ✗ | Limited | ✗ | ✓ | **ADVANTAGE** |

### Key Positioning Gaps to Close

1. **Compliance reporting** - Competitors have this, JanuSec doesn't
   - 2-3 week effort to implement
   - High enterprise value

2. **CSPM completeness** - Sentinel stronger here
   - 2 week effort
   - Important for cloud-first organizations

3. **UI polish** - Competitors more mature
   - Frontend investment needed
   - Not blocking production

---

## SECTION 7: CRITICAL PATH TO MARKET

### Minimum Viable Product (MVP) → Production

**Current State**: 75-80% of MVP is complete

**Remaining 20-25%**:
1. [ ] Qualys/Tenable APIs (3 days)
2. [ ] RBAC + multi-tenancy hardening (3 days)
3. [ ] Database optimization (2 days)
4. [ ] Stress testing + benchmarking (3 days)
5. [ ] Kubernetes manifests (3 days)
6. [ ] Documentation + runbooks (2 days)

**Timeline**: 2-3 weeks to production
**Go/No-Go**: Ready (dependencies are well-understood)

---

### Enterprise Ready → Market Leadership

**Additional 6-8 weeks for**:
- Compliance frameworks
- Advanced CSPM/eBPF
- EDR integrations
- UI/UX refinements
- Sales enablement materials

---

## SECTION 8: STRATEGIC RECOMMENDATIONS

### For Next Sprint:

1. **Prioritize P0/P1 items**:
   - Qualys/Tenable (customer asks)
   - RBAC + tenancy (security requirement)
   - Compliance mapping (sales differentiator)

2. **Avoid scope creep**:
   - Don't build EDR connector (P2, not blocking)
   - Don't overengineer CSPM (Partial is acceptable)
   - Skip Tier 3 "forensic report" (nice-to-have)

3. **Run parallel tracks**:
   - Infrastructure team: Kubernetes manifests
   - Backend team: Qualys/Tenable + RBAC
   - QA team: Stress testing + multi-tenancy validation

4. **Customer feedback**:
   - Run pilot with 2-3 beta customers
   - Iterate on most-requested features
   - Validate pricing model

### Success Metrics:

- **Deployment**: 1-click Kubernetes deployment working
- **Scale**: 100K events/day processed without errors
- **Reliability**: 99.9% uptime in production week 1
- **User satisfaction**: Pilot customers rate 4.5+ / 5.0

---

## APPENDIX: Detailed Implementation Checklist

### Qualys Connector
- [ ] Research Qualys API docs
- [ ] Implement OAuth token fetch
- [ ] Build VM API client
- [ ] Map vuln → artifact
- [ ] Add pagination + cursor
- [ ] Write 5 tests
- [ ] Integration test with real API

### RBAC Implementation
- [ ] Define roles + permissions
- [ ] Create permission matrix
- [ ] Implement @require_scopes decorator
- [ ] Enforce in all endpoints
- [ ] Write 20+ tests
- [ ] Document in API guide

### Compliance Mapping
- [ ] Research CIS/NIST/ISO27001
- [ ] Design control → evidence mapping
- [ ] Implement mapping engine
- [ ] Build compliance dashboard
- [ ] Export compliance report
- [ ] Test with real audit firm

---

## CLOSING STATEMENT

JanuSec is **production-ready in its core capabilities** but needs **2-3 weeks of hardening** before enterprise deployment. The roadmap is **clear, achievable, and prioritized** by customer value.

**Recommendation**: Launch production pilot with completed features now, add connectors/compliance over 4-6 weeks.
