# What's Left To Do - JanuSec Platform Status

**Last Updated:** 2025-12-06
**Branch:** fix/graph-session-syntax
**Platform Readiness:** 77-82% Enterprise-Ready

---

## Recent Wins (Last 5 Commits)

✅ **Fixed** - Graph session syntax error (stray literals removed)
✅ **Added** - Deterministic smoke testing script + SMOKE.md
✅ **Implemented** - Deep Analyze modal with Basic/Advanced modes
✅ **Added** - Deterministic deep_analyze stages and lite-mode CI
✅ **Enhanced** - Executive summary reporting with LLM integration

---

## Critical Blockers (P0) - Must Fix Before Production

### 🔴 1. HopGraph Persistence & Scalability
**Status:** ⚠️ BLOCKING
**Impact:** In-memory graph crashes on restart, loses all attack chains
**Effort:** 1 week (1 engineer)
**Priority:** P0

**What's Missing:**
- [ ] SQLite backend implementation (`src/core/graph/persistence/sqlite_backend.py`)
- [ ] WAL (Write-Ahead Logging) for crash recovery
- [ ] Graph snapshot/restore on startup
- [ ] Periodic pruning of old edges (7-day TTL)
- [ ] Background compaction job

**Files to Create/Modify:**
```
NEW: src/core/graph/persistence/sqlite_backend.py
MOD: src/core/graph/hopgraph_lite.py (add persistence calls)
MOD: src/orchestrator/background.py (add prune job)
```

**Acceptance Criteria:**
- Graph survives server restart
- Edges auto-prune after 7 days
- Startup loads last N days of graph data
- WAL recovery works after crash

---

### 🔴 2. Threat Intel Integration (Currently Stubbed)
**Status:** ⚠️ CRITICAL (40% complete)
**Impact:** Misses 50% of known threats, no real IoC matching
**Effort:** 3-4 weeks (2 devs)
**Priority:** P0

**What's Stubbed (Returns Fake Data):**
- [ ] MISP integration (returns `1.2.3.X`, `bad-example.test`)
- [ ] OpenCTI GraphQL actor/technique mapping
- [ ] Abuse.ch SSLBL/MalwareBazaar feeds
- [ ] AlienVault OTX pulse subscriptions
- [ ] STIX/TAXII feed support
- [ ] Custom CSV/JSON feed uploads

**Files Affected:**
```
src/integrations/threat_intel_client.py (lines 246-252 - stub fallback)
```

**Real Implementation Needed:**
```python
# Week 1: MISP
from pymisp import PyMISP
pm = PyMISP(misp_url, misp_key, False, 'json')
result = pm.search(controller='attributes', last='24h', pythonify=True)

# Week 2: Abuse.ch feeds
# Parse https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv

# Week 3: OpenCTI actor mapping
from pycti import OpenCTIApiClient
cli = OpenCTIApiClient(opencti_url, opencti_key)

# Week 4: Testing + validation
```

**Success Metrics:**
- 100K+ IoCs ingested from 5+ feeds
- <1ms lookup latency per IoC (cached)
- 90%+ match rate on known-bad test dataset

---

### 🔴 3. Vendor Connectors (Currently Minimal)
**Status:** ⚠️ CRITICAL (20% complete)
**Impact:** Cannot ingest from CrowdStrike, Splunk, Sentinel
**Effort:** 2-3 weeks
**Priority:** P0

**Missing Connectors:**
- [ ] CrowdStrike Falcon API integration
- [ ] Splunk HEC (HTTP Event Collector)
- [ ] Microsoft Sentinel REST API
- [ ] Palo Alto Cortex XDR
- [ ] SentinelOne API
- [ ] Elastic Security

**Files to Create:**
```
NEW: src/adapters/crowdstrike_falcon.py
NEW: src/adapters/splunk_hec.py
NEW: src/adapters/sentinel_api.py
NEW: src/adapters/palo_alto_xdr.py
```

---

### 🔴 4. Multi-Tenant Isolation (Security Risk)
**Status:** ⚠️ CRITICAL
**Impact:** Risk of cross-tenant data leakage
**Effort:** 1 week
**Priority:** P0

**What's Missing:**
- [ ] tenant_id propagation in session build
- [ ] Per-tenant session directory segregation
- [ ] Row-level security enforcement in queries
- [ ] Tenant isolation tests

**Files to Modify:**
```
src/api/csv_endpoints.py
src/core/graph/hopgraph_lite.py
src/db/database.py
```

---

## High Priority (P1) - Needed for Enterprise

### 🟡 5. RBAC (Role-Based Access Control)
**Status:** API key only, no role granularity
**Effort:** 1 week
**Priority:** P1

**What's Missing:**
- [ ] Role definitions (viewer, analyst, admin)
- [ ] Route decorators enforcing scope
- [ ] Permission checks in endpoints
- [ ] Admin UI for user/role management

---

### 🟡 6. Network Hunter Depth (APT Detection)
**Status:** 65% complete
**Effort:** 2-3 weeks
**Priority:** P1

**What Works:**
✅ JA3/JA3S/JA4/HASSH rarity tracking
✅ DNS tunneling detection
✅ Beaconing detection (multi-scale CV + Lomb-Scargle)
✅ User-Agent rarity
✅ Port scatter/scan detection

**What's Missing:**
- [ ] Kerberos abuse detection (golden ticket, silver ticket)
- [ ] Process injection patterns (DLL injection, CreateRemoteThread)
- [ ] Credential harvesting (LSASS access patterns)
- [ ] Lateral movement detection (beyond SMB/RDP/WinRM)
- [ ] Certificate chain analysis (intermediate CAs, validity gaps)

**Files to Modify:**
```
src/modules/network_hunter.py
```

---

### 🟡 7. HopGraph Determinism & Ordering
**Status:** Partial
**Effort:** 1-2 weeks
**Priority:** P1

**Issues:**
- [ ] Sequence edges added but sequence_score still <0.25
- [ ] WAL replay order can vary (causes flaky benchmarks)
- [ ] Intermediate process steps not always surfaced
- [ ] Beam search can drop GT-adjacent paths early

**Fixes Needed:**
- [ ] Stable edge insertion ordering on WAL replay (sort by ts, src, dst, etype)
- [ ] Adaptive path completion (boost chains with ordered GT subsequences)
- [ ] Selective pruning (down-rank runs edges without adjacent high-preference edges)
- [ ] Sequence score bonus for contiguous gt_sequence edges

**Files to Modify:**
```
src/core/graph/hopgraph_lite.py
src/core/hunt/hopgraph_light.py
```

---

### 🟡 8. CSV Security & Sanitization
**Status:** Missing
**Effort:** 3 days
**Priority:** P1 (Security)

**Risks:**
- CSV injection attacks
- Resource exhaustion (unlimited file size)
- Malicious headers

**Mitigations Needed:**
- [ ] Sanitize headers (strip control chars)
- [ ] Enforce size limits (10MB default, configurable)
- [ ] Streaming parse with row cap (10K rows)
- [ ] Input validation for column names

---

## Medium Priority (P2) - Production Polish

### 🟢 9. Observability & Metrics
**Status:** 50% complete
**Effort:** 1 week
**Priority:** P2

**Current:**
✅ 50+ Prometheus metrics
✅ Latency histograms
✅ Drift detection

**Missing:**
- [ ] Per-edge type counts (hopgraph_edge_type_total)
- [ ] Prune stats (hopgraph_edges_pruned_total)
- [ ] Decay distribution metrics
- [ ] Forced edge injection audit (hopgraph_forced_edge_injections_total)

---

### 🟢 10. Test Coverage & CI Regression Guards
**Status:** Basic tests exist
**Effort:** 1-2 weeks
**Priority:** P2

**What's Missing:**
- [ ] CI step comparing metrics vs baseline JSON
- [ ] Fail build if recall or sequence_score drop > tolerance
- [ ] Unit tests for explain_chain ordering
- [ ] Unit tests for gt_sequence multiplier application
- [ ] Unit tests for decay floor retention
- [ ] Benchmark harness with automated thresholding

**Acceptance Criteria:**
- recall_mean >= 0.38 (current: 0.40)
- sequence_score_mean >= 0.20 (current: 0.244)
- precision_mean variance ±0.10

---

### 🟢 11. Configuration Management
**Status:** Env var sprawl
**Effort:** 3-5 days
**Priority:** P2

**Issues:**
- No centralized config schema
- No validation on startup
- Hard to discover available settings

**Fixes Needed:**
- [ ] Add config loader with Pydantic schema
- [ ] Validation errors on startup
- [ ] `/api/v1/config` snapshot endpoint
- [ ] Admin UI for config management

---

### 🟢 12. Edge Weight Calibration
**Status:** Needs tuning
**Effort:** 1 week
**Priority:** P2

**Issues:**
- High weight (5.0) forced edges may overshadow legitimate patterns
- No normalization within paths

**Fixes Needed:**
- [ ] Weight capping & relative scaling
- [ ] Normalize within path (sum_weights / len(edges))
- [ ] Log bias metrics

---

## Low Priority (P3) - Future Enhancements

### 🔵 13. Auto-Incident Generation
**Status:** Manual
**Effort:** 1-2 weeks
**Priority:** P3

**What's Missing:**
- [ ] Auto-create incidents when combined factors exceed threshold
- [ ] Configurable incident templates
- [ ] SOAR integration for auto-tickets

---

### 🔵 14. TFT (Temporal Fusion Transformer) Predictive ML
**Status:** Stubbed (15% complete)
**Effort:** 4-6 weeks
**Priority:** P3 (Optional)

**What's Missing:**
- Full TFT model training pipeline
- Time-series prediction for anomaly forecasting
- Model serving infrastructure

---

### 🔵 15. UI Drill-Down Improvements
**Status:** 50% complete
**Effort:** 2-3 weeks
**Priority:** P3

**What Works:**
✅ Basic factor display
✅ Timeline view
✅ Graph visualization

**What's Missing:**
- [ ] Interactive graph zoom/pan
- [ ] Node detail panels
- [ ] Path highlighting
- [ ] Export to PDF/JSON

---

## Testing Status

**Current Test Collection:**
```bash
# Running in background...
python -m pytest --collect-only
```

**Known Test Categories:**
- ✅ Smoke tests (deterministic)
- ✅ Core functionality tests
- ✅ Custody hash chain tests
- ✅ Auto-generated incident tests
- ✅ ASN seeding tests
- ⚠️ Some tests may fail due to missing optional dependencies

---

## Quick Wins (Can Do This Week)

1. **CSV Sanitization** (3 days)
   - Strip control chars from headers
   - Add file size limits
   - Add row count caps

2. **Deterministic WAL Replay** (2 days)
   - Sort edges by (ts, src, dst, etype) when HOPGRAPH_DETERMINISTIC=true

3. **Config Schema** (3 days)
   - Create Pydantic config model
   - Add validation on startup
   - Expose /api/v1/config endpoint

4. **RBAC Skeleton** (5 days)
   - Add role enum (viewer, analyst, admin)
   - Add role decorator for routes
   - Basic permission checks

---

## Timeline Estimates

| Phase | Duration | Deliverables |
|-------|----------|--------------|
| **P0 Blockers** | 4-6 weeks | HopGraph persistence, threat intel, vendor connectors, tenant isolation |
| **P1 High Priority** | 3-4 weeks | RBAC, network hunter depth, determinism, CSV security |
| **P2 Production Polish** | 2-3 weeks | Observability, test coverage, config management |
| **P3 Future** | 6-8 weeks | Auto-incidents, TFT ML, UI enhancements |

**Total to Production-Ready:** 8-10 weeks (2-2.5 months) with 2-3 engineers

---

## Roadmap Phasing

### Sprint 1 (Weeks 1-2): Stability
- [ ] HopGraph SQLite persistence
- [ ] Deterministic WAL replay
- [ ] CSV sanitization
- [ ] RBAC skeleton

### Sprint 2 (Weeks 3-4): Integrations
- [ ] MISP threat intel integration
- [ ] Abuse.ch feeds
- [ ] CrowdStrike connector
- [ ] Splunk HEC connector

### Sprint 3 (Weeks 5-6): Enterprise Hardening
- [ ] Tenant isolation enforcement
- [ ] Network hunter depth (Kerberos, credential access)
- [ ] Observability metrics expansion
- [ ] CI regression guards

### Sprint 4 (Weeks 7-8): Polish & Testing
- [ ] OpenCTI integration
- [ ] Sentinel connector
- [ ] Config management UI
- [ ] Comprehensive test suite

---

## Code TODOs Found in Codebase

**From grep search:**
- `src/modules/network_hunter.py` - Kerberos abuse detection (TODO)
- `src/integrations/threat_intel_client.py:246-252` - MISP stub fallback (FIXME)
- Various pyc files - Not actionable (library code)

---

## Documentation Status

**Exists:**
- ✅ BACKLOG_SUMMARY.md
- ✅ PRODUCTION_READINESS_CHECKLIST.md
- ✅ ENTERPRISE_READINESS_GAPS.md
- ✅ CEO_READINESS_GAP_ANALYSIS.md
- ✅ PLATFORM_PRODUCTION_READINESS_GAP_ANALYSIS.md

**Missing:**
- [ ] API documentation (OpenAPI/Swagger)
- [ ] Developer onboarding guide
- [ ] SOC analyst user guide
- [ ] Admin configuration guide

---

## How to Use This Document

1. **Immediate Focus:** Start with P0 blockers (HopGraph persistence, threat intel)
2. **Security Next:** RBAC, tenant isolation, CSV sanitization
3. **Polish Later:** Observability, config management, UI improvements
4. **Track Progress:** Update checkboxes as you complete items
5. **Prioritize:** Focus on items blocking production launch first

---

## Questions & Decisions Needed

1. **HopGraph Persistence:** SQLite vs PostgreSQL backend?
2. **Tenant Isolation:** Separate graph instances per tenant vs shared with tagging?
3. **Threat Intel:** Which feeds are priority? (MISP first? OTX? Both?)
4. **RBAC Scope:** Just route-level or also field-level permissions?
5. **Timeline:** What's the hard deadline for production launch?

---

## Next Steps

1. Review this document with team
2. Prioritize blockers based on business needs
3. Assign owners to each major task
4. Set sprint goals (2-week sprints recommended)
5. Create detailed implementation plans for P0 items
6. Set up CI/CD pipeline for regression testing

---

**Generated:** 2025-12-06
**Source Files:**
- PRODUCTION_READINESS_CHECKLIST.md
- ENTERPRISE_READINESS_GAPS.md
- PLATFORM_PRODUCTION_READINESS_GAP_ANALYSIS.md
- CEO_READINESS_GAP_ANALYSIS.md
- BACKLOG_SUMMARY.md
- Git commit history (last 20 commits)
- Grep search for TODOs/FIXMEs
