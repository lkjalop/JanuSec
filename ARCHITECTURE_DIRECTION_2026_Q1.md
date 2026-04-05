# Janusec — Architecture Deep Dive, Status Matrix & Go-Live Direction
**Date**: 2026-03-27 | **Branch**: feat/webhook-guard-middleware-only-verification

---

## Table of Contents
1. [Pipeline Architecture](#1-pipeline-architecture)
2. [Network + Endpoint Focus Verification](#2-network--endpoint-focus-verification)
3. [LLM Tier 1 & 2 Summaries](#3-llm-tier-1--2-summaries)
4. [Persona Report Generation](#4-persona-report-generation)
5. [HopGraph Attack Correlation Engine](#5-hopgraph-attack-correlation-engine)
6. [Complete Status Matrix](#6-complete-status-matrix)
7. [Cloud Sieve Direction (Azure / AWS / GCP)](#7-cloud-sieve-direction-azure--aws--gcp)
8. [Self-Hosted vs SaaS Direction](#8-self-hosted-vs-saas-direction)
9. [Go-Live in 3–4 Weeks Priority Plan](#9-go-live-in-34-weeks-priority-plan)
10. [ASCII Architecture Diagram](#10-ascii-architecture-diagram)
11. [User Flows](#11-user-flows)
12. [Files to Edit / Refactor / Create](#12-files-to-editrefactorcreate)

---

## 1. Pipeline Architecture

### Total Stages: 33 (across 3 groups)

```
src/core/event_pipeline/stages/__init__.py   — stage registry
src/core/event_pipeline/pipeline.py          — execution engine (498 lines)
src/core/event_pipeline/stages/
  ├── primitives.py    — process/auth/identity stages
  ├── network.py       — beacon, egress, domain novelty, pcap
  ├── advanced.py      — hunt lanes, correlation, embedding
  ├── sbom.py          — SBOM vulnerability stages
  └── base.py          — BaseStage ABC
```

### FAST / CORE Group (24 stages — always run)

| # | Stage | Purpose | File |
|---|-------|---------|------|
| 1 | `baseline` | Regex pattern matching | primitives.py |
| 2 | `regex` | Rule-based detection | primitives.py |
| 3 | `parent_child` | Process parent-child chains | primitives.py |
| 4 | `endpoint` | Windows/Linux process signals | primitives.py |
| 5 | `email_enrichment` | Email metadata enrichment | primitives.py |
| 6 | `auth_burst` | Auth anomaly detection | primitives.py |
| 7 | `identity` | Identity-based enrichment | primitives.py |
| 8 | `graph` | Entity relationship graph queries | advanced.py |
| 9 | `adaptive_pre` | Pre-processing adaptive filter | advanced.py |
| 10 | `packet_summary` | Network packet summarization | network.py |
| 11 | `threat_intel` | IOC/threat intel lookups | advanced.py |
| 12 | `supply_chain_npm` | NPM supply chain checks | advanced.py |
| 13 | `supply_chain_cicd` | CI/CD supply chain checks | advanced.py |
| 14 | `sbom_exec` | SBOM execution analysis | sbom.py |
| 15 | `sbom_vuln` | SBOM vulnerability detection | sbom.py |
| 16 | `ebpf_analysis` | eBPF kernel monitoring | primitives.py |
| 17 | `rare_token` | Token rarity detection | primitives.py |
| 18 | `hunt_lanes` | Pluggable threat hunting lanes | advanced.py |
| 19 | `correlation` | Multi-factor correlation synthesis | advanced.py |
| 20 | `quality_filter` | QA/quality floor filtering | advanced.py |
| 21 | `mapping` | MITRE/STRIDE/DREAD mapping | advanced.py |
| 22 | `cluster_dedupe` | Alert deduplication | advanced.py |
| 23 | `coverage_tracker` | Detection coverage tracking | advanced.py |
| 24 | `embedding` | Vector embedding generation | advanced.py |

### HEAVY Group (5 stages — skipped under load or high confidence)

| # | Stage | Timeout | Skip Condition |
|---|-------|---------|----------------|
| 1 | `beacon` | 30s | `skip_beacon_under_load` |
| 2 | `egress` | 30s | `skip_egress_under_load` |
| 3 | `domain_novelty` | 30s | `skip_domain_novelty_under_load` |
| 4 | `pcap_session` | 30s | high confidence gate |
| 5 | `binary_payload` | 60s | always gated |

**Heavy skip threshold**: `heavy_skip_confidence = 0.8` (per-tenant override available)

### EXTERNAL Group (2 stages — optional, feature-flagged)

| # | Stage | Requirement |
|---|-------|-------------|
| 1 | `cert_analysis` | `modules.certificate_analysis` |
| 2 | `http_header` | `modules.http_header_analysis` |

### Execution Flow

```
Event arrives
     │
     ▼
[1] Confidence gate ──► (confidence >= heavy_skip_threshold) ──► skip HEAVY
     │
     ▼
[2] Load gate ──────────► (under load) ──────────────────────────► skip beacon/egress/domain_novelty
     │
     ▼
[3] Run CORE stages sequentially (with per-stage timeout)
     │
     ▼
[4] Run HEAVY stages (if not skipped) — optional process pool isolation
     │
     ▼
[5] Run EXTERNAL stages (if feature enabled)
     │
     ▼
[6] Factor synthesis + terminal verdict
     │
     ▼
[7] T1 Summary (deterministic) → persisted decision
     │
     ▼
[8] T2 Queue (async LLM) → enriched alert record
```

---

## 2. Network + Endpoint Focus Verification

**YES** — the platform is now squarely focused on network + endpoint telemetry.

### Network Telemetry

```
src/live/zeek_adapter.py               — Zeek JSON log parser
src/core/event_pipeline/stages/
  └── network.py                       — beacon, egress, domain novelty, pcap
deploy/connectors/
  ├── zeek_sidecar.compose.yml         — Docker Zeek sidecar
  └── fluentbit_zeek_to_http.conf      — FluentBit → HTTP forwarding
```

**Zeek log types parsed**: `conn`, `dns`, `http`, `ssl` (JA3/JA3S)

### Endpoint Telemetry

```
src/core/event_pipeline/stages/primitives.py   — parent_child, endpoint, auth_burst
src/core/detectors/auth_burst.py               — burst detection
src/connectors/sysmon_evtx.py                  — Sysmon event log ingest
```

**Supported sources**: Sysmon (Windows), WinEvtX, KAPE artifacts (scaffold)

### On-Demand Telemetry (Evidence-Driven)

```
src/artifact/memory_acquisition.py     — on-demand memory collection
src/artifact/memory_pipeline.py        — memory forensics pipeline
src/core/event_pipeline/pipeline.py    — _attach_memory_jobs() (lines 473-497)
```

**Trigger**: Evidence found during pipeline analysis can request KAPE/memory collection jobs.
Evidence-driven → on-demand: if beacon stage + egress stage both fire, memory job queued.

### Real-Time Streaming Ingest

```
src/api/stream_ingest.py               — POST /api/v1/ingest/stream
```
- Token-bucket rate limiting (per-tenant)
- Deduplication (15min hash cache)
- Backpressure: `drop_oldest` | `reject` | `block`
- Max payload: 10MB

### Batch Upload Ingest

```
src/api/csv_endpoints.py               — POST /api/v1/csv/ingest
src/api/upload_endpoints.py            — POST /api/v1/upload/*
src/api/ingest_api.py                  — POST /api/v1/ingest/csv_rows
```

### Webhook Ingest (Third-Party Alerts)

```
src/api/webhook_middleware.py          — WebhookGuardMiddleware
```
- HMAC + timestamp validation
- SQLite replay cache (5000 entries)
- Exempt: CrowdStrike, Sentinel, Splunk

---

## 3. LLM Tier 1 & 2 Summaries

### Tier 1 (Deterministic — No LLM Required)

```
src/core/correlation/tier1_summarizer.py   — summarize_tier1(event)
src/api/llm_tier1.py                       — REST endpoint
src/api/llm_tier1_local.py                 — offline version
```

**Output schema**:
```json
{
  "title": "Suspicious Parent-Child Process Chain",
  "score": 0.87,
  "mitre": ["T1059.001", "T1055"],
  "reason": ["cmd.exe spawned by Excel", "unsigned binary injection"],
  "top_factors": [{"name": "parent_child_anomaly", "score": 0.82}]
}
```

**Status**: ✅ PRODUCTION — runs on every event, no LLM needed.

### Tier 2 (LLM-Augmented — Async Queue)

```
src/api/tier2_endpoints.py             — POST /api/v1/tier2/enrich_batch
src/api/llm_tier2_rag.py              — RAG-augmented generation
src/queue/redis_tier2.py              — async job queue
src/integrations/llm_client.py        — multi-provider abstraction
```

**Providers**: Ollama (default/local), OpenAI, Anthropic Claude
**Fallback chain**: Ollama → OpenAI → Anthropic → LocalDeterministicClient

**Output schema**:
```json
{
  "summary": "An attacker leveraged Excel macro → cmd.exe process injection...",
  "structured": {"attack_phase": "Execution", "severity": "Critical"},
  "confidence": 0.91,
  "recommendations": ["Isolate host", "Pull memory dump"],
  "next_steps": ["Check lateral movement from host", "Review DKIM fail on sender"],
  "cost": 0.0023,
  "model": "llama3"
}
```

**Circuit breaker**: 5 failures → 60s trip
**Status**: ✅ PRODUCTION — async, cost-tracked, circuit-broken.

---

## 4. Persona Report Generation

```
src/analysis/persona_format.py         — persona prompt templates
src/api/executive_report_endpoints.py  — executive dashboard
src/api/report_endpoints.py            — HTML/PDF report generation (1379 lines)
src/reporting/comprehensive_report_generator.py — HTML builder
```

### Three Personas

| Persona | Audience | Focus | Output |
|---------|----------|-------|--------|
| **Analyst** | SOC Tier 1/2 | What happened, MITRE mapping, indicators | 4–6 technical sentences |
| **Manager** | Security manager | Business impact, severity, prioritization | High-level with severity label |
| **Forensics** | IR team | Investigation checklist, artifacts, timeline | Detailed forensics checklist |

### Report Formats

- **HTML report**: `POST /api/v1/report/generate`
- **PDF export**: `POST /api/v1/report/generate_pdf` (WeasyPrint)
- **Email dispatch**: `POST /api/v1/report/email_summary`
- **Executive dashboard**: `GET /api/v1/executive/dashboard`
- **Coverage report**: `GET /api/v1/executive/coverage` (MITRE, STRIDE, DREAD, CVSS, MAESTRO, PASTA)

**Status**: ✅ PRODUCTION — HTML/PDF, email dispatch, executive dashboard all working.

---

## 5. HopGraph Attack Correlation Engine

```
src/core/graph/hopgraph_lite.py            — HopGraphLite (in-memory + SQLite)
src/core/correlation/hunt_correlation.py   — CorrelationEngine (54 factors)
src/core/correlation/factor_constants.py   — factor definitions
src/api/graph_session_endpoints.py         — session CRUD
src/core/hunt/lanes/                       — pluggable hunt lanes
  ├── ja3_novelty.py
  └── process_lineage.py
```

### HopGraphLite — Entity Graph

```
Entities: user, host, process, ip, domain
Edges typed:
  AUTH edge  — TTL 72h
  NET edge   — TTL 24h
  PROC edge  — TTL 12h

Sliding window: 15 minutes (real-time)
Max events:    5,000 in memory
Persistence:   SQLite (HOPGRAPH_PERSISTENCE_ENABLED=1)
```

### Correlation Engine — 54 Factors

Sample factors:
```
CORR_BEACON_RARE_JARM              — C2 beacon by JARM fingerprint
CORR_C2_MULTI_CHANNEL              — multi-channel C2 beacon
CORR_DNS_TUNNEL_THROUGHPUT         — DNS exfiltration volume
CORR_EGRESS_EXFIL_PATTERN          — data exfiltration pattern
CORR_LATERAL_PIVOT_POSSIBLE        — lateral movement signal
CORR_RANSOMWARE_BEACON_CHAIN       — ransomware + beacon combo
CORR_ANOMALOUS_USER_AGENT_CHAIN    — user-agent anomaly chain
... 47 more
```

### Hunt Lanes (Pluggable)

| Lane | Detection Focus |
|------|----------------|
| `process_lineage` | Process parent-child chains |
| `ja3_novelty` | Novel JA3 TLS fingerprints |
| `email_bec` | Business email compromise |
| `privilege_misuse` | Privilege escalation (feature-flagged) |
| `host_pivot` | Host pivoting (feature-flagged) |

**Status**: ✅ Core graph + correlation IMPLEMENTED, pattern synthesis ~70% complete.

---

## 6. Complete Status Matrix

| Component | Status | Grade | Notes |
|-----------|--------|-------|-------|
| **INGESTION** | | | |
| Real-time streaming ingest | ✅ Done | Production | Rate-limited, deduplicated, backpressured |
| Batch CSV ingest | ✅ Done | Production | Multi-row, file upload |
| Webhook ingest (HMAC guard) | ✅ Done | Production | Replay protection, vendor exemptions |
| On-demand forensic trigger | ⚠️ Partial | Demo | Memory/KAPE job scaffold |
| **PIPELINE** | | | |
| 24 FAST/CORE stages | ✅ Done | Production | Modular, group-aware |
| 5 HEAVY stages | ✅ Done | Production | Load-gated, timeout |
| 2 EXTERNAL stages | ⚠️ Partial | Demo | Feature-flagged |
| Circuit breaker (load) | ✅ Done | Production | Confidence + load gates |
| Per-tenant stage overrides | ✅ Done | Production | JSON config |
| Process pool isolation | ✅ Done | Production | For heavy stages |
| **DETECTION** | | | |
| Regex / baseline rules | ✅ Done | Production | Fast deterministic |
| Zeek network telemetry | ✅ Done | Production | conn/dns/http/ssl |
| Beacon detection (C2) | ✅ Done | Production | JA3, JARM, interval |
| Egress / exfil detection | ✅ Done | Production | Volume spike, DNS tunnel |
| Domain novelty | ✅ Done | Production | Sliding window tracker |
| Process parent-child | ✅ Done | Production | Windows + Linux |
| Auth burst detection | ✅ Done | Production | Temporal burst |
| SBOM + vuln detection | ✅ Done | Enterprise | KEV/EPSS enriched |
| Supply chain (NPM/CI) | ✅ Done | Enterprise | |
| eBPF kernel monitoring | ⚠️ Partial | Demo | Stage present, limited depth |
| PCAP session analysis | ⚠️ Partial | Demo | 30s timeout, scaffold |
| Binary payload analysis | ⚠️ Partial | Demo | Stub with timeout |
| **LLM / AI** | | | |
| Tier 1 deterministic summary | ✅ Done | Production | No LLM required |
| Tier 2 LLM summary (async) | ✅ Done | Production | Ollama/OpenAI/Anthropic |
| RAG-augmented summaries | ✅ Done | Production | Vector retrieval |
| LLM cost tracking | ✅ Done | Production | Per-tenant budget |
| LLM circuit breaker | ✅ Done | Production | 5-failure → 60s trip |
| **REPORTING** | | | |
| Analyst persona report | ✅ Done | Production | |
| Manager persona report | ✅ Done | Production | |
| Forensics persona report | ✅ Done | Production | |
| HTML report generation | ✅ Done | Production | WeasyPrint PDF too |
| Executive dashboard | ✅ Done | Production | Coverage, hunts, sessions |
| Email dispatch | ✅ Done | Production | SMTP integration |
| **HOPGRAPH / CORRELATION** | | | |
| HopGraphLite (in-memory) | ✅ Done | Production | 15min window, 5k events |
| SQLite persistence backend | ✅ Done | Production | Restart-safe |
| 54-factor correlation engine | ✅ Done | Production | Temporal window 5min |
| Pattern synthesis (advanced) | ⚠️ Partial | Demo | ~70% complete |
| Graph session API | ✅ Done | Production | Reconstruct + PPR |
| Hunt lanes (ja3/lineage/bec) | ✅ Done | Production | 3 active, 2 feature-flagged |
| **CLOUD CONNECTORS** | | | |
| AWS CloudTrail | ✅ Done | Production | Checkpointed incremental |
| AWS CloudWatch | ✅ Done | Production | |
| AWS GuardDuty | ✅ Done | Production | |
| AWS SecurityHub | ✅ Done | Production | |
| AWS VPC Flow Logs | ✅ Done | Production | |
| AWS S3 Access Logs | ✅ Done | Production | |
| GCP Asset Inventory | ⚠️ Partial | Demo | Scaffold |
| GCP IAM Audit | ⚠️ Partial | Demo | Scaffold |
| Azure Event Hub | ❌ Stub | Roadmap | See Section 7 |
| Azure IAM/ARM logs | ❌ Stub | Roadmap | iam_azure_arm.py scaffold |
| **INFRASTRUCTURE** | | | |
| Multi-tenancy (full) | ✅ Done | Enterprise | Fully enforced |
| Single-tenant bypass | ✅ Done | Production | DEFAULT_TENANT=default |
| Auth (API key + OIDC) | ✅ Done | Production | Rate limited |
| Per-tenant metrics | ✅ Done | Enterprise | Prometheus labels |
| Per-tenant LLM budget | ✅ Done | Enterprise | Hard cap enforcement |
| Redis queue (T2) | ✅ Done | Production | Async LLM jobs |
| SSE decisions stream | ✅ Done | Production | Real-time push |

---

## 7. Cloud Sieve Direction (Azure / AWS / GCP)

### Your Vision (The "Security Sieve" Model)

> Clients wire their cloud telemetry (Azure Monitor, CloudTrail, GCP Audit Logs) into Janusec.
> Janusec acts as a sieve — ingesting high-volume noise, filtering good/bad/suspicious, applying
> Tier 1 + Tier 2 LLM summaries, and generating persona-based reports. No complex SIEM needed.

**This is partially built (AWS 100%, GCP ~30%, Azure ~5%).**

### What to Build for Azure (the biggest gap)

```
Architecture:
  Azure Monitor → Diagnostic Settings → Azure Event Hub
                                               │
                              ┌────────────────┘
                              ▼
                    [Janusec Event Hub Connector]
                    src/connectors/azure/event_hub.py   ← CREATE
                              │
                    Normalise → canonical_envelope()
                              │
                    Ingest → POST /api/v1/ingest/stream
                              │
                    Pipeline → 24 fast stages
                              │
                    T1 Summary → persisted decision
                              │
                    T2 Queue  → LLM-enriched alert
                              │
                    Persona Report → Analyst/Manager/Forensics
```

### Azure Event Hub Sources to Wire

| Azure Source | Telemetry Type | Priority |
|-------------|----------------|----------|
| Azure AD Sign-in Logs | Identity / auth | P0 |
| Azure AD Audit Logs | IAM changes | P0 |
| Microsoft Defender for Cloud | Security findings | P0 |
| Azure Monitor Activity Log | ARM resource changes | P1 |
| Azure Sentinel (preview) | SIEM alerts | P1 |
| Microsoft 365 Defender | Endpoint/email alerts | P1 |
| Azure Network Watcher | Flow logs | P2 |
| Azure Key Vault logs | Secret access | P2 |

### New Files to Create

```
src/connectors/azure/
├── __init__.py
├── base.py                  — AzureConnectorBase (SAS/AAD auth, checkpoint)
├── event_hub.py             — Azure Event Hub consumer (AMQP via azure-eventhub)
├── entra_id.py              — Entra ID sign-in + audit log fetcher
├── defender_cloud.py        — Microsoft Defender for Cloud findings
└── normalizer.py            — Azure → canonical_envelope() mapping
```

### AWS (Already Production — just document it better)

```
src/connectors/aws/
├── base.py           ✅
├── cloudtrail.py     ✅
├── cloudwatch.py     ✅
├── guardduty.py      ✅
├── securityhub.py    ✅
├── vpc_flow.py       ✅
├── s3_access.py      ✅
├── iam_changes.py    ✅
└── config_snapshot.py ✅
```

### GCP (Needs completion)

```
src/connectors/gcp/
├── base.py           ⚠️ — needs checkpoint + error handling
├── pubsub.py         ❌ — CREATE: Pub/Sub consumer for log sinks
├── scc.py            ❌ — CREATE: Security Command Center findings
└── audit_log.py      ⚠️ — partial, needs normalizer
```

---

## 8. Self-Hosted vs SaaS Direction

### Recommendation: Go Self-Hosted First

**Pros**:
- Each client controls their own data (air-gap capable)
- No shared infrastructure risk
- Simplifies compliance (SOC2, ISO27001) — client's responsibility
- Speeds up sales — no "where does my data go?" objection
- Can pivot to hosted later once revenue justifies it

**Multi-tenancy is already bypassable**:
```bash
# Single-tenant mode
DEFAULT_TENANT=default
# Result: all tenant isolation becomes no-ops
# Single config file, no tenant resolution overhead
```

### Self-Hosted Deployment Stack (Docker Compose)

```yaml
# docker-compose.selfhosted.yml  ← CREATE THIS
services:
  janusec-api:     # FastAPI + pipeline
  janusec-worker:  # T2 LLM queue worker
  janusec-ollama:  # Local LLM (Ollama + llama3)
  postgres:        # PostgreSQL (or SQLite for tiny deploys)
  redis:           # T2 job queue
```

No Kubernetes needed for single-tenant self-hosted.
Minimum footprint: 4 containers, 8GB RAM, 4 CPU cores.

### What to Downplay / Defer for Self-Hosted Launch

| Feature | Action | Reason |
|---------|--------|--------|
| Multi-tenancy | Disable (DEFAULT_TENANT) | Not needed for self-hosted |
| OIDC SSO | Optional (API key auth only) | Reduces complexity |
| Kubernetes / Helm | Optional | Docker Compose sufficient |
| Azure Event Hub | Roadmap | AWS is production, do Azure in sprint 2 |
| eBPF / binary analysis | Stub / disabled | Too complex for initial release |
| PCAP session analysis | Optional | Users can enable if they have PCAP |

---

## 9. Go-Live in 3–4 Weeks Priority Plan

### Week 1 — Harden Core & Package Self-Hosted

**P0 — Must Have**

| Task | File(s) | Effort |
|------|---------|--------|
| Create `docker-compose.selfhosted.yml` | (new) | 0.5d |
| Single-tenant quickstart `.env.example` | `.env.example` | 0.5d |
| Fix any broken imports/startup errors | `src/api/server.py` | 1d |
| Ensure T1 summary fires on every event | `src/core/correlation/tier1_summarizer.py` | 0.5d |
| Verify Zeek adapter end-to-end | `src/live/zeek_adapter.py` | 1d |
| Smoke test: ingest → pipeline → T1 decision | `tests/test_smoke_pipeline.py` | 1d |

**P1 — Should Have**

| Task | File(s) | Effort |
|------|---------|--------|
| Ollama container + llama3 prewarm | `docker-compose.selfhosted.yml` | 0.5d |
| T2 LLM queue worker health check | `src/queue/redis_tier2.py` | 0.5d |
| Basic API key auth `.env` config | `src/api/auth_rate_limit.py` | 0.5d |
| Persona report HTML template | `src/reporting/comprehensive_report_generator.py` | 1d |

### Week 2 — Cloud Sieve Connectors

**P0 — AWS (already done — test + document)**

| Task | File(s) | Effort |
|------|---------|--------|
| AWS CloudTrail end-to-end test | `src/connectors/aws/cloudtrail.py` | 1d |
| GuardDuty findings → T1 summary | `src/connectors/aws/guardduty.py` | 0.5d |
| AWS connector quickstart doc | `docs/connectors/aws_quickstart.md` | 0.5d |

**P1 — Azure Event Hub (new — biggest gap)**

| Task | File(s) | Effort |
|------|---------|--------|
| `azure/event_hub.py` consumer | `src/connectors/azure/event_hub.py` | 2d |
| Entra ID normalizer | `src/connectors/azure/entra_id.py` | 1d |
| Azure → canonical_envelope() | `src/connectors/azure/normalizer.py` | 1d |
| Azure quickstart guide | `docs/connectors/azure_quickstart.md` | 0.5d |

### Week 3 — Polish UX + Reporting

| Task | File(s) | Effort |
|------|---------|--------|
| HopGraph pattern synthesis completion | `src/core/correlation/hunt_correlation.py` | 2d |
| Executive dashboard final polish | `frontend/static/janusec-platform-complete-LIVE.html` | 1d |
| Forensics persona report template | `src/analysis/persona_format.py` | 0.5d |
| `/api/v1/report/generate` PDF output QA | `src/api/report_endpoints.py` | 0.5d |
| Metrics / Grafana dashboard minimal set | `grafana/dashboards/` | 1d |

### Week 4 — Hardening & Launch Readiness

| Task | File(s) | Effort |
|------|---------|--------|
| Rate limit + auth hardening | `src/api/auth_rate_limit.py` | 0.5d |
| Webhook HMAC key rotation guide | `docs/security/webhook_key_rotation.md` | 0.5d |
| Full smoke test suite (CI) | `.github/workflows/smoke.yml` | 1d |
| README / quickstart for self-hosted | `README.md` | 1d |
| Security scan (Bandit + pip-audit) | `.github/workflows/bandit.yml` | 0.5d |
| First client onboarding runbook | `docs/ONBOARDING_GUIDE.md` | 1d |

---

## 10. ASCII Architecture Diagram

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║                        JANUSEC SECURITY PLATFORM                                ║
║                  "Cloud Security Sieve + AI Triage Engine"                      ║
╚══════════════════════════════════════════════════════════════════════════════════╝

  ┌─────────────────── TELEMETRY SOURCES ──────────────────────┐
  │                                                              │
  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
  │  │   AWS Cloud  │  │  Azure Cloud │  │    GCP Cloud     │  │
  │  │              │  │              │  │                  │  │
  │  │ CloudTrail   │  │ Event Hub ←──┼──│ Pub/Sub ←────────┼──│
  │  │ GuardDuty    │  │ Entra ID     │  │ SCC Findings     │  │
  │  │ VPC Flows    │  │ Defender     │  │ IAM Audit        │  │
  │  │ SecurityHub  │  │ Activity Log │  │ Asset Inventory  │  │
  │  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘  │
  │         │                 │                    │            │
  │  ┌──────┴─────────────────┴────────────────────┴────────┐   │
  │  │              NETWORK + ENDPOINT SENSORS               │   │
  │  │                                                        │   │
  │  │  Zeek → conn/dns/http/ssl  │  Sysmon/WinEvtX          │   │
  │  │  Suricata alerts           │  KAPE artifacts           │   │
  │  │  FluentBit forwarding      │  eBPF (partial)           │   │
  │  └──────────────────────────────────────────────────────┘   │
  └─────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │   INGEST LAYER     │
                    │                   │
                    │ /ingest/stream     │ ← real-time (rate-limited, dedup)
                    │ /ingest/csv_rows   │ ← batch CSV
                    │ /upload/*          │ ← file upload (PCAP, EVTX, CSV)
                    │ /webhooks/*        │ ← HMAC-guarded (Sentinel, Splunk)
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────────────────────────────────┐
                    │            EVENT PIPELINE (33 stages)           │
                    │                                                  │
                    │  ┌──────────────────────────────────────────┐   │
                    │  │  FAST / CORE (24 stages — always run)    │   │
                    │  │                                          │   │
                    │  │  baseline → regex → parent_child         │   │
                    │  │  endpoint → email_enrich → auth_burst    │   │
                    │  │  identity → graph → threat_intel         │   │
                    │  │  packet_summary → supply_chain           │   │
                    │  │  sbom_exec → sbom_vuln → rare_token      │   │
                    │  │  hunt_lanes → correlation → mapping      │   │
                    │  │  cluster_dedupe → embedding              │   │
                    │  └──────────────────────────────────────────┘   │
                    │  ┌──────────────────────────────────────────┐   │
                    │  │  HEAVY (5 stages — load + confidence gate)│   │
                    │  │                                          │   │
                    │  │  beacon (C2) → egress (exfil)           │   │
                    │  │  domain_novelty → pcap_session           │   │
                    │  │  binary_payload                          │   │
                    │  └──────────────────────────────────────────┘   │
                    └──────────────────┬──────────────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────┐
                    │         HOPGRAPH ENGINE              │
                    │                                      │
                    │  Entity graph (user/host/proc/ip)    │
                    │  54 correlation factors              │
                    │  Temporal window: 5 min              │
                    │  Sliding window:  15 min             │
                    │  Hunt lanes: ja3/lineage/bec         │
                    │  PPR node scoring                    │
                    │  SQLite persistence backend          │
                    └──────────────────┬──────────────────┘
                                       │
                    ┌──────────────────▼──────────────────┐
                    │        AI TRIAGE LAYER               │
                    │                                      │
                    │  ┌──────────────────────────────┐    │
                    │  │  TIER 1 (Deterministic, fast) │    │
                    │  │  • MITRE mapping              │    │
                    │  │  • Factor summary             │    │
                    │  │  • Confidence score           │    │
                    │  │  • No LLM required            │    │
                    │  └──────────────────────────────┘    │
                    │  ┌──────────────────────────────┐    │
                    │  │  TIER 2 (LLM async queue)     │    │
                    │  │  • Ollama / OpenAI / Anthropic│    │
                    │  │  • RAG-augmented context      │    │
                    │  │  • Cost tracked per tenant    │    │
                    │  │  • Circuit breaker protected  │    │
                    │  └──────────────────────────────┘    │
                    └──────────────────┬──────────────────┘
                                       │
                    ┌──────────────────▼──────────────────┐
                    │       PERSONA REPORT ENGINE          │
                    │                                      │
                    │  ┌──────────┐ ┌──────────┐ ┌──────┐ │
                    │  │ Analyst  │ │ Manager  │ │Forens│ │
                    │  │ (SOC)    │ │ (CISO)   │ │(IR)  │ │
                    │  └──────────┘ └──────────┘ └──────┘ │
                    │                                      │
                    │  HTML / PDF / Email dispatch         │
                    │  Executive coverage dashboard        │
                    │  MITRE/STRIDE/DREAD/CVSS overlay     │
                    └──────────────────┬──────────────────┘
                                       │
                    ┌──────────────────▼──────────────────┐
                    │         SOC ANALYST UX               │
                    │                                      │
                    │  Live decisions stream (SSE)         │
                    │  HopGraph attack timeline UI         │
                    │  Evidence investigation panel        │
                    │  Feedback loop (analyst labels)      │
                    │  Deep analyze (LLM on-demand)        │
                    └─────────────────────────────────────┘
```

---

## 11. User Flows

### Flow 1: AWS CloudTrail → Alert → Persona Report

```
[Client AWS Account]
      │
      │ CloudTrail events (API calls, IAM changes)
      ▼
[Janusec AWS Connector]  src/connectors/aws/cloudtrail.py
      │ canonical_envelope(event)
      ▼
POST /api/v1/ingest/stream
      │
      ▼
[Pipeline — 24 FAST stages]
      │ parent_child detects unusual IAM role assumption
      │ threat_intel matches known attacker IP
      │ correlation fires: CORR_LATERAL_PIVOT_POSSIBLE (score 0.84)
      ▼
[T1 Summary]  — deterministic, immediate
      │ {"title": "IAM Lateral Movement", "score": 0.84, "mitre": ["T1078"]}
      ▼
[T2 Queue]  — async LLM enrichment (30-90s)
      │ LLM: "An attacker assumed the DevAdmin role from IP 45.x.x.x..."
      ▼
[Persona Report]  src/api/report_endpoints.py
      │ Analyst: "IAM role chained → EC2 metadata → credentials"
      │ Manager: "Critical: Likely credential theft in AWS us-east-1"
      │ Forensics: "1. Pull CloudTrail for AssumeRole events..."
      ▼
[Email Dispatch / SSE Stream / PDF Export]
```

### Flow 2: Azure Event Hub → Real-Time Triage (TO BUILD)

```
[Client Azure Tenant]
      │
      │ Entra ID sign-in logs (unusual location, MFA bypass)
      │ Defender for Cloud alert (malware detected)
      ▼
[Azure Event Hub]  (client wires this up in ~10 mins)
      │
      ▼
[Janusec Event Hub Consumer]  src/connectors/azure/event_hub.py  ← CREATE
      │ canonical_envelope(azure_event)
      ▼
POST /api/v1/ingest/stream
      │
      ▼
[Pipeline]  auth_burst + identity + correlation
      │ Impossible travel detected (sign-in from AU + US within 5min)
      ▼
[T1 + T2 Summary]
      │
      ▼
[Manager Report]: "MFA fatigue attack likely — same user 3 failed MFA in 2min"
```

### Flow 3: On-Demand Evidence → Forensics Trigger

```
[Zeek streaming]
      │ SSL: unusual JA3 fingerprint
      │ DNS: domain novelty spike
      ▼
[Pipeline — HEAVY beacon stage fires]
      │ CORR_BEACON_RARE_JARM = 0.91
      ▼
[Memory Job Triggered]  src/artifact/memory_acquisition.py
      │ KAPE job queued for host "WIN-LAPTOP-042"
      │ Requested artifacts: prefetch, MFT, process list
      ▼
[Analyst UI]
      │ "Evidence found — memory collection pending"
      │ Analyst approves → KAPE executes → artifacts uploaded
      ▼
[Forensics Persona Report]
      │ Investigation checklist generated from collected artifacts
```

### Flow 4: Batch CSV Upload → Hopgraph Session

```
[SOC Analyst]
      │ Exports SIEM CSV (1000 rows, last 24h)
      ▼
POST /api/v1/upload/csv
      │
      ▼
[Pipeline — batch mode]
      │ Processes rows through all FAST stages
      │ HopGraph observes entity relationships
      ▼
[Graph Reconstruction]  POST /api/v1/graph/reconstruct
      │ Builds attack timeline from entity edges
      │ PPR scoring identifies pivot point
      ▼
[Session Report]
      │ "3-hop attack: user phished → lateral to DC → exfil to S3"
```

---

## 12. Files to Edit / Refactor / Create

### P0 — Week 1 (Self-Hosted Launch)

#### CREATE: `docker-compose.selfhosted.yml`
```yaml
# Minimal self-hosted stack
services:
  api:      image: janusec-api:latest
  worker:   image: janusec-worker:latest
  ollama:   image: ollama/ollama:latest
  postgres: image: postgres:15
  redis:    image: redis:7-alpine
```

#### EDIT: `.env.example`
```
# Add single-tenant section at top:
DEFAULT_TENANT=default
SINGLE_TENANT_MODE=true
LLM_PROVIDER=ollama
OLLAMA_HOST=http://ollama:11434
ALERTS_API_KEYS=changeme123
```

#### EDIT: `src/api/server.py`
- Line ~50: Verify `DEFAULT_TENANT` env loaded before app startup
- Add `/health` endpoint if missing (needed for Docker healthcheck)

#### EDIT: `src/core/event_pipeline/pipeline.py`
- Lines 473–497: Verify `_attach_memory_jobs()` doesn't crash if KAPE not configured
- Add graceful fallback for missing KAPE host

#### EDIT: `src/integrations/llm_client.py`
- Verify Ollama prewarm probe fires on startup (`/api/tags` call)
- Ensure `LocalDeterministicClient` fallback is silent (no noisy logs)

### P1 — Week 2 (Azure Cloud Sieve)

#### CREATE: `src/connectors/azure/__init__.py`

#### CREATE: `src/connectors/azure/base.py`
```python
class AzureConnectorBase:
    """Base: SAS/AAD auth, checkpoint dir, canonical_envelope()"""
    checkpoint_dir: str = 'data/checkpoints/azure'
    def load_checkpoint(name) -> dict
    def save_checkpoint(name, data) -> None
    def canonical_envelope(raw_event) -> dict
```

#### CREATE: `src/connectors/azure/event_hub.py`
```python
# Dependencies: azure-eventhub>=5.11
# Consumer group: $Default
# Checkpoint: Blob or local file

class EventHubConnector(AzureConnectorBase):
    connection_string: str  # from env AZURE_EVENTHUB_CONNECTION_STRING
    eventhub_name: str      # from env AZURE_EVENTHUB_NAME

    async def consume():
        # Uses EventHubConsumerClient (async)
        # Normalizes each event → canonical_envelope
        # POSTs to /api/v1/ingest/stream
```

#### CREATE: `src/connectors/azure/entra_id.py`
```python
# Microsoft Graph API: sign-in logs, audit logs
# Auth: Client credentials flow (app registration)
# Env: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET

class EntraIDConnector(AzureConnectorBase):
    def fetch_signin_logs(since: datetime) -> Iterable[dict]
    def fetch_audit_logs(since: datetime) -> Iterable[dict]
```

#### CREATE: `src/connectors/azure/normalizer.py`
```python
# Map Azure event schema → Janusec canonical_envelope
# Covers: Entra ID, Defender, Activity Log, Event Hub

def normalize_entra_signin(raw) -> dict
def normalize_defender_alert(raw) -> dict
def normalize_activity_log(raw) -> dict
```

#### EDIT: `src/api/server.py`
- Register Azure connector routes under `/api/v1/connectors/azure/*`

### P2 — Week 3 (HopGraph Completion)

#### EDIT: `src/core/correlation/hunt_correlation.py`
- Complete pattern synthesis logic (currently ~70%)
- Add: `detect_ransomware_chain()`, `detect_lateral_movement()`, `detect_exfil_pattern()`
- Each pattern: takes `host_factor_times` → returns `CorrelationEmission`

#### EDIT: `src/core/graph/hopgraph_lite.py`
- Add `detect_patterns()` method (likely missing or stub)
- Wire `observe()` output into `CorrelationEngine` factor list

#### EDIT: `src/analysis/persona_format.py`
- Enrich **Forensics** persona prompt with structured checklist format
- Add `cloud_persona` for cloud-specific findings (IAM, resource changes)

### P3 — Week 4 (Polish & Launch)

#### EDIT: `README.md`
- Replace current content with self-hosted quickstart
- Section: "Wire Azure Event Hub in 10 minutes"
- Section: "Wire AWS CloudTrail in 5 minutes"

#### CREATE: `docs/ONBOARDING_GUIDE.md`
- Step-by-step: Docker Compose deploy → first event → first report

#### CREATE: `docs/connectors/azure_quickstart.md`
- Azure Event Hub setup with screenshots
- Entra ID app registration steps

#### EDIT: `.github/workflows/smoke.yml`
- Add end-to-end smoke: ingest → pipeline → T1 decision → assert score > 0

#### EDIT: `src/api/auth_rate_limit.py`
- Harden: remove `PYTEST_CURRENT_TEST` permissive path from production builds
- Move to env flag: `JANUSEC_TEST_MODE=true`

---

## Summary: New Direction Statement

> **Janusec is a Cloud Security Sieve + AI Triage Engine.**
>
> Clients wire their existing cloud telemetry (AWS CloudTrail, Azure Event Hub, GCP Pub/Sub,
> Zeek network sensors, Sysmon endpoint logs) into Janusec. The platform ingests at scale,
> runs 33 pipeline stages to separate signal from noise, correlates with HopGraph across
> a 15-minute sliding entity window, and generates Tier 1 deterministic summaries instantly
> and Tier 2 LLM-enriched summaries asynchronously. Three persona-tuned reports (Analyst,
> Manager, Forensics) are generated in HTML/PDF/email format.
>
> Self-hosted first: each client runs their own Docker Compose stack. No shared infrastructure.
> No "where does my data go" objections. Can pivot to managed hosting once revenue justifies.
>
> **AWS is production. Azure is the sprint 2 priority. GCP follows.**
> **Network + Endpoint + Cloud IAM = the three detection domains.**
> **No SIEM required. Janusec IS the sieve.**

---

*Generated: 2026-03-27 | Branch: feat/webhook-guard-middleware-only-verification*
