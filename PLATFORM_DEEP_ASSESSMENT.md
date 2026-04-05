# JanuSec Platform Deep Assessment
**Generated:** 2026-03-24
**Test Suite:** 1,865 tests | 1,657 passed (88.9%) | 217 failed | 40 skipped
**Branch:** feat/webhook-guard-middleware-only-verification

---

## Table of Contents
1. [What Is JanuSec & Who Is It For](#1-what-is-janusec--who-is-it-for)
2. [Competitive Landscape](#2-competitive-landscape)
3. [HopGraph Correlation Engine](#3-hopgraph-correlation-engine)
4. [LLM Tier-1 & Tier-2 Summaries](#4-llm-tier-1--tier-2-summaries)
5. [Persona-Based Reporting](#5-persona-based-reporting)
6. [8-Domain Detection Coverage](#6-8-domain-detection-coverage)
7. [Isolation, Actions & Playbooks](#7-isolation-actions--playbooks)
8. [Stream Events & Alert Pipeline](#8-stream-events--alert-pipeline)
9. [Latency Optimisation](#9-latency-optimisation)
10. [Test Suite Results](#10-test-suite-results)
11. [Installation & Deployment Environments](#11-installation--deployment-environments)
12. [Master Status Matrix](#12-master-status-matrix)

---

## 1. What Is JanuSec & Who Is It For

### Core Value Proposition
JanuSec is an **AI-powered Extended Detection & Response (XDR) platform** solving the "alert tsunami" problem in enterprise SOCs.

| Metric | Claim | Evidence File |
|--------|-------|---------------|
| False positive reduction | 98% | [README.md:11-32](README.md) |
| Alert recall preserved | 96%+ | [README.md:36](README.md) |
| Analyst workload reduction | 70% | [README.md:32](README.md) |
| Cost vs Splunk | 97% cheaper ($0.002 vs $0.06/event) | [JANUSEC_COMPETITIVE_ANALYSIS.md:1-50](JANUSEC_COMPETITIVE_ANALYSIS.md) |
| Threat detection speed | 10x faster (minutes vs hours) | [README.md:32](README.md) |
| Events/day capacity | 100,000+ | [README.md:36](README.md) |
| Pipeline p95 latency target | <500ms | [README.md:36](README.md) |

### Target Buyers
| Persona | Need | How JanuSec Helps |
|---------|------|-------------------|
| **SOC Analyst** (primary) | Drowning in 10K+ alerts/day | T1/T2 LLM triage, auto-suppression, confidence scoring |
| **Threat Hunter** | Manual log correlation | HopGraph multi-hop attack chain reconstruction |
| **CISO** (secondary) | Board reporting, budget justification | Executive persona view, DREAD scores, MITRE mapping |
| **MSSP** (tertiary) | Multi-tenant triage at scale | Per-tenant isolation, quota control, persona routing |
| **IR Analyst** | Offline forensics | CSV/Excel multi-log analyzer without live connectors |

### 30-Stage Progressive Pipeline
```
Stages  1- 5  │ Baseline          │ IOC lookup, allowlists          │ <1ms
Stages  6-12  │ Lightweight       │ Regex, entropy, port scans, geo │ 1-10ms
Stages 13-21  │ Adaptive          │ TF-IDF, beaconing, DNS exfil    │ 10-50ms
Stages 22-25  │ Correlation       │ HopGraph, temporal, co-occur    │ 20-100ms
Stages 26-28  │ ML                │ Isolation Forest, LightGBM      │ 50-200ms
Stages 29-30  │ External AI       │ Ollama / Azure OpenAI           │ 500-2000ms
```
**Source:** [README.md:61-149](README.md) | [src/core/event_pipeline/pipeline.py:84-130](src/core/event_pipeline/pipeline.py)

---

## 2. Competitive Landscape

| Vendor | Category | JanuSec Advantage |
|--------|----------|-------------------|
| **Splunk Enterprise Security** | SIEM | 97% cheaper; self-tuning vs manual rules; multi-domain vs single |
| **Microsoft Sentinel** | Cloud SIEM | Vendor-agnostic; on-prem/edge support; no Azure lock-in |
| **CrowdStrike Falcon XDR** | EDR+XDR | 8 domains vs endpoint-only; no agent required for network/email |
| **Palo Alto Cortex XDR** | XDR | No Palo hardware dependency; open connector model |
| **Elastic Security** | SIEM | LLM triage vs manual investigation; adaptive FP suppression |
| **Wiz / Orca** | CSPM | Real-time threat detection, not just posture |

### JanuSec's 5 Unique Differentiators
1. **Only 8-domain simultaneous correlation** — endpoint + network + email + IAM + cloud + data + remote + API
2. **AI triage, not just detection** — LLM T1/T2 summaries with 5 personas, graceful local fallback
3. **Self-tuning FP suppression** — TF-IDF rarity + feedback loop auto-weight + EWMA baselines
4. **Explainability-first** — DREAD score + factor provenance + chain-of-custody hash per verdict
5. **Graceful degradation** — Full detection with zero external dependencies (local rules + ML)

---

## 3. HopGraph Correlation Engine

### Status: REAL — Substantially Production-Grade

**Primary file:** [src/core/graph/hopgraph_lite.py](src/core/graph/hopgraph_lite.py) (1,003 lines)

### What Is Implemented (REAL)

#### Graph Construction & Storage
```
src/core/graph/hopgraph_lite.py:35-60    — State: edges_ts, node_registry, _spike_state
src/core/graph/hopgraph_lite.py:242      — observe() — event → edge + node registration
src/core/graph/hopgraph_lite.py:296      — Auto-evict every 500 events
```

**Node types:** `user`, `host`, `process`, `package`, `cicd`, `binary`
**Edge types with per-type TTLs:**

| Edge Type | TTL | Meaning |
|-----------|-----|---------|
| `auth` | 72 hours | user → host authentication |
| `net` | 24 hours | host → host network connection |
| `proc` | 12 hours | user → process execution |
| `deploys` | configurable | cicd → binary deployment |
| `builds` | configurable | cicd → package build |

#### Personalized PageRank (PPR)
```
src/core/graph/hopgraph_lite.py:680-723  — ppr() algorithm
```
- Localized random walk with restart: alpha=0.15, 8 steps, cap=128 nodes, branch cap=16
- Returns top-32 nodes by score
- **Latency tracked:** `hopgraph_ppr_latency_seconds` histogram
- ✅ **REAL algorithm** — not a heuristic placeholder

#### Motif Detection
```
src/core/graph/hopgraph_lite.py:310-421  — factors() motif patterns
src/core/graph/hopgraph_lite.py:754-779  — detect_lateral_chain()
```
- Lateral movement chains: user → multiple hosts (BFS expansion)
- Process burst: user → 5+ distinct processes
- DC-first-touch detection
- Auth → proc → net pattern sequences
- ✅ **REAL**

#### Leaky Integrate-and-Fire Spike Detector
```
src/core/graph/hopgraph_lite.py:726-745  — integrate_spike()
```
- V(t) = V₀ × exp(−decay × dt) + strength
- Per-entity-channel threshold, exponential decay in-place
- ✅ **REAL**

#### TTL/Eviction
```
src/core/graph/hopgraph_lite.py:600-650  — _evict()
```
- Window: 900 seconds (default), max 5,000 events
- Per-edge-type TTL enforcement inside PPR
- ✅ **REAL**

#### Optional SQLite Persistence
```
src/core/graph/hopgraph_lite.py:54       — backend: SQLiteHopGraphBackend
```
- Async persist via env flag
- ⚠️ **PARTIAL** — works but not enabled by default

### What Needs More Work (STUB / INCOMPLETE)

| Gap | File | Lines | Issue |
|-----|------|-------|-------|
| PageRank scoring in graph_scoring | [src/core/graph/graph_scoring.py:163-164](src/core/graph/graph_scoring.py) | 163-164 | Uses `len(path)/10.0` as proxy — not real PageRank |
| Session tracking | N/A | — | No graph session objects; PPR is stateless per-call |
| Graph replay / historical queries | N/A | — | No persistent query layer |
| HopGraph integration fallback | [src/core/graph/hopgraph_integration.py:52-100](src/core/graph/hopgraph_integration.py) | 52-100 | Deterministic fallback only, no real traversal |
| Cross-edge timestamp sync | hopgraph_lite.py | — | Each edge type evicts independently |

### HopGraph Metrics
```
hopgraph_nodes_total              (gauge)
hopgraph_edges_total              (gauge)
hopgraph_ppr_latency_seconds      (histogram) ← KEY perf tracker
hopgraph_reconstructions_total    (counter)
hopgraph_evictions_total          (counter)
```

---

## 4. LLM Tier-1 & Tier-2 Summaries

### Architecture: THREE-TIER LLM FALLBACK CHAIN

```
src/integrations/llm_client.py   — Provider router: Ollama → OpenAI → Anthropic → LocalDeterministic
```

**Priority order** ([src/integrations/llm_client.py:243-257](src/integrations/llm_client.py)):
1. Env var `LLM_PROVIDER` override
2. Ollama local (if `OLLAMA_HOST` configured or no managed API keys)
3. OpenAI (if `OPENAI_API_KEY` set)
4. Anthropic (if `ANTHROPIC_API_KEY` set)
5. `LocalDeterministicClient` — hash-based fallback, always works (tests/demo)

**Circuit breaker** ([src/integrations/llm_client.py:195-211](src/integrations/llm_client.py)):
- Per-tenant failure tracking
- Trip threshold: `LLM_BREAKER_FAILURE_THRESHOLD` (default 5 failures)
- Trip window: `LLM_BREAKER_TRIP_SECONDS` (default 60s)

---

### Tier 1 (T1) — Fast Triage Summary

**Status: ✅ REAL — two implementations (stub endpoint + full engine)**

| File | Lines | Status | Role |
|------|-------|--------|------|
| [src/api/insights_endpoints.py:509-626](src/api/insights_endpoints.py) | 626 | ✅ REAL | **Primary T1 engine** — budget gating, triage scoring, persona injection |
| [src/core/correlation/tier1_summarizer.py](src/core/correlation/tier1_summarizer.py) | 48 | ✅ REAL | Deterministic structured extraction (fallback) |
| [src/api/llm_tier1.py](src/api/llm_tier1.py) | 39 | ⚠️ STUB | REST wrapper — hardcoded rationale strings, not real LLM call |
| [src/api/llm_tier1_enhanced.py](src/api/llm_tier1_enhanced.py) | — | ✅ REAL | Enhanced variant with full LLM |
| [src/api/llm_tier1_local.py](src/api/llm_tier1_local.py) | — | ✅ REAL | Local-only (Ollama) variant |

**T1 Triage Gating Logic** ([src/api/insights_endpoints.py:513-543](src/api/insights_endpoints.py)):
```
triage_score < LLM_T1_MIN_TRIAGE (0.15) → skip LLM, return {llm_skipped_reason: 'below_threshold'}
existing_llm_cost >= LLM_BUDGET_PER_ASSESSMENT → skip, return {llm_skipped_reason: 'budget_exhausted'}
otherwise → call LLM with persona-injected prompt
```

**T1 Prompt pattern:**
```
"You are a SOC analyst performing FAST TRIAGE.
Schema: WHAT IS IT / EXPLOITABILITY / WHAT TO DO / CONCISE PLAYBOOK (30-45 lines)
Process: {proc}  Host: {host}  Verdict: {verdict}  Domain: {domain}
DREAD: {dread}  Signals: {signals}"
```

**T1 Triage Scoring inputs** ([src/api/insights_endpoints.py:546-556](src/api/insights_endpoints.py)):
```python
tri_inputs = {
  'dread':       row.get('_dread.score'),
  'correlation': row.get('_pipeline_confidence'),
  'density':     row.get('factor_density'),
  'confidence':  _derive_confidence_score(row),
  'rarity':      row.get('_rarity'),
}
```

---

### Tier 2 (T2) — Deep Cross-Domain Analysis

**Status: ✅ REAL — full LLM pipeline with streaming and RAG**

| File | Lines | Role |
|------|-------|------|
| [src/api/insights_endpoints.py:629-699](src/api/insights_endpoints.py) | — | **Primary T2 engine** — timeline, supply chain, sandbox, OAuth |
| [src/api/tier2_endpoints.py](src/api/tier2_endpoints.py) | 200 | `/api/v1/csv/tier2_summarize` + `/tier2_sse` (CSV analysis path) |
| [src/ai/tier2_prompts.py](src/ai/tier2_prompts.py) | — | Prompt builder with graph/TI context injection |
| [src/api/llm_tier2_rag.py](src/api/llm_tier2_rag.py) | — | RAG-augmented variant |
| [src/queue/redis_tier2.py](src/queue/redis_tier2.py) | — | Redis-queued async T2 jobs |

**T2 enriches with** ([src/api/insights_endpoints.py:629-699](src/api/insights_endpoints.py)):
- Timeline from correlation stages (cross-domain sequences)
- Supply chain: OAuth scopes, repo activity, package events
- Sandbox enrichment from `raw_event.sandbox_enrichment`
- Executive business impact assessment
- Full `pipeline_context` (all 30 stage outputs)

**T2 Sections in Prompt:**
```
verdict | actions | evidence | reasoning | timeline |
threat_intel | graph_context | business_impact |
recommendations | controls | mitre | next_steps
```

**T2 Budget Guard** ([src/api/tier2_endpoints.py:12-28](src/api/tier2_endpoints.py)):
- Per-tenant budget via `T2_BUDGET_LEFT` env or `tenant_overrides`
- HTTP 402 if budget exceeded
- Cost estimate: `$0.015 × max(1, row_count)`

**T2 SSE Streaming** ([src/api/tier2_endpoints.py:103-170](src/api/tier2_endpoints.py)):
- Real `StreamingResponse` for token-by-token LLM output
- Budget reservation before generation starts
- Prometheus metrics: `tier2_requests_total`, `tier2_summarize_latency_ms`
- ✅ **REAL streaming**

---

## 5. Persona-Based Reporting

**Status: REAL — 5 personas with distinct views**

| File | Lines | Role |
|------|-------|------|
| [src/reporting/persona_views.py](src/reporting/persona_views.py) | 1-173 | Core persona view generator |
| [src/analysis/persona_format.py](src/analysis/persona_format.py) | 1-34 | LLM prompt templates per persona |
| [src/core/ranking/persona_forwarder.py](src/core/ranking/persona_forwarder.py) | — | Routes to downstream consumer |
| [src/reporting/persona_parser.py](src/reporting/persona_parser.py) | — | Parses persona from request context |
| [frontend/static/js/persona_ui.js](frontend/static/js/persona_ui.js) | — | Frontend persona switcher |

### Personas Defined

| Persona | Key Additions | LLM Prompt Style |
|---------|--------------|-----------------|
| `executive` | headline, business_impact, tier_metadata | "Summarize with business impact, severity label, prioritization" |
| `soc_analyst` | raw factors, MITRE details, IOC list, investigation steps | "Concise, actionable; focus on what happened and mitigations" |
| `compliance` | control mappings, regulatory references | Extended with control data |
| `threat_hunter` | graph context, lateral movement paths, TTPs | Technical; patterns and hunt hypotheses |
| `mssp` | per-tenant partitioned view, quota/cost metadata | Multi-tenant aware summary |

**Core generation function:** [src/reporting/persona_views.py:29-173](src/reporting/persona_views.py) — `generate_persona_view()`

**Per-view standard content:**
```python
{
  "report_id": "...",
  "persona": "soc_analyst",
  "disclosure_level": 2,
  "summary_signals": {
    "risk_drivers": [...],      # top-N risk factors
    "factors": [...],           # scored detection factors
    "iocs": {type: [...]},      # IOC type → list mapping
    "impacted_entities": [...],
    "recommended_actions": [...],
    "enrichment": {...},        # email auth signals if applicable
    "dread": {                  # DREAD scoring breakdown
      "breakdown": {...},
      "provenance": {"factors": [...]}
    }
  },
  "decision_gates": [...]       # DecisionGate typed objects
}
```

### What Needs More Work
- `forensics` persona is in prompt templates ([src/analysis/persona_format.py:15-17](src/analysis/persona_format.py)) but **not wired into `generate_persona_view()`** — only 5 personas are handled there
- `mssp` persona content is skeletal vs executive/soc_analyst
- Playbook attachment to persona view is via optional `get_playbook_for_verdict` which may not be available

---

## 6. 8-Domain Detection Coverage

**Total rule files:** 79 Python files across 14 domain subdirectories

### Domain Coverage Map

| # | Domain | Subdirectory | Rule Files | Status |
|---|--------|--------------|-----------|--------|
| 1 | **Email / BEC** | `rules/email/` | 15 files | ✅ REAL — richest domain |
| 2 | **Network** | `rules/network/` | 2+ files | ✅ REAL |
| 3 | **Binary / Endpoint** | `rules/binary/` | 4 files | ✅ REAL |
| 4 | **IAM / Identity** | `rules/iam/` | 2 files | ⚠️ PARTIAL |
| 5 | **Supply Chain** | `rules/supplychain/` | 3 files | ✅ REAL |
| 6 | **API Security** | `rules/api_security*.py` | 2 files | ⚠️ PARTIAL |
| 7 | **Graph / Lateral** | `rules/graph/` | 2 files | ✅ REAL |
| 8 | **eBPF / Container** | `rules/ebpf/` | 2 files | ⚠️ PARTIAL |
| + | LOLBins (Linux/macOS) | `rules/lolbin/`, `linux/macos_lolbins.py` | 4 files | ✅ REAL |
| + | Multi-week rule packs | `rules/top10/20/30/40/50_priority.py` | 5 files | ✅ REAL (vector mismatch) |
| + | Week 1/2/X rules | `rules/week1/`, `week2/`, `weekX/` | 10+ files | ✅ REAL |
| + | Tenant allowlists | `rules/tenant/` | 2 files | ✅ REAL |

### Email Domain — Richest Coverage
```
rules/email/bec_brand_oauth_spoof_enriched.py
rules/email/bec_chain_enriched.py
rules/email/bec_impersonation_enriched.py
rules/email/bec_invoice_fraud_pattern_enriched.py
rules/email/bec_payment_change_dkim_flip_enriched.py
rules/email/bec_payment_change_dkim_pass_domain_flip_enriched.py
rules/email/bec_reply_chain_enriched.py
rules/email/bec_supplier_portal_free_reply_enriched.py
rules/email/bec_supplier_portal_takeover_enriched.py
rules/email/bec_supplier_replyto_freemail_enriched.py
rules/email/bec_vendor_spoof_chain_enriched.py
rules/email/display_name_fuzzy_enriched.py
rules/email/dkim_dmarc_failure_enriched.py
rules/email/email_oauth_brand_spoof_enriched.py
rules/email/phish_attachment_enriched.py
```

### Why Detection Rules Are Failing Tests (217 failures)
The `top10/20/30/40` and `week1/2` rule tests use **test vectors from `data/custom_test_vectors.json`** (now deleted per git status). The rules themselves are real — the test vectors no longer exist. Fix: restore test vector data or regenerate with current rule schemas.

```python
# Pattern in ALL failing rule tests:
evt = load_vector("col_keylogger_detected_exfil")   # loads from deleted JSON file
matches = CORRELATION_RULES.evaluate(evt)
assert any(r.id == "col_keylogger_detected_exfil" for r in matches)
# → assert False  (vector file missing, so evt is empty/wrong shape)
```

---

## 7. Isolation, Actions & Playbooks

### Full SOAR Engine — REAL (discovered in `src/soar/`)

The platform has a **complete SOAR engine** at [src/soar/](src/soar/) — 14 files — that is separate from the stub in `src/modules/playbook_executor.py`.

| File | Status | Role |
|------|--------|------|
| [src/soar/playbook_engine.py](src/soar/playbook_engine.py) | ✅ REAL | Full SOAR engine with isolation/block/quarantine APIs |
| [src/soar/playbook_executor.py](src/soar/playbook_executor.py) | ✅ REAL | Step-by-step async DAG execution with idempotency |
| [src/soar/playbook_loader.py](src/soar/playbook_loader.py) | ✅ REAL | YAML → dataclass parser |
| [src/soar/playbook_queue.py](src/soar/playbook_queue.py) | ✅ REAL | Async queue management |
| [src/soar/playbook_worker.py](src/soar/playbook_worker.py) | ✅ REAL | Background processor |
| [src/soar/connectors.py](src/soar/connectors.py) | ✅ REAL | `ConnectorRegistry` + `http_post()` via httpx |
| [src/soar/connector_audit.py](src/soar/connector_audit.py) | ✅ REAL | Full audit trail for all connector calls |
| [src/soar/engine.py](src/soar/engine.py) | ✅ REAL | Core execution engine |
| [src/soar/dsl_schema.py](src/soar/dsl_schema.py) | ✅ REAL | YAML DSL schema validation |
| [src/soar/actions/slack_notify.py](src/soar/actions/slack_notify.py) | ✅ REAL | Slack action handler |
| [src/soar/actions/tag_event.py](src/soar/actions/tag_event.py) | ✅ REAL | Alert tagging action |

### Connector Pattern — Conditional Real/Mock

**Key insight:** Actions are real HTTP calls if `api_url` is in params, otherwise safe mock ([src/soar/connectors.py:74-80](src/soar/connectors.py)):
```python
async def firewall_block_ip(params):
    ip = params.get('ip')
    url = params.get('api_url')
    if url:
        return await http_post(url, {"action": "block", "ip": ip})  # ← REAL
    await asyncio.sleep(0.01)
    return {"blocked": True, "ip": ip}  # ← MOCK (safe default)
```

**Auth support** ([src/soar/connectors.py:49-71](src/soar/connectors.py)):
- ApiKey auth: `Authorization: ApiKey {key}`
- Bearer token from env: `Authorization: Bearer {VAULT_TOKEN}`
- httpx with 5-second timeout

### Isolation Actions Available

| Action | Status | Condition |
|--------|--------|-----------|
| `isolate_endpoint` (EDR) | ✅ Real HTTP POST | requires `api_url` in playbook params |
| `block_ip_address` (firewall) | ✅ Real HTTP POST | requires `api_url` |
| `quarantine_file` (EPP) | ✅ Real HTTP POST | requires `api_url` |
| `idp_revoke_sessions` (IdP) | ✅ Real HTTP POST | requires `api_url` |
| `mailbox_disable_rule` (Exchange) | ⚠️ Mock | `sleep(0.01)` fallback |
| Slack notification | ✅ Always real | uses `SLACK_WEBHOOK_URL` env |
| Alert tagging | ✅ Always real | in-memory + persisted |
| AI enrichment call | ✅ Always real | uses LLM client |

### Playbook Execution Guarantees ([src/soar/playbook_executor.py:55-205](src/soar/playbook_executor.py))
- **Idempotency**: Re-running same `execution_id` skips already-completed steps
- **DAG dependencies**: `depends_on: [step_id]` blocks on pending deps
- **Conditional gating**: `require_factor` skips step if factor absent from context
- **Templating**: `{{context.field}}` substitution in params
- **Audit log**: Every action logged to `action_log/DATE/execution_id.jsonl`
- **Metrics**: Prometheus counter per action type

### Playbook YAML Schema ([src/soar/dsl_schema.py](src/soar/dsl_schema.py))
```yaml
- id: tag_alert
  action: tag
  params:
    tags: ["suspicious", "lateral"]
- id: notify_sec
  action: slack
  params:
    channel: "#sec-alerts"
    message: "{{event.id}} escalated"
  depends_on: [tag_alert]
- id: isolate_host
  action: isolate_endpoint
  params:
    api_url: "https://edr.example.com/endpoints/actions"
    endpoint_id: "{{context.host}}"
  require_factor: "lateral_movement_confirmed"
```

### What Playbooks Can Do
**Always real (no config needed):** tag, note, slack, AI enrich, ticket write
**Real if api_url provided:** EDR isolate, firewall block, file quarantine, IdP session revoke
**Not yet implemented:** rollback semantics, conditional branching (if/else), loops, approval workflows

### Stub vs Real Note
`src/modules/playbook_executor.py` (15 lines, always returns success) is a **shim/adapter** — the real implementation is the full `src/soar/` directory. The shim is used when loading the module registry; the SOAR engine operates independently.

### Dispatcher / Action Sink

**File:** [src/core/actions/dispatcher.py](src/core/actions/dispatcher.py)

| Feature | Status |
|---------|--------|
| Rate limiter (per-connector token bucket) | ✅ REAL |
| Circuit breaker (per tenant+connector) | ✅ REAL |
| Outbox pattern for durability | ✅ REAL |
| SLO tracking (success rate, MTTC per tenant) | ✅ REAL |
| Slack notification | ✅ REAL HTTP webhook |
| Eclipse XDR `update_verdict()` | ❌ Logs only |
| Audit log (append-only JSONL) | ✅ REAL |

---

## 8. Stream Events & Alert Pipeline

### SSE Decisions Stream — REAL

**File:** [src/api/decisions_stream.py](src/api/decisions_stream.py) (321 lines)

```
GET /api/v1/stream/decisions     — multi-client SSE broadcast
GET /api/v1/stream/artifacts     — alias to decisions stream
GET /api/v1/stream/hopgraph      — attack graph overlay SSE
```

**Architecture:**
```
publish_decision(summary)
  → _CLIENT_QUEUES (asyncio.Queue per client, maxsize=1000)
  → cross-loop safe via run_coroutine_threadsafe()
  → _RECENT_DECISIONS ring (maxlen=50) for new subscriber backfill
  → keepalive ":keepalive\n\n" every 0.5s
```

**SSE Payload Shape:**
```json
{
  "event_id": "uuid",
  "confidence": 0.85,
  "verdict": "escalate",
  "ts": 1711234567.89,
  "factors": ["factor_a", "factor_b"],
  "stage_timings": [
    {"name": "baseline", "duration_ms": 3, "confidence_after": 0.3},
    {"name": "tfidf",    "duration_ms": 12, "confidence_after": 0.6}
  ],
  "ab_tests": [{"test_id": "exp_001", "variant": "A"}]
}
```

**Source:** [src/api/decisions_stream.py:58-191](src/api/decisions_stream.py)

### Alert Pipeline — REAL (3-level dedup)

**File:** [src/api/alerts_endpoints.py](src/api/alerts_endpoints.py) (1,171 lines)

#### Level 1 — Rule-entity dedup
```
src/api/alerts_endpoints.py:720-789
Key: rule_id | entity_id | ioc_hash | hour_bucket
TTL: ALERT_DEDUP_TTL_SECONDS (default 30s)
```

#### Level 2 — Event-id dedup
```
src/api/alerts_endpoints.py:810-901
Key: event_id → emit_ts
Suppresses re-emit within dedup_window
```

#### Level 3 — Ring dedup
```
src/api/alerts_endpoints.py:910-934
Ring max: ALERT_RING_MAX = 500 (FIFO)
On dupe: increments dedup_increment counter on existing entry
```

#### Alert Fields
```json
{
  "id": "event_uuid",
  "rule_id": "rule_name",
  "rule_name": "human readable",
  "entity_id": "host|user",
  "host": "hostname",
  "user": "username",
  "verdict": "escalate|block|unknown",
  "confidence": 0.0-1.0,
  "score": 0.0-1.0,
  "severity": "critical|high|medium|low",
  "factors": ["factor_a", ...],
  "iocs": ["indicator", ...],
  "mitre": "T1078",
  "mitre_techniques": ["T1078", "T1021"],
  "ts": 1711234567,
  "tenant_id": "tenant_name",
  "title": "Alert title",
  "dedup_increment": 0
}
```

#### Severity Calculation ([src/api/alerts_endpoints.py:159-168](src/api/alerts_endpoints.py))
```python
if verdict in ('malicious','block','escalate') and score >= 0.9: "critical"
elif score >= 0.75: "high"
elif score >= 0.55: "medium"
else: "low"
```

#### Query Endpoints
```
GET /api/v1/alerts/recent         — last N alerts, tenant-scoped
GET /api/v1/alerts/search         — filter by host, verdict, min_score, time range
GET /api/v1/stream/decisions      — live SSE feed (subscribe for real-time)
```

### What to Ask the Stream For
```
# Real-time: subscribe to SSE
curl -N http://localhost:8080/api/v1/stream/decisions \
  -H "X-API-Key: <key>"

# Recent alerts (poll)
curl http://localhost:8080/api/v1/alerts/recent?limit=50&tenant_id=acme \
  -H "X-API-Key: <key>"

# High-confidence alerts only
curl "http://localhost:8080/api/v1/alerts/search?min_score=0.75&verdict=escalate" \
  -H "X-API-Key: <key>"

# HopGraph overlay stream
curl -N http://localhost:8080/api/v1/stream/hopgraph \
  -H "X-API-Key: <key>"
```

---

## 9. Latency Optimisation

### Current Optimizations (IN PLACE)

| Mechanism | Location | Effect |
|-----------|----------|--------|
| Memory circuit breaker | [src/core/event_pipeline/circuit_breaker.py:32-82](src/core/event_pipeline/circuit_breaker.py) | Disables heavy stages before OOM; checks every 5s |
| Heavy stage skip | [src/core/event_pipeline/pipeline.py:125-130](src/core/event_pipeline/pipeline.py) | Skips stages 22-30 if confidence ≥ 0.8 |
| PPR hop cap | [src/core/graph/hopgraph_lite.py:680-723](src/core/graph/hopgraph_lite.py) | α=0.15, 8 steps, cap=128, branch=16 |
| HopGraph preset cache | [src/core/graph/hopgraph_lite.py:54,473-485](src/core/graph/hopgraph_lite.py) | 15s TTL on graph query results |
| LRU for ASN lookups | `src/core/enrichment/asn_reputation.py` | `@lru_cache(maxsize=4096)` |
| LRU for factor descriptions | `src/core/reporting/factor_descriptions.py` | `@lru_cache(maxsize=1)` singleton |
| Graph event windowing | [src/core/graph/hopgraph_lite.py:36-38](src/core/graph/hopgraph_lite.py) | 900s window, 5000 event max, evict every 500 |
| Async throughout | `src/api/decisions_stream.py`, `pipeline.py` | Non-blocking I/O, cross-loop scheduling |
| Alert dedup early exit | [src/api/alerts_endpoints.py:823-839](src/api/alerts_endpoints.py) | PlatformState ring check before DB write |

### Bottlenecks (NOT YET OPTIMIZED)

| Bottleneck | File | Lines | Impact | Fix Needed |
|-----------|------|-------|--------|-----------|
| No Redis for distributed cache | — | — | Medium | Add Redis for shared LRU across workers |
| Single-event pipeline (no batching) | `pipeline.py` | 121 | Medium | Micro-batch 10-50 events |
| `/alerts/recent` no cache | `alerts_endpoints.py` | 193-408 | Low-Med | 5s cache on recent results |
| PPR non-incremental | `hopgraph_lite.py` | 680-723 | Medium | Incremental PageRank update |
| Alert dedup O(n) ring scan | `alerts_endpoints.py` | 915-934 | Low | Set-based dedup index |
| JSONL read on every history fetch | `alerts_endpoints.py` | 274-313 | Medium | Load once on startup, append-only |
| No vector index (pgvector) | (deleted migrations) | — | High for RAG | Re-add pgvector migrations |

### Pipeline Metrics Available
```
pipeline_stage_latency_ms{stage}          ← per-stage breakdown
pipeline_heavy_stage_latency_ms{stage}    ← heavy stage isolation
pipeline_confidence_progress{stage}       ← confidence evolution
pipeline_events_total{terminal}           ← throughput
pipeline_breaker_disabled                 ← circuit breaker state
hopgraph_ppr_latency_seconds             ← graph query time
```
**Source:** [src/core/event_pipeline/metrics.py](src/core/event_pipeline/metrics.py)

---

## 10. Test Suite Results

```
Total collected:   1,865 tests
PASSED:            1,657  (88.9%)
FAILED:              217  (11.6%)
SKIPPED:              40
xfailed:               1
Collection errors:    41 files (missing Python packages)
Runtime:           ~7 minutes
```

### Failure Root Causes

| Category | Count | Root Cause | Fix Priority |
|----------|-------|-----------|-------------|
| Correlation rule vectors missing | ~85 | `data/custom_test_vectors.json` deleted (git status shows `D`) | **P0** — restore file |
| XDR webhook auth (401 vs 200) | ~7 | Tests don't sign requests; WebhookGuardMiddleware on current branch requires HMAC | **P1** — add HMAC to test fixtures |
| Missing/moved API routes (404) | ~15 | IAM endpoints, metrics API, WEF/ETW, ISMS routes moved/removed | **P1** — route reconciliation |
| Async/coroutine errors | ~15 | `asyncio_mode = auto` unknown to installed pytest-asyncio version | **P1** — `pip install pytest-asyncio --upgrade` |
| LOLbin rule matching (assert False) | ~15 | Linux/macOS LOLbin tests, tfidf tokenizer tests — rule condition drift | **P1** |
| Snyk/supply chain TypeError | ~8 | API return shape changed | **P1** |
| Technique mapping TypeError | ~2 | Return type changed list→dict | **P1** |
| SSRF guard ordering | ~1 | Middleware priority: HMAC fires before SSRF check | **P2** |
| Tenant metrics/quota auth | ~6 | Admin key not in test fixtures | **P2** |
| HopGraph WAL snapshot tests | ~2 | `test_hopgraph_snapshot_wal*.py` — WAL persistence assertion | **P2** |
| Vendor adapter tests | ~3 | CrowdStrike, Splunk, Sentinel adapter assertions | **P2** |
| Collection errors (missing deps) | 41 files | `cryptography`, `lark`, `aiohttp`, `tenacity` not installed | **P0** — `pip install` |

### Missing Python Packages (blocks 41 test files)
```bash
pip install cryptography tenacity "lark-parser>=0.12" aiohttp pytest-timeout pytest-asyncio --upgrade
```

### Missing Package Details
| Package | Blocked Tests |
|---------|--------------|
| `cryptography` | 18 files — AKV, IAM workers, DKIM, token rotation, Proofpoint |
| `aiohttp` | 7 files — core functionality, correlation, custody, slack paths, persistence |
| `lark` | 2 files — syslog collector/TLS |
| `tenacity` | 1 file — connectors scaffold |
| `pytest-timeout` | All files (crashes `pytest.ini` addopts) |
| `botocore` | `test_import_moto.py` — DLQ/S3 tests |

### Playwright Tests — 18 Spec Files, Not Yet Run
```
tests/playwright/
  csv_analyzer.spec.ts           tier2_sse.spec.ts
  admin_factors.spec.ts          tier2_comment.spec.ts
  cached_explain_timing.spec.ts  csv_quick_actions.spec.ts
  evidence_extra.spec.ts         test_admin_thresholds.spec.ts
  live_evidence_actions.spec.ts  test_ewma_toggle.spec.ts
  llm_copy_export.spec.ts        test_mapping_modal.spec.ts
  llm_panels.spec.ts             test_sbom_upload.spec.ts
  precision_panel.spec.ts        test_tenant_temporal.spec.ts
                                 test_threat_topn_persistence.spec.ts
                                 test_upload_failure.spec.ts
```

**To run Playwright tests:**
```bash
# Start server first
uvicorn src.api.server:app --port 8080 &

# Then run Playwright
npx playwright test tests/playwright/
# or specific spec:
npx playwright test tests/playwright/tier2_sse.spec.ts --headed
```
Requires: Node.js, `node_modules` present (already installed), live server at `http://localhost:8080`.

---

## 11. Installation & Deployment Environments

### Minimum Requirements
```
CPU:  2 vCPU
RAM:  4 GB
Disk: 20 GB (for JSONL logs and graph snapshots)
OS:   Linux (Ubuntu 22.04 / Debian 12 recommended) or Docker on Windows/macOS
```

### Required Services
| Service | Version | Purpose | Required? |
|---------|---------|---------|-----------|
| PostgreSQL | 15+ | Events, decisions, audit logs | **YES** (SQLite fallback for dev) |
| Redis | 4.6+ | Rate limiting, RQ worker queue, session state | **YES** for workers |
| Prometheus | 2.x | Metrics collection | Recommended |
| Grafana | Latest | Dashboards | Optional |

### Optional External Services
| Service | Env Var | Purpose |
|---------|---------|---------|
| Ollama | `OLLAMA_HOST` | Local LLM (llama3, mistral, etc.) |
| Azure OpenAI | `OPENAI_API_KEY` | Cloud LLM |
| Anthropic | `ANTHROPIC_API_KEY` | Claude LLM |
| VirusTotal | `VT_API_KEY` | Hash/IP/domain reputation |
| Qualys | `QUALYS_*` | Vulnerability data |
| Slack | `SLACK_WEBHOOK_URL` | Alert notifications |
| SMTP | `SMTP_*` | Email alerts |

### Deployment Targets

#### Docker Compose (Primary)
```bash
docker compose up -d           # Standard
docker compose -f docker-compose.dev.yml up      # Dev + hot-reload
docker compose -f docker-compose.redis.yml up    # With Redis
docker compose -f docker-compose.azure.override.yml up  # Azure
docker compose -f docker-compose.gcp.override.yml up    # GCP
```

**Dockerfiles available:**
- `Dockerfile` — multi-stage standard (Python 3.11)
- `Dockerfile.api` — API-only build
- `Dockerfile.fast` — lightweight build
- `Dockerfile.worker` — RQ background worker
- `Dockerfile.collector` — data collector services

#### Kubernetes / Helm
```bash
helm install janusec ./helm/ -f helm/values.yaml
```
- Helm chart at [helm/](helm/)
- Supports: custom image repo, persistent Postgres, embedding worker toggle

#### Cloud Native (Terraform)
```
infra/terraform/dlq_main.tf    — AWS DLQ + S3 dead-letter
infra/terraform/variables.tf   — Cloud variables (Azure/GCP/AWS)
azure-deployment/              — AKS-ready configuration
gcp/functions/scc_pubsub/      — GCP Security Command Center ingestion
```

#### Bare Metal / Edge
- All services run on standard Linux VMs
- Python 3.11+, pip install from requirements.txt
- No container orchestration required

### Key Environment Variables
| Variable | Default | Purpose |
|----------|---------|---------|
| `APP_DB_DSN` | `postgresql://postgres:postgres@db:5432/janusec` | Database |
| `API_KEYS_JSON` | — | Required: `[{"key":"xxx","scopes":["read","write"]}]` |
| `OLLAMA_HOST` | `http://host.docker.internal:11434` | Local LLM |
| `OLLAMA_MODEL` | `llama3:8b` | LLM model |
| `PLATFORM_LITE_INIT` | `0` | `1` = disable heavy features for CI |
| `LLM_MOCK` | `0` | `1` = use fixture responses (testing) |
| `EVENT_QUEUE_MAX` | `2000` | Ingestion queue capacity |
| `ALERT_RING_MAX` | `500` | In-memory alert ring size |
| `ZEEK_NXDOMAIN_RATE_THRESHOLD` | `0.35` | DNS anomaly threshold |
| `ENABLE_VT_REPUTATION` | `0` | `1` = enable VirusTotal lookups |
| `PERSIST_BACKEND` | `jsonl` | `jsonl` / `postgres` / `dual` |

### Health Checks
```bash
curl http://localhost:8080/health   # alive?
curl http://localhost:8080/ready    # dependencies ready?
```

### CI Environments Defined
```
.github/workflows/ci.yml                  — Full test suite
.github/workflows/ci-validate.yml         — Lint + security
.github/workflows/pytest-lite.yml         — Fast unit tests
.github/workflows/pytest-full.yml         — Complete coverage
.github/workflows/helm-ci.yml             — Helm chart validation
.github/workflows/benchmark-ci.yml        — Performance testing
.github/workflows/playwright.yml          — E2E browser tests
.github/workflows/trivy.yml               — Container CVE scanning
.github/workflows/bandit.yml              — SAST security scan
.github/workflows/zap-baseline.yml        — OWASP ZAP API scan
.github/workflows/migrations-and-db-tests.yml — DB migration tests
```

---

## 12. Master Status Matrix

### Core Components
| Component | File | Lines | Status | Notes |
|-----------|------|-------|--------|-------|
| Event pipeline (30 stages) | [src/core/event_pipeline/pipeline.py](src/core/event_pipeline/pipeline.py) | 497 | ✅ REAL | Circuit breaker, stage timing, confidence blending |
| HopGraph PPR algorithm | [src/core/graph/hopgraph_lite.py:680-723](src/core/graph/hopgraph_lite.py) | 1003 | ✅ REAL | alpha=0.15, 8 steps, capped |
| Motif / lateral detection | [src/core/graph/hopgraph_lite.py:310-421](src/core/graph/hopgraph_lite.py) | — | ✅ REAL | 5 motif patterns |
| SSE decisions stream | [src/api/decisions_stream.py](src/api/decisions_stream.py) | 321 | ✅ REAL | Multi-client, ring buffer, metrics |
| HopGraph SSE stream | `src/api/hopgraph_stream.py` | — | ✅ REAL | Per-tenant, 40-item backlog |
| Alert 3-level dedup | [src/api/alerts_endpoints.py:690-934](src/api/alerts_endpoints.py) | 1171 | ✅ REAL | Rule-entity + event-id + ring |
| Webhook HMAC guard | [src/api/webhook_middleware.py](src/api/webhook_middleware.py) | — | ✅ REAL | Replay DB, timestamp, vendor-exempt |
| LLM T2 (deep analysis) | [src/api/tier2_endpoints.py](src/api/tier2_endpoints.py) | 200 | ✅ REAL | Budget guard, SSE streaming |
| LLM T1 (fast summary) | [src/core/correlation/tier1_summarizer.py](src/core/correlation/tier1_summarizer.py) | 48 | ⚠️ PARTIAL | Deterministic; LLM call in enhanced variant |
| Persona views (5 personas) | [src/reporting/persona_views.py](src/reporting/persona_views.py) | 173 | ✅ REAL | DREAD + email enrichment |
| VirusTotal integration | `src/artifact/vt_queue.py` | — | ✅ REAL | Rate-limited, token bucket |
| Qualys connector | `src/adapters/qualys_connector.py` | — | ✅ REAL | OAuth2, tenacity retry |
| Zeek log adapter | [src/live/zeek_adapter.py](src/live/zeek_adapter.py) | — | ✅ REAL | JSON line parser, GeoIP |
| Database (Postgres+SQLite) | `src/db/database.py` | — | ✅ REAL | asyncpg pool, SQLite fallback |
| RQ/LLM worker | `src/workers/llm_worker.py` | — | ✅ REAL | Redis-backed, batch=10 |
| Action dispatcher | [src/core/actions/dispatcher.py](src/core/actions/dispatcher.py) | 80+ | ✅ REAL | Rate limit, circuit breaker, outbox |
| Playbook executor | [src/modules/playbook_executor.py](src/modules/playbook_executor.py) | 15 | ❌ STUB | Returns `{'status':'success'}` always |
| Eclipse XDR sink | `src/core/actions/eclipse_sink.py` | — | ⚠️ PARTIAL | Logs only, no API call |
| MISP integration | `src/integrations/threat_intel_client.py` | — | ❌ STUB | URL stored, zero calls |
| OpenCTI integration | `src/integrations/threat_intel_client.py` | — | ❌ STUB | URL stored, zero calls |
| Alert Postgres persistence | `src/api/alerts_endpoints.py:648` | — | ❌ STUB | "extend later" comment |
| PageRank (graph_scoring) | `src/core/graph/graph_scoring.py:163` | — | ❌ STUB | `len(path)/10` heuristic |
| WebSocket endpoints | (entire codebase) | — | ❌ NONE | SSE only; no WS implemented |
| Graph session tracking | — | — | ❌ STUB | No session objects; PPR stateless |

### 8-Domain Rule Coverage
| Domain | Files | Status |
|--------|-------|--------|
| Email / BEC | 15 | ✅ Richest domain |
| Supply Chain | 3 | ✅ Real |
| Binary / Endpoint | 4 | ✅ Real |
| Graph / Lateral Movement | 2 | ✅ Real |
| Network | 2+ | ✅ Real |
| IAM / Identity | 2 | ⚠️ Needs expansion |
| API Security | 2 | ⚠️ Needs expansion |
| eBPF / Container | 2 | ⚠️ Linux-only, needs testing |

---

*This document was auto-generated from live codebase analysis and test run results on 2026-03-24.*
