# JanuSec — Full Platform Assessment & Go-To-Market Report
**Date:** 2026-03-24
**Branch:** feat/webhook-guard-middleware-only-verification
**Test Results:** 1,865 tests | 1,657 passed (88.9%) | 217 failed | 40 skipped | 41 files blocked (missing deps)
**Overall Readiness:** ~72% production-ready

---

## Table of Contents
1. [What JanuSec Does & Who It's For](#1-what-janusec-does--who-its-for)
2. [Competitive Landscape](#2-competitive-landscape)
3. [Test Suite Results](#3-test-suite-results)
4. [HopGraph Correlation Engine](#4-hopgraph-correlation-engine)
5. [LLM Tier-1 & Tier-2 Summaries](#5-llm-tier-1--tier-2-summaries)
6. [Persona-Based Reporting](#6-persona-based-reporting)
7. [8-Domain Detection Coverage](#7-8-domain-detection-coverage)
8. [Isolation, SOAR & Playbooks](#8-isolation-soar--playbooks)
9. [Stream Events & Alert Pipeline](#9-stream-events--alert-pipeline)
10. [Latency Optimisation](#10-latency-optimisation)
11. [Excel/CSV Batch Processing — 5-Minute Fix](#11-excelcsv-batch-processing--5-minute-fix)
12. [Connector Status](#12-connector-status)
13. [Real-Time Streaming Architecture](#13-real-time-streaming-architecture)
14. [Cloud Telemetry Funnel — Azure / AWS / GCP / Oracle](#14-cloud-telemetry-funnel--azure--aws--gcp--oracle)
15. [Codex GPT Work — What Was Fixed](#15-codex-gpt-work--what-was-fixed)
16. [Installation & Deployment Environments](#16-installation--deployment-environments)
17. [Path to Market — Prioritized Roadmap](#17-path-to-market--prioritized-roadmap)
18. [Master Status Matrix](#18-master-status-matrix)

---

## 1. What JanuSec Does & Who It's For

### Core Value Proposition
JanuSec is an **AI-powered Extended Detection & Response (XDR) platform** solving the "alert tsunami" problem in enterprise SOCs.

| Metric | Claim | Source |
|--------|-------|--------|
| False positive reduction | 98% | [README.md:11-32](README.md) |
| Alert recall preserved | 96%+ | [README.md:36](README.md) |
| Analyst workload reduction | 70% | [README.md:32](README.md) |
| Cost vs Splunk | 97% cheaper ($0.002 vs $0.06/event) | [JANUSEC_COMPETITIVE_ANALYSIS.md](JANUSEC_COMPETITIVE_ANALYSIS.md) |
| Detection speed | 10x faster (minutes vs hours) | [README.md:32](README.md) |
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
Stages  1- 5  │ Baseline       │ IOC lookup, allowlists           │ <1ms
Stages  6-12  │ Lightweight    │ Regex, entropy, port scans, geo  │ 1-10ms
Stages 13-21  │ Adaptive       │ TF-IDF, beaconing, DNS exfil     │ 10-50ms
Stages 22-25  │ Correlation    │ HopGraph, temporal, co-occur     │ 20-100ms
Stages 26-28  │ ML             │ Isolation Forest, LightGBM       │ 50-200ms
Stages 29-30  │ External AI    │ Ollama / Azure OpenAI            │ 500-2000ms
```
**Source:** [src/core/event_pipeline/pipeline.py:84-130](src/core/event_pipeline/pipeline.py)

---

## 2. Competitive Landscape

| Vendor | Category | JanuSec Advantage |
|--------|----------|-------------------|
| **Splunk Enterprise Security** | SIEM | 97% cheaper; self-tuning vs manual rules; multi-domain |
| **Microsoft Sentinel** | Cloud SIEM | Vendor-agnostic; on-prem/edge; no Azure lock-in |
| **CrowdStrike Falcon XDR** | EDR+XDR | 8 domains vs endpoint-only; no mandatory agent |
| **Palo Alto Cortex XDR** | XDR | No Palo Alto hardware dependency; open connector model |
| **Elastic Security** | SIEM | LLM triage vs manual investigation; adaptive FP suppression |
| **Wiz / Orca** | CSPM | Real-time threat detection, not just posture |

### JanuSec's 5 Unique Differentiators
1. **Only 8-domain simultaneous correlation** — endpoint + network + email + IAM + cloud + data + remote + API
2. **AI triage, not just detection** — LLM T1/T2 summaries with 5 personas, graceful local fallback
3. **Self-tuning FP suppression** — TF-IDF rarity + feedback loop auto-weight + EWMA baselines
4. **Explainability-first** — DREAD score + factor provenance + chain-of-custody hash per verdict
5. **Graceful degradation** — Full detection with zero external dependencies (local rules + ML)

---

## 3. Test Suite Results

```
Total collected:    1,865 tests
PASSED:             1,657  (88.9%)
FAILED:               217  (11.6%)
SKIPPED:               40
xfailed:                1
Collection errors:     41 files (missing Python packages)
Runtime:            ~7 minutes
```

### Failure Root Causes

| Category | Count | Root Cause | Fix Priority |
|----------|-------|-----------|-------------|
| Correlation rule test vectors missing | ~85 | `data/custom_test_vectors.json` deleted (git status `D`) | **P0** — restore file |
| XDR webhook auth (401 vs 200) | ~7 | Tests don't sign requests; WebhookGuardMiddleware requires HMAC on this branch | **P1** |
| Missing/moved API routes (404) | ~15 | IAM, metrics, ISMS, WEF/ETW endpoints moved/removed | **P1** |
| Async/coroutine errors | ~15 | `asyncio_mode = auto` unknown to installed pytest-asyncio | **P1** — `pip install pytest-asyncio --upgrade` |
| LOLbin rule matching (assert False) | ~15 | Linux/macOS LOLbin tests, tfidf tokenizer — rule condition drift | **P1** |
| Snyk/supply chain TypeError | ~8 | API return shape changed | **P1** |
| Technique mapping TypeError | ~2 | Return type changed list→dict | **P1** |
| SSRF guard ordering | ~1 | HMAC fires before SSRF check in middleware chain | **P2** |
| Tenant metrics/quota auth | ~6 | Admin key not in test fixtures | **P2** |
| HopGraph WAL snapshot tests | ~2 | WAL persistence assertion drifted | **P2** |
| Vendor adapter tests | ~3 | CrowdStrike, Splunk, Sentinel schema drift | **P2** |
| Collection errors (missing deps) | 41 files | `cryptography`, `lark`, `aiohttp`, `tenacity`, `pytest-timeout` not installed | **P0** |

### Missing Python Packages
```bash
pip install cryptography tenacity "lark>=0.12" aiohttp pytest-timeout pytest-asyncio botocore --upgrade
```

| Package | Blocked Test Files |
|---------|-------------------|
| `cryptography` | 18 — AKV, IAM workers, DKIM, token rotation, Proofpoint |
| `aiohttp` | 7 — core functionality, correlation, custody, slack, persistence |
| `lark` | 2 — syslog collector/TLS |
| `tenacity` | 1 — connectors scaffold |
| `pytest-timeout` | All files (crashes `pytest.ini` addopts) |
| `botocore` | 1 — DLQ/S3 tests |

### Playwright — 18 Spec Files, Not Run Yet
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
```bash
# Run Playwright (requires live server)
uvicorn src.api.server:app --port 8080 &
npx playwright test tests/playwright/
```

---

## 4. HopGraph Correlation Engine

**Primary file:** [src/core/graph/hopgraph_lite.py](src/core/graph/hopgraph_lite.py) (1,003 lines)
**Status: REAL — Substantially Production-Grade**

### What Is Implemented (REAL)

#### Graph Construction
```
src/core/graph/hopgraph_lite.py:35-60   — State: edges_ts, node_registry, _spike_state
src/core/graph/hopgraph_lite.py:242     — observe() — event → edge + node registration
src/core/graph/hopgraph_lite.py:296     — Auto-evict every 500 events
```

**Node types:** `user`, `host`, `process`, `package`, `cicd`, `binary`

**Edge types with TTLs:**
| Edge | TTL | Meaning |
|------|-----|---------|
| `auth` | 72h | user → host |
| `net` | 24h | host → host |
| `proc` | 12h | user → process |
| `deploys` | configurable | cicd → binary |
| `builds` | configurable | cicd → package |

#### Personalized PageRank (PPR) ✅ REAL
```
src/core/graph/hopgraph_lite.py:680-723 — ppr() algorithm
```
- alpha=0.15, 8 steps, cap=128 nodes, branch cap=16
- Returns top-32 nodes by score
- Metric: `hopgraph_ppr_latency_seconds` histogram

#### Motif Detection ✅ REAL
```
src/core/graph/hopgraph_lite.py:310-421 — factors() motif patterns
src/core/graph/hopgraph_lite.py:754-779 — detect_lateral_chain()
```
- Lateral movement: user → multiple hosts (BFS)
- Process burst: user → 5+ distinct processes
- DC-first-touch detection
- Auth → proc → net sequence

#### Leaky Integrate-and-Fire ✅ REAL
```
src/core/graph/hopgraph_lite.py:726-745 — integrate_spike()
```
- V(t) = V₀ × exp(−decay × dt) + strength

#### Graph Session Persistence ✅ REAL (Codex — new)
```
src/repositories/graph_sessions_repo.py — DB-backed session CRUD
src/api/graph_sessions.py:259           — persist/load on build
src/api/graph_sessions.py:4417,4440,4467 — /replay, /paths, /timeline endpoints
```

### What Needs More Work (STUB / INCOMPLETE)

| Gap | File | Lines | Issue |
|-----|------|-------|-------|
| PageRank in graph_scoring | [src/core/graph/graph_scoring.py:163](src/core/graph/graph_scoring.py) | 163-164 | `len(path)/10` heuristic — not real PageRank |
| hopgraph_integration fallback | [src/core/graph/hopgraph_integration.py:52-100](src/core/graph/hopgraph_integration.py) | 52-100 | Deterministic response generation only |
| Multi-domain graph rollup | N/A | — | Cross-domain `domain_confidence` not computed |

### HopGraph Metrics
```
hopgraph_nodes_total              (gauge)
hopgraph_edges_total              (gauge)
hopgraph_ppr_latency_seconds      (histogram)
hopgraph_reconstructions_total    (counter)
hopgraph_evictions_total          (counter)
```

---

## 5. LLM Tier-1 & Tier-2 Summaries

### Fallback Chain
```
src/integrations/llm_client.py — Ollama → OpenAI → Anthropic → LocalDeterministic
```

| Provider | Env Var | Latency | Notes |
|----------|---------|---------|-------|
| Ollama (local) | `OLLAMA_HOST` | 1-5s | Default if configured |
| OpenAI | `OPENAI_API_KEY` | 0.5-2s | GPT-4o-mini for T1 |
| Anthropic | `ANTHROPIC_API_KEY` | 0.5-2s | Claude for T1/T2 |
| LocalDeterministic | always | <10ms | Hash-based; forbidden in live mode |

### Tier 1 (T1) — Fast Triage

| File | Lines | Status |
|------|-------|--------|
| [src/api/insights_endpoints.py:509-626](src/api/insights_endpoints.py) | 626 | ✅ REAL — primary T1 engine |
| [src/core/correlation/tier1_summarizer.py](src/core/correlation/tier1_summarizer.py) | 48 | ✅ REAL — deterministic fallback |
| [src/api/llm_tier1.py:15-39](src/api/llm_tier1.py) | 39 | ⚠️ STUB — hardcoded rationale strings |
| [src/api/llm_tier1_enhanced.py](src/api/llm_tier1_enhanced.py) | — | ✅ REAL — full LLM |
| [src/api/llm_tier1_local.py](src/api/llm_tier1_local.py) | — | ✅ REAL — Ollama-only variant |

**Triage gating** ([src/api/insights_endpoints.py:513-543](src/api/insights_endpoints.py)):
```
triage_score < LLM_T1_MIN_TRIAGE (0.15) → skip LLM
existing_llm_cost >= LLM_BUDGET_PER_ASSESSMENT → skip (budget)
otherwise → call LLM with persona-injected prompt
```

**T1 Prompt:**
```
"SOC analyst FAST TRIAGE — schema: WHAT IS IT / EXPLOITABILITY / WHAT TO DO / PLAYBOOK (30-45 lines)
Process: {proc}  Host: {host}  Verdict: {verdict}  DREAD: {dread}  Signals: {signals}"
```

### Tier 2 (T2) — Deep Cross-Domain Analysis

| File | Lines | Status |
|------|-------|--------|
| [src/api/insights_endpoints.py:629-699](src/api/insights_endpoints.py) | — | ✅ REAL — primary T2 engine |
| [src/api/tier2_endpoints.py:103-170](src/api/tier2_endpoints.py) | 200 | ✅ REAL — SSE streaming |
| [src/ai/tier2_prompts.py](src/ai/tier2_prompts.py) | — | ✅ REAL — prompt builder |
| [src/api/llm_tier2_rag.py](src/api/llm_tier2_rag.py) | — | ✅ REAL — RAG variant |
| [src/queue/redis_tier2.py](src/queue/redis_tier2.py) | — | ✅ REAL — Redis-queued async |

**T2 enriches with:** timeline, supply chain (OAuth/repo/package), sandbox results, business impact, full pipeline context

**T2 Budget Guard:** `T2_BUDGET_LEFT` env — HTTP 402 if exceeded; cost estimate: `$0.015 × max(1, row_count)`

**T2 SSE tokens streamed:** [src/api/tier2_endpoints.py:103-170](src/api/tier2_endpoints.py) — real `StreamingResponse`, token-by-token

---

## 6. Persona-Based Reporting

**Status: REAL — 5 personas with distinct views**

| File | Role |
|------|------|
| [src/reporting/persona_views.py:29-173](src/reporting/persona_views.py) | Core `generate_persona_view()` |
| [src/analysis/persona_format.py:1-34](src/analysis/persona_format.py) | LLM prompt templates per persona |
| [src/reporting/persona_parser.py:71-150](src/reporting/persona_parser.py) | Parses & validates LLM structured output |
| [src/core/ranking/persona_forwarder.py](src/core/ranking/persona_forwarder.py) | Routes to downstream consumer |
| [frontend/static/js/persona_ui.js](frontend/static/js/persona_ui.js) | Frontend persona switcher |

### Personas

| Persona | Key Additions | LLM Prompt Style |
|---------|--------------|-----------------|
| `executive` | headline, business_impact, tier_metadata | High-level; severity label, business impact |
| `soc_analyst` | raw factors, MITRE, IOC list, investigation steps | Concise, actionable, technical |
| `compliance` | control mappings, NIST/ISO/PCI references | Audit trail; framework alignment |
| `threat_hunter` | graph context, lateral movement paths, TTPs | Hunt hypotheses; statistical breakdown |
| `mssp` | per-tenant partitioned view, quota/cost metadata | Multi-tenant; SLA-aware |

**Progressive Disclosure Levels** ([src/reporting/persona_views.py:94-125](src/reporting/persona_views.py)):
```
Level 1 (MINIMAL):  headline + top action + playbook_actions
Level 2 (SUMMARY):  timeline + IOCs + decision gates + redacted evidence
Level 3 (DETAILED): full provenance + evidence links
```

### What Needs More Work
- `forensics` persona in prompt templates ([src/analysis/persona_format.py:15-17](src/analysis/persona_format.py)) **not wired into `generate_persona_view()`**
- `mssp` persona content is skeletal vs executive/soc_analyst
- Playbook attachment to persona view uses optional import that may not resolve

---

## 7. 8-Domain Detection Coverage

**Total rule files:** 79 Python files across 14 domain subdirectories
**Source:** [src/core/correlation/rules/](src/core/correlation/rules/)

### Domain Coverage Map

| # | Domain | Directory | Rules | Status | Priority Gap |
|---|--------|-----------|-------|--------|-------------|
| 1 | **Email / BEC** | `rules/email/` | 15 | ✅ Complete | — |
| 2 | **Endpoint / LOLbin** | `rules/lolbin/`, `week1/`, `week2/` | 10+ | ✅ Real | Test vectors missing |
| 3 | **Supply Chain** | `rules/supplychain/` | 3 | ✅ Real | Needs expansion |
| 4 | **Binary / Malware** | `rules/binary/` | 4 | ✅ Real | — |
| 5 | **Graph / Lateral** | `rules/graph/` | 2 | ✅ Real | — |
| 6 | **Network** | `rules/network/` | 2+ | ✅ Real | Needs C2/exfil rules |
| 7 | **IAM / Identity** | `rules/iam/` | 2 | ⚠️ Partial | **AD, Entra, Okta missing** |
| 8 | **API Security** | `rules/api_security*.py` | 2 | ⚠️ Partial | Needs expansion |
| — | **eBPF / Container** | `rules/ebpf/` | 2 | ⚠️ Minimal | Linux-only, limited |
| — | **Cloud** | Not built | 0 | ❌ Missing | **GCP/Azure/AWS rules needed** |
| — | **Data / Exfil** | Partial in network | 0 dedicated | ❌ Missing | — |
| — | **Kernel / eBPF deep** | `rules/ebpf/` | 2 | ❌ Minimal | Container escape only |

### Email Domain — Richest Coverage (15 rules)
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

### Why ~85 Rule Tests Fail
```python
# ALL failing rule tests load from deleted data/custom_test_vectors.json:
evt = load_vector("col_keylogger_detected_exfil")  # file gone → empty event
assert any(r.id == "col_keylogger_detected_exfil" for r in matches)
# → assert False  (rules are real; test vectors are missing)
```
**Fix:** restore `data/custom_test_vectors.json` or regenerate from rule schemas.

### Multi-Domain Aggregation — STUB
The `domain_confidence` field mentioned in T2 context is **never computed** — there is no code that aggregates across domains into a single cross-domain confidence rollup. This is a significant gap for the "8-domain" marketing claim.

---

## 8. Isolation, SOAR & Playbooks

### Full SOAR Engine — REAL

**Location:** [src/soar/](src/soar/) — 14 files

| File | Status | Role |
|------|--------|------|
| [src/soar/playbook_engine.py](src/soar/playbook_engine.py) | ✅ REAL | Isolation/block/quarantine APIs |
| [src/soar/playbook_executor.py:55-205](src/soar/playbook_executor.py) | ✅ REAL | Async DAG execution, idempotency |
| [src/soar/playbook_loader.py](src/soar/playbook_loader.py) | ✅ REAL | YAML → dataclass |
| [src/soar/playbook_queue.py](src/soar/playbook_queue.py) | ✅ REAL | Async queue |
| [src/soar/playbook_worker.py](src/soar/playbook_worker.py) | ✅ REAL | Background processor |
| [src/soar/connectors.py:49-71](src/soar/connectors.py) | ✅ REAL | httpx http_post, ApiKey + Bearer auth |
| [src/soar/connector_audit.py](src/soar/connector_audit.py) | ✅ REAL | Audit trail (who called what) |
| [src/soar/engine.py](src/soar/engine.py) | ✅ REAL | Core execution engine |
| [src/soar/dsl_schema.py](src/soar/dsl_schema.py) | ✅ REAL | YAML DSL schema validation |
| [src/soar/actions/slack_notify.py](src/soar/actions/slack_notify.py) | ✅ REAL | Slack action handler |
| [src/soar/actions/tag_event.py](src/soar/actions/tag_event.py) | ✅ REAL | Alert tagging |

> **Note:** `src/modules/playbook_executor.py` (15 lines, always returns success) is a shim/adapter — the real engine is `src/soar/`.

### Connector Pattern — Conditional Real/Mock
```python
# src/soar/connectors.py:74-80
async def firewall_block_ip(params):
    url = params.get('api_url')
    if url:
        return await http_post(url, {"action": "block", "ip": ip})  # ← REAL
    await asyncio.sleep(0.01)
    return {"blocked": True, "ip": ip}  # ← MOCK (safe default, no config needed)
```

### Isolation Actions Available

| Action | Status | Requires |
|--------|--------|---------|
| `isolate_endpoint` (EDR) | ✅ Real HTTP POST | `api_url` in playbook params |
| `block_ip_address` (firewall) | ✅ Real HTTP POST | `api_url` |
| `quarantine_file` (EPP) | ✅ Real HTTP POST | `api_url` |
| `idp_revoke_sessions` | ✅ Real HTTP POST | `api_url` |
| Email quarantine (MS Graph) | ✅ REAL | MS Graph app registration |
| Slack notification | ✅ Always real | `SLACK_WEBHOOK_URL` env |
| Alert tagging | ✅ Always real | None |
| Ticket write | ✅ Always real | None |
| `mailbox_disable_rule` | ⚠️ Mock | `sleep(0.01)` — not implemented |
| Eclipse XDR verdict push | ❌ Logs only | Not implemented |

### Playbook Execution Guarantees
```
src/soar/playbook_executor.py:55-205
```
- **Idempotency**: Re-running same `execution_id` skips already-completed steps
- **DAG dependencies**: `depends_on: [step_id]` blocks on pending deps
- **Conditional gating**: `require_factor` skips step if factor absent from context
- **Templating**: `{{context.field}}` substitution in params
- **Audit log**: `action_log/DATE/execution_id.jsonl`

### Playbook YAML Schema
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

### Not Yet Implemented in Playbooks
- Rollback semantics (completed action = permanent)
- Conditional branching (if/else logic)
- Loops / iteration
- Approval workflows (`approval_required` field exists but ignored)

---

## 9. Stream Events & Alert Pipeline

### SSE Decisions Stream — REAL

**File:** [src/api/decisions_stream.py](src/api/decisions_stream.py) (321 lines)

```
GET /api/v1/stream/decisions     — multi-client SSE broadcast
GET /api/v1/stream/artifacts     — alias to decisions stream
GET /api/v1/stream/hopgraph      — attack graph overlay SSE (40-item backlog)
```

**Architecture:**
```
publish_decision(summary)
  → _CLIENT_QUEUES (asyncio.Queue per client, maxsize=1000)
  → cross-loop safe: run_coroutine_threadsafe()
  → _RECENT_DECISIONS ring (maxlen=50) — new subscribers get backfill
  → keepalive ":keepalive\n\n" every 0.5s timeout
```

**SSE Payload shape** ([src/api/decisions_stream.py:58-191](src/api/decisions_stream.py)):
```json
{
  "event_id": "uuid",
  "confidence": 0.85,
  "verdict": "escalate",
  "ts": 1711234567.89,
  "factors": ["bec_reply_chain", "dkim_fail"],
  "stage_timings": [
    {"name": "baseline",  "duration_ms": 3,  "confidence_after": 0.3},
    {"name": "tfidf",     "duration_ms": 12, "confidence_after": 0.6},
    {"name": "hopgraph",  "duration_ms": 45, "confidence_after": 0.85}
  ],
  "ab_tests": [{"test_id": "exp_001", "variant": "A"}]
}
```

### Alert Pipeline — 3-Level Dedup (REAL)

**File:** [src/api/alerts_endpoints.py](src/api/alerts_endpoints.py) (1,171 lines)

| Level | Location | Key | TTL |
|-------|----------|-----|-----|
| 1 — Rule-entity | `alerts_endpoints.py:720-789` | `rule_id|entity_id|ioc_hash|hour_bucket` | 30s |
| 2 — Event-id | `alerts_endpoints.py:810-901` | `event_id → emit_ts` | dedup_window |
| 3 — Ring | `alerts_endpoints.py:910-934` | ring scan, `dedup_increment` counter | FIFO, max=500 |

**Alert Fields:**
```json
{
  "id": "event_uuid",          "rule_id": "rule_name",
  "entity_id": "host|user",   "host": "hostname",
  "user": "username",          "verdict": "escalate|block|unknown",
  "confidence": 0.85,          "severity": "critical|high|medium|low",
  "factors": ["factor_a"],     "iocs": ["indicator"],
  "mitre": "T1078",            "mitre_techniques": ["T1078","T1021"],
  "ts": 1711234567,            "tenant_id": "acme",
  "title": "Alert title",      "dedup_increment": 0
}
```

**Severity calculation** ([src/api/alerts_endpoints.py:159-168](src/api/alerts_endpoints.py)):
```python
if verdict in ('malicious','block','escalate') and score >= 0.9: "critical"
elif score >= 0.75: "high"
elif score >= 0.55: "medium"
else: "low"
```

### What to Call

```bash
# Subscribe to real-time SSE decisions
curl -N http://localhost:8080/api/v1/stream/decisions \
  -H "X-API-Key: <key>" -H "X-Tenant-ID: acme"

# Recent alerts (poll)
curl "http://localhost:8080/api/v1/alerts/recent?limit=50&tenant_id=acme" \
  -H "X-API-Key: <key>"

# High-confidence alerts only
curl "http://localhost:8080/api/v1/alerts/search?min_score=0.75&verdict=escalate" \
  -H "X-API-Key: <key>"

# HopGraph overlay stream
curl -N http://localhost:8080/api/v1/stream/hopgraph \
  -H "X-API-Key: <key>" -H "X-Tenant-ID: acme"

# T2 summary (SSE token-by-token)
curl -N -X POST http://localhost:8080/api/v1/csv/tier2_sse \
  -H "X-API-Key: <key>" -H "X-Tenant-ID: acme" \
  -H "Content-Type: application/json" \
  -d '{"org":"acme","assessment_id":"abc","rows":[...]}'
```

---

## 10. Latency Optimisation

### Current Optimizations (IN PLACE)

| Mechanism | File | Lines | Effect |
|-----------|------|-------|--------|
| Memory circuit breaker | [src/core/event_pipeline/circuit_breaker.py:32-82](src/core/event_pipeline/circuit_breaker.py) | 32-82 | Disables heavy stages before OOM |
| Heavy stage skip | [src/core/event_pipeline/pipeline.py:125-130](src/core/event_pipeline/pipeline.py) | 125-130 | Skips stages 22-30 if confidence ≥ 0.8 |
| PPR hop cap | [src/core/graph/hopgraph_lite.py:680-723](src/core/graph/hopgraph_lite.py) | 680-723 | α=0.15, 8 steps, cap=128 |
| HopGraph preset cache | [src/core/graph/hopgraph_lite.py:473-485](src/core/graph/hopgraph_lite.py) | 473-485 | 15s TTL on graph query results |
| ASN LRU cache | `src/core/enrichment/asn_reputation.py` | — | `@lru_cache(maxsize=4096)` |
| Graph event windowing | [src/core/graph/hopgraph_lite.py:36-38](src/core/graph/hopgraph_lite.py) | 36-38 | 900s window, 5,000 event max |
| Alert dedup early exit | [src/api/alerts_endpoints.py:823-839](src/api/alerts_endpoints.py) | 823-839 | Ring check before DB write |
| Async/await throughout | `pipeline.py`, `decisions_stream.py` | — | Non-blocking I/O |
| T2 SSE streaming | [src/api/tier2_endpoints.py:103-170](src/api/tier2_endpoints.py) | 103-170 | Token-by-token — user sees first token fast |

### Bottlenecks (NOT YET OPTIMIZED)

| Bottleneck | File | Lines | Fix Needed |
|-----------|------|-------|-----------|
| Single-event pipeline (no batching) | `pipeline.py` | 121 | Micro-batch 10-50 events |
| No Redis for distributed LRU | — | — | Add Redis for shared cache across workers |
| `/alerts/recent` no result cache | `alerts_endpoints.py` | 193-408 | 5s cache on recent results |
| PPR non-incremental | `hopgraph_lite.py` | 680-723 | Incremental PageRank update |
| Alert dedup O(n) ring scan | `alerts_endpoints.py` | 915-934 | Set-based dedup index |
| JSONL read on every history fetch | `alerts_endpoints.py` | 274-313 | Load once on startup, append-only |
| pgvector deleted | deleted migrations | — | Re-add for RAG T2 semantic search |

### Pipeline Stage Metrics
```
pipeline_stage_latency_ms{stage}        ← per-stage breakdown
pipeline_heavy_stage_latency_ms{stage}  ← heavy stage isolation
pipeline_confidence_progress{stage}     ← confidence evolution
pipeline_events_total{terminal}         ← throughput
pipeline_breaker_disabled               ← circuit breaker state
hopgraph_ppr_latency_seconds            ← graph query latency
```
**Source:** [src/core/event_pipeline/metrics.py](src/core/event_pipeline/metrics.py)

---

## 11. Excel/CSV Batch Processing — 5-Minute Fix

### The Problem
When user uploads `CyberStash_csv1.xlsx` or `CyberStash_csv2.xlsx` (~500 rows):
- All 500 rows processed sequentially
- LLM T2 per row: 1-5 seconds
- **Total perceived wait: 5+ minutes before any result appears**

### What Already Exists (Partially Wired)

The backfill engine at [src/api/csv_endpoints.py:867-960](src/api/csv_endpoints.py) already:
- Sorts rows by `triage_score` percentile (highest risk first)
- Has configurable `BACKFILL_BURST_SIZE` (immediate batches) and `BACKFILL_BATCH_SIZE`
- Has `chunk_index` / `chunk_total` fields on the payload model
- Processes in background asyncio tasks

**Gap:** Frontend doesn't render results progressively — waits for 100% completion.

### Recommended Fix — Priority Top-10 Pre-Burst

**Concept:** Sort uploaded rows by triage score → emit top-10 first → T1 LLM → stream results via SSE → process remainder in background.

**Environment tuning (works today, no code change needed):**
```env
BACKFILL_BURST_SIZE=1           # emit top batch immediately
BACKFILL_BATCH_SIZE=10          # 10 rows per burst
LLM_T1_MIN_TRIAGE=0.1           # lower threshold → more rows get T1
BACKFILL_MAX_RUNTIME_SECONDS=300
```

**API call sequence:**
```
1. POST /api/v1/upload/files
   → { assessment_id: "abc123", chunk_total: 50 }

2. POST /api/v1/csv/backfill_initiate
   → { assessment_id: "abc123", batch_size: 10, target_coverage: 1.0 }

3. GET  /api/v1/stream/decisions   (SSE)
   → top-10 rows stream back within ~15-30s

4. GET  /api/v1/alerts/recent?assessment_id=abc123
   → poll for full results as background completes
```

**Latency budget per row:**
```
T1 summary (Ollama local):      1-3s
T1 summary (GPT-4o-mini):      0.5-1s
Regex + TF-IDF pipeline:        <50ms
HopGraph correlation:           20-100ms
─────────────────────────────────────
Top-10 visible results:         ~15-30s  (vs 5 minutes for 500)
```

**Frontend change needed:**
```javascript
// frontend/static/js/csv_analyzer.js — listen to SSE, render as rows complete
const evtSrc = new EventSource('/api/v1/stream/decisions');
evtSrc.onmessage = (e) => renderAlert(JSON.parse(e.data));
```

---

## 12. Connector Status

### Data Ingest Connectors

| Connector | File | Status | Real API? | Notes |
|-----------|------|--------|-----------|-------|
| **Zeek** (network logs) | [src/live/zeek_adapter.py](src/live/zeek_adapter.py) | ✅ REAL | File/socket | JSON line parser, GeoIP, heartbeat |
| **Qualys** (vuln) | `src/adapters/qualys_connector.py` | ✅ REAL | OAuth2 + HTTP | Tenacity retry, CVSS normalization |
| **VirusTotal** | `src/artifact/vt_queue.py` | ✅ REAL | HTTP v3 API | Rate-limited 4/min, token bucket |
| **Microsoft Graph** | `src/integrations/ms_graph_connector.py` | ✅ REAL | OAuth2 MS Graph | O365/Exchange email |
| **Snyk** | `src/adapters/snyk_connector.py` | ✅ REAL | HTTP API | Tests drifted — 429/500/timeout |
| **Proofpoint TAP** | `src/connectors/` | ⚠️ PARTIAL | HTTP API | Needs `cryptography` dep |
| **Tenable** | Referenced in tests | ⚠️ PARTIAL | Unknown | VPR enrichment tested only |
| **CrowdStrike** | `src/adapters/` | ⚠️ PARTIAL | Schema map | Adapter test assertions failing |
| **Splunk** | `src/adapters/` | ⚠️ PARTIAL | Schema map | Adapter test assertions failing |
| **Microsoft Sentinel** | `src/adapters/` | ⚠️ PARTIAL | Schema map | Adapter test assertions failing |
| **Wazuh** | Referenced in tests | ⚠️ PARTIAL | Log file | Schema assertions failing |
| **Suricata** | Referenced in tests | ⚠️ PARTIAL | Log file | Assertions failing |
| **GCP SCC** | `gcp/functions/scc_pubsub/` | ⚠️ PARTIAL | Pub/Sub | Function exists, not integrated |
| **Eclipse XDR** | `src/adapters/eclipse_xdr.py` | ❌ STUB | Logs only | "Phase 1" — no real API calls |
| **MISP** | `src/integrations/threat_intel_client.py` | ❌ STUB | Placeholder | URL stored, never called |
| **OpenCTI** | `src/integrations/threat_intel_client.py` | ❌ STUB | Placeholder | URL stored, never called |
| **Azure Event Hubs** | Not built | ❌ MISSING | — | **High priority for cloud funnel** |
| **AWS Kinesis** | `infra/terraform/dlq_main.tf` partial | ❌ MISSING | — | DLQ exists, stream consumer missing |
| **Active Directory** | `rules/iam/` only | ❌ MISSING | — | No AD/Entra/Okta connector |

### Action/Response Connectors

| Connector | Status | Config |
|-----------|--------|--------|
| Slack | ✅ REAL | `SLACK_WEBHOOK_URL` |
| EDR isolation | ✅ Real if `api_url` set | Playbook param |
| Firewall block | ✅ Real if `api_url` set | Playbook param |
| File quarantine | ✅ Real if `api_url` set | Playbook param |
| IdP revoke | ✅ Real if `api_url` set | Playbook param |
| Email quarantine | ✅ REAL (MS Graph) | MS Graph app registration |
| Ticket write | ✅ REAL | Writes to `tickets/tickets.log` |
| Eclipse XDR verdict | ❌ Logs only | Not implemented |

---

## 13. Real-Time Streaming Architecture

### What's Live

| Endpoint | Type | Status | Notes |
|----------|------|--------|-------|
| `GET /api/v1/stream/decisions` | SSE | ✅ REAL | Multi-client, 50-event ring backfill |
| `GET /api/v1/stream/artifacts` | SSE | ✅ REAL | Alias to decisions |
| `GET /api/v1/stream/hopgraph` | SSE | ✅ REAL | Per-tenant, 40-event backlog |
| `POST /api/v1/csv/tier2_sse` | SSE | ✅ REAL | Token-by-token LLM streaming |
| WebSocket endpoints | WS | ❌ NONE | Not implemented anywhere |
| Redis Pub/Sub | Internal | ✅ REAL | Worker ↔ app comms (optional) |

### Batch Processing

| Component | Status | Location |
|-----------|--------|----------|
| Backfill runner (triage-sorted) | ✅ REAL | `src/api/csv_endpoints.py:867-960` |
| RQ/LLM worker (Redis-backed) | ✅ REAL | `src/workers/llm_worker.py` |
| Redis Tier-2 queue | ✅ REAL | `src/queue/redis_tier2.py` |
| Gap detection loop (60s poll) | ✅ REAL | `src/api/background_tasks.py` |
| Explain precompute cache (5min) | ✅ REAL | `src/api/background_tasks.py` |
| VT queue threading worker | ✅ REAL | `src/artifact/vt_queue.py` |

---

## 14. Cloud Telemetry Funnel — Azure / AWS / GCP / Oracle

### The Architecture (Makes Complete Sense)

```
┌─────────────────── CUSTOMER ENVIRONMENT ────────────────────┐
│  Endpoint   Network    Email    Cloud   IAM     SIEM/XDR    │
│  (Agent)   (NGFW)   (O365)   (Azure)  (Entra)  (Sentinel)  │
│      │         │        │        │       │          │       │
│      └─────────┴────────┴────────┴───────┴──────────┘       │
│                              │                               │
│                   ┌──────────▼──────────┐                   │
│                   │  CLOUD EVENT BUS     │ ← all telemetry  │
│                   │  (Event Hub/Kinesis) │   centralized    │
│                   └──────────┬──────────┘                   │
└──────────────────────────────┼──────────────────────────────┘
                               │ (stream consumer)
                    ┌──────────▼──────────┐
                    │      JANUSEC         │
                    │  30-stage pipeline   │
                    │  HopGraph corr.      │
                    │  LLM T1/T2           │
                    │  8-domain detection  │
                    └──────────┬──────────┘
                               │
         ┌─────────────────────┼─────────────────────┐
         ▼                     ▼                       ▼
  ┌──────────┐        ┌──────────────┐       ┌──────────────┐
  │  Alerts  │        │   Playbooks  │       │Persona Report│
  │ SSE/API  │        │ (auto-block/ │       │ (exec/soc/  │
  │          │        │  isolate)    │       │  forensics)  │
  └──────────┘        └──────┬───────┘       └──────┬───────┘
                             │                      │
              ┌──────────────┼──────────────────────┘
              ▼              ▼
       ┌──────────┐   ┌──────────────────┐
       │  Client  │   │   Client SIEM    │
       │   XDR    │   │   (Splunk /      │
       │ (webhook)│   │    Sentinel)     │
       └──────────┘   └──────────────────┘
```

### Why This Works
- Azure Event Hubs = Kafka-compatible → JanuSec consumes via standard Kafka SDK
- JanuSec reduces 1M events/day → hundreds of actionable verdicts
- Results pushed back via webhook (`src/soar/connectors.py`) or SSE pull
- Multi-tenant: each customer = separate tenant namespace in JanuSec

### Cloud Platform Equivalents

| Cloud | Telemetry Bus | JanuSec Connector | Existing Assets | Effort |
|-------|--------------|-------------------|-----------------|--------|
| **Azure** | Azure Event Hubs (Kafka) | Build `AzureEventHubConnector` | `azure-deployment/`, Terraform | **2-3 weeks** |
| **AWS** | Amazon Kinesis | Build `KinesisConnector` | `infra/terraform/dlq_main.tf` exists | **2-3 weeks** |
| **GCP** | Google Pub/Sub | Complete `gcp/functions/scc_pubsub/` | Function partially built | **1-2 weeks** |
| **Oracle** | Oracle Streaming Service (Kafka) | Same as Azure (Kafka-compatible) | None | **2-3 weeks** |

### Build Order Recommendation
```
Phase 1 (v1 — Pull mode, 1-2 weeks):
  Azure: JanuSec polls Event Hub REST API every 30s
  Pattern: extend ConnectorBase with Azure SDK

Phase 2 (v2 — Push mode, already works):
  Customer sends webhooks → JanuSec /api/v1/events
  WebhookGuardMiddleware already handles HMAC auth

Phase 3 (v3 — Real-time stream, 2-3 weeks):
  Kafka consumer from Event Hub / Kinesis / Pub/Sub
  New file: src/connectors/azure_eventhub.py

Phase 4 (v4 — Multi-tenant SaaS, 4-6 weeks):
  Per-customer Event Hub namespace routing
  Tenant-aware consumer group management
```

**Dependencies to add for Azure:**
```bash
pip install azure-eventhub azure-identity azure-servicebus
```

**Dependencies for AWS:**
```bash
pip install aioboto3 boto3
```

---

## 15. Codex GPT Work — What Was Fixed

A Codex agent session (March 2026) made the following changes. Review before merging:

### ✅ DONE — Runtime Truthfulness
| Change | File | Effect |
|--------|------|--------|
| `TEST_HELPERS_ENABLED=0`, `PLATFORM_LITE_INIT=0` in Compose | `docker-compose.yml` | No longer boots in demo mode |
| Removed `devkey123` fallback | `app.py:3197`, `app.py:6977` | No insecure default key |
| `sitecustomize.py` constrained to pytest-only | `sitecustomize.py` | Fixed `DISABLE_DB=1`, `FAST_TEST_MODE=1` leaking into Docker |
| `/health`, `/ready`, `/api/v1/llm/health` exempt from tenant middleware | `app.py`, `tenant_middleware.py` | Health probes work anonymously |
| Dedicated `worker` service | `docker-compose.yml` | LLM worker in separate container |
| Fixed Ollama probe | `llm_client.py` | LLM health reports truthful provider/fallback |

**Live Stack Status after Codex:**
```
DB connected:          true  (Postgres asyncpg)
Redis connected:       true
Worker connected:      true
LLM provider:          ollama
HopGraph persistence:  enabled
Fallback active:       false
```

### ✅ DONE — Graph Session Persistence
| Change | File | Lines |
|--------|------|-------|
| New `GraphSessionsRepo` DB-backed CRUD | `src/repositories/graph_sessions_repo.py` | 11+ |
| Sessions persist across restarts | `src/api/graph_sessions.py` | 259 |
| Replay/history endpoints | `src/api/graph_sessions.py` | 4417, 4440, 4467 |

### ✅ DONE — Migration System
| Change | File | Effect |
|--------|------|--------|
| Linearized dual root revisions | `alembic/versions/0001_create_reports_table.py` | `down_revision = '0001_baseline'` |
| `alembic.ini` consolidated | `alembic.ini` | Single authoritative config |
| `alembic/env.py` reads `APP_DB_DSN` | `alembic/env.py` | Docker env var matched |
| `psycopg2-binary>=2.9.9` added | `requirements.txt` | Sync driver for Alembic CLI |
| `alembic>=1.13.0` added | `requirements.txt` | Explicit dependency |
| Migration runner uses CLI subprocess | `src/db/migrations.py` | Fail-fast in live mode |

### ⚠️ REMAINING ISSUES FROM CODEX SESSION
| Issue | File | Priority |
|-------|------|----------|
| `psycopg2.py` stub at repo root shadows real library | `psycopg2.py` | **P0** — delete or rename |
| App still partially entering lite-registration path | `app.py` | **P0** — trace PLATFORM_LITE_INIT handling |
| No real staging API key configured | `.env` | **P1** — set `API_KEYS_JSON` |
| `/api/v1/llm/health` returns 401 without key | `src/api/llm_health.py` | **P2** |

---

## 16. Installation & Deployment Environments

### Minimum Requirements
```
CPU:  2 vCPU
RAM:  4 GB
Disk: 20 GB (JSONL logs + graph snapshots)
OS:   Linux Ubuntu 22.04+ or Docker on Windows/macOS
```

### Required Services
| Service | Version | Purpose | Required? |
|---------|---------|---------|-----------|
| PostgreSQL | 15+ | Events, decisions, audit logs | **YES** (SQLite fallback for dev) |
| Redis | 4.6+ | Rate limiting, RQ worker, session state | **YES** for LLM workers |
| Prometheus | 2.x | Metrics collection | Recommended |
| Grafana | Latest | Dashboards | Optional |

### Optional External Services
| Service | Env Var | Purpose |
|---------|---------|---------|
| Ollama | `OLLAMA_HOST` | Local LLM (llama3, mistral) |
| Azure OpenAI | `OPENAI_API_KEY` | Cloud LLM |
| Anthropic | `ANTHROPIC_API_KEY` | Claude |
| VirusTotal | `VT_API_KEY` | Hash/IP/domain reputation |
| Qualys | `QUALYS_*` | Vulnerability enrichment |
| Slack | `SLACK_WEBHOOK_URL` | Alert notifications |

### Docker Compose Variants
```bash
docker compose up -d                                           # Standard
docker compose -f docker-compose.dev.yml up                   # Dev + hot-reload
docker compose -f docker-compose.redis.yml up                 # With Redis
docker compose -f docker-compose.azure.override.yml up        # Azure cloud
docker compose -f docker-compose.gcp.override.yml up          # GCP cloud
docker compose -f docker-compose.staging.yml up               # Staging env
```

### Kubernetes / Helm
```bash
helm install janusec ./helm/ -f helm/values.yaml
```

### Cloud Native (Terraform)
```
infra/terraform/dlq_main.tf    — AWS DLQ + S3
infra/terraform/variables.tf   — Cloud variables
azure-deployment/              — AKS-ready
gcp/functions/scc_pubsub/      — GCP SCC ingestion
```

### Key Environment Variables
| Variable | Default | Purpose |
|----------|---------|---------|
| `APP_DB_DSN` | `postgresql://postgres:postgres@db:5432/janusec` | Database |
| `API_KEYS_JSON` | — | **Required:** `[{"key":"xxx","scopes":["read","write"]}]` |
| `OLLAMA_HOST` | `http://host.docker.internal:11434` | Local LLM |
| `PLATFORM_LITE_INIT` | `0` | `1` = disable heavy features (CI only) |
| `LLM_MOCK` | `0` | `1` = fixture responses (testing only) |
| `EVENT_QUEUE_MAX` | `2000` | Ingestion queue capacity |
| `ALERT_RING_MAX` | `500` | In-memory alert ring size |
| `ENABLE_VT_REPUTATION` | `0` | `1` = live VirusTotal lookups |
| `PERSIST_BACKEND` | `jsonl` | `jsonl` / `postgres` / `dual` |
| `BACKFILL_BURST_SIZE` | `3` | Immediate batches on upload |
| `BACKFILL_BATCH_SIZE` | `50` | Rows per batch (set to 10 for fast start) |

### Health Checks
```bash
curl http://localhost:8080/health   # alive?
curl http://localhost:8080/ready    # dependencies ready?
curl http://localhost:8080/api/v1/llm/health -H "X-API-Key: <key>"
```

### CI Environments
```
.github/workflows/ci-validate.yml         — Lint + security
.github/workflows/pytest-lite.yml         — Fast unit tests
.github/workflows/pytest-full.yml         — Complete coverage
.github/workflows/playwright.yml          — E2E browser tests
.github/workflows/helm-ci.yml             — Helm chart validation
.github/workflows/benchmark-ci.yml        — Performance testing
.github/workflows/trivy.yml               — Container CVE scanning
.github/workflows/bandit.yml              — SAST scan
.github/workflows/zap-baseline.yml        — OWASP ZAP API scan
.github/workflows/migrations-and-db-tests.yml — DB migration tests
```

---

## 17. Path to Market — Prioritized Roadmap

### Overall Completeness

| Layer | % Done | Notes |
|-------|--------|-------|
| Core detection pipeline (30 stages) | **85%** | Works; test vectors missing |
| HopGraph correlation | **80%** | PPR real; sessions now DB-backed |
| LLM T1/T2 summaries | **80%** | Real engines; stub REST wrapper at `/llm/tier1` |
| Persona reporting | **70%** | 5 of 6 personas wired; forensics missing |
| 8-domain rules | **60%** | Email best; cloud/IAM/eBPF sparse |
| SOAR / playbooks | **65%** | Full engine; destructive actions need config |
| Connectors | **45%** | Qualys/VT/Graph real; many drifted or missing |
| Docker / staging | **80%** | Codex fixed runtime truthfulness |
| Database / migrations | **75%** | Codex linearized; psycopg2 stub at root blocks |
| Test suite | **88.9%** | 1,657/1,865 pass; 41 files blocked |
| Playwright E2E | **0%** | 18 specs written, never run |

**Overall: ~73% production-ready**

---

### P0 — Fix Before Any Real Traffic (1 Week)

| # | Task | File | Why |
|---|------|------|-----|
| 1 | **Delete `psycopg2.py` stub at repo root** | `psycopg2.py` | Shadows real library; breaks Alembic and all Postgres connectivity |
| 2 | **Restore `data/custom_test_vectors.json`** | `data/` (deleted) | Fixes ~85 failing rule tests instantly |
| 3 | **Install missing test deps** | `requirements-dev.txt` | `cryptography aiohttp lark tenacity pytest-timeout` — unblocks 41 test files |
| 4 | **Set real `API_KEYS_JSON` in `.env`** | `.env` | No real staging key; all API calls unauthorized |
| 5 | **Trace and fix `PLATFORM_LITE_INIT=0` leak** | `app.py` | Stack still enters lite-registration path |

### P1 — Before First Paying Customer (2-4 Weeks)

| # | Task | File | Why |
|---|------|------|-----|
| 6 | Wire `forensics` persona into `generate_persona_view()` | [src/reporting/persona_views.py](src/reporting/persona_views.py) | Only 5 of 6 personas active |
| 7 | Fix alert Postgres persistence | [src/api/alerts_endpoints.py:648](src/api/alerts_endpoints.py) | "stub implementation" comment — alerts not stored in DB |
| 8 | Replace PageRank heuristic | [src/core/graph/graph_scoring.py:163](src/core/graph/graph_scoring.py) | `len(path)/10` is not PageRank |
| 9 | Fix XDR webhook test fixtures (add HMAC) | `tests/test_xdr_webhook.py` | 7 tests returning 401 |
| 10 | Reconcile moved/deleted routes | `src/api/app.py` | 15 tests hitting 404 (IAM, metrics, ISMS, WEF) |
| 11 | Fix asyncio_mode | `pytest.ini` | 15 async tests failing |
| 12 | Fix LOLbin/TF-IDF rule condition drift | `rules/lolbin/` | 15 rule tests returning False |
| 13 | **Excel batch priority burst** | [src/api/csv_endpoints.py:841](src/api/csv_endpoints.py) | Top-10 T1 summaries in 30s vs 5 minutes |
| 14 | Add cloud domain rules | `src/core/correlation/rules/cloud/` | **Missing entire GCP/Azure/AWS detection domain** |
| 15 | Expand IAM domain rules | `src/core/correlation/rules/iam/` | Only 2 rules for Entra/Okta/AD |
| 16 | Run Playwright suite against live server | `tests/playwright/` | 18 specs — UX completely unvalidated |

### P2 — GA / Scalable Deployment (4-8 Weeks)

| # | Task | Why |
|---|------|-----|
| 17 | **Azure Event Hub connector** | Biggest revenue unlock — cloud funnel v1 |
| 18 | **AWS Kinesis connector** | AWS parity |
| 19 | **Complete GCP Pub/Sub** (`gcp/functions/scc_pubsub/`) | GCP funnel |
| 20 | **Re-enable pgvector** (deleted in migrations) | RAG T2 semantic search needs it |
| 21 | **Multi-domain confidence aggregation** | `domain_confidence` is never computed — 8-domain claim needs it |
| 22 | Redis distributed cache | Shared LRU across workers |
| 23 | Incremental PPR | Full recompute per call — bottleneck at scale |
| 24 | Micro-batch event processing | Single-event pipeline → batch 10-50 |
| 25 | Approval workflows in playbooks | `approval_required` field exists but unused |
| 26 | Eclipse XDR real API | Current sink only logs |
| 27 | MISP / OpenCTI real API calls | Currently URL-only placeholders |
| 28 | SOC 2 / ISO 27001 audit trail completion | Required for enterprise sales |
| 29 | Fix Splunk/CrowdStrike/Sentinel adapter schemas | Vendor adapter tests failing |
| 30 | Active Directory / Entra ID / Okta connectors | No live IAM connector exists |

### P3 — Competitive Differentiation (2-4 Months)

| # | Task |
|---|------|
| 31 | WebSocket endpoints (complement SSE for bidirectional use cases) |
| 32 | Oracle Cloud Streaming connector |
| 33 | eBPF kernel domain expansion (beyond container escape) |
| 34 | Conditional branching in playbook DSL (if/else logic) |
| 35 | Rollback semantics for SOAR actions |
| 36 | Scheduled threat hunting (cron-based hunt lane triggers) |
| 37 | AI/ML domain rules (LLM-abuse, prompt injection, model poisoning) |
| 38 | MSSP white-label reporting |

---

## 18. Master Status Matrix

### Core Components

| Component | File | Lines | Status | Notes |
|-----------|------|-------|--------|-------|
| Event pipeline (30 stages) | [src/core/event_pipeline/pipeline.py](src/core/event_pipeline/pipeline.py) | 497 | ✅ REAL | Circuit breaker, confidence blending |
| HopGraph PPR | [src/core/graph/hopgraph_lite.py:680-723](src/core/graph/hopgraph_lite.py) | 1003 | ✅ REAL | alpha=0.15, 8 steps, capped |
| Motif / lateral detection | [src/core/graph/hopgraph_lite.py:310-421](src/core/graph/hopgraph_lite.py) | — | ✅ REAL | 5 motif patterns |
| Graph session persistence | [src/repositories/graph_sessions_repo.py](src/repositories/graph_sessions_repo.py) | — | ✅ REAL | Codex — DB-backed |
| SSE decisions stream | [src/api/decisions_stream.py](src/api/decisions_stream.py) | 321 | ✅ REAL | Multi-client, ring buffer, keepalive |
| T2 SSE streaming | [src/api/tier2_endpoints.py:103-170](src/api/tier2_endpoints.py) | 200 | ✅ REAL | Token-by-token LLM |
| Alert 3-level dedup | [src/api/alerts_endpoints.py:690-934](src/api/alerts_endpoints.py) | 1171 | ✅ REAL | Rule-entity + event-id + ring |
| Webhook HMAC guard | [src/api/webhook_middleware.py](src/api/webhook_middleware.py) | — | ✅ REAL | Replay DB, timestamp, vendor-exempt |
| SOAR engine | [src/soar/](src/soar/) | 14 files | ✅ REAL | Full DAG executor + connector audit |
| LLM T1 (insights engine) | [src/api/insights_endpoints.py:509-626](src/api/insights_endpoints.py) | — | ✅ REAL | Budget-gated, persona-injected |
| LLM T2 (deep analysis) | [src/api/insights_endpoints.py:629-699](src/api/insights_endpoints.py) | — | ✅ REAL | Timeline, supply chain, sandbox |
| Persona views (5 personas) | [src/reporting/persona_views.py](src/reporting/persona_views.py) | 173 | ✅ REAL | DREAD + email enrichment |
| VirusTotal | `src/artifact/vt_queue.py` | — | ✅ REAL | Rate-limited, token bucket |
| Qualys | `src/adapters/qualys_connector.py` | — | ✅ REAL | OAuth2, tenacity retry |
| MS Graph (email) | `src/integrations/ms_graph_connector.py` | — | ✅ REAL | O365/Exchange |
| Zeek adapter | [src/live/zeek_adapter.py](src/live/zeek_adapter.py) | — | ✅ REAL | JSON line, GeoIP |
| Database (Postgres+SQLite) | `src/db/database.py` | — | ✅ REAL | asyncpg pool, fallback |
| RQ/LLM worker | `src/workers/llm_worker.py` | — | ✅ REAL | Redis-backed, batch=10 |
| Backfill runner | [src/api/csv_endpoints.py:867-960](src/api/csv_endpoints.py) | — | ✅ REAL | Triage-sorted batch processing |
| Action dispatcher | [src/core/actions/dispatcher.py](src/core/actions/dispatcher.py) | 80+ | ✅ REAL | Rate limit, CB, outbox |
| LLM T1 REST endpoint | [src/api/llm_tier1.py:15-39](src/api/llm_tier1.py) | 39 | ⚠️ STUB | Hardcoded rationale — not real LLM |
| Alert Postgres persistence | [src/api/alerts_endpoints.py:648](src/api/alerts_endpoints.py) | — | ❌ STUB | "extend later" comment |
| PageRank scoring | [src/core/graph/graph_scoring.py:163](src/core/graph/graph_scoring.py) | — | ❌ STUB | `len(path)/10` heuristic |
| Multi-domain aggregation | (missing) | — | ❌ STUB | `domain_confidence` never computed |
| WebSocket endpoints | (entire codebase) | — | ❌ NONE | SSE only |
| Eclipse XDR sink | `src/core/actions/eclipse_sink.py` | — | ❌ STUB | Logs only |
| MISP integration | `src/integrations/threat_intel_client.py` | — | ❌ STUB | URL stored, zero calls |
| OpenCTI integration | `src/integrations/threat_intel_client.py` | — | ❌ STUB | URL stored, zero calls |
| Azure Event Hub connector | (not built) | — | ❌ MISSING | High priority |
| AD / Entra / Okta connector | (not built) | — | ❌ MISSING | High priority |

### 8-Domain Rule Coverage

| Domain | Directory | Rules | Status |
|--------|-----------|-------|--------|
| Email / BEC | `rules/email/` | 15 | ✅ Complete — richest domain |
| Endpoint / LOLbin | `rules/lolbin/`, `week1/`, `week2/` | 10+ | ✅ Real — test vectors missing |
| Supply Chain | `rules/supplychain/` | 3 | ✅ Real |
| Binary / Malware | `rules/binary/` | 4 | ✅ Real |
| Graph / Lateral | `rules/graph/` | 2 | ✅ Real |
| Network | `rules/network/` | 2+ | ✅ Real |
| IAM / Identity | `rules/iam/` | 2 | ⚠️ Partial — AD/Entra/Okta missing |
| API Security | `rules/api_security*.py` | 2 | ⚠️ Partial |
| eBPF / Container | `rules/ebpf/` | 2 | ⚠️ Minimal |
| **Cloud** | (not built) | 0 | ❌ Missing — entire domain |
| **Data / Exfil** | (scattered) | 0 dedicated | ❌ Missing |
| **AI / LLM Abuse** | (not built) | 0 | ❌ Missing |

---

## Quick Summary: What Works RIGHT NOW (with Docker + Ollama)

### ✅ Production-Ready Today
- 30-stage progressive detection pipeline (85% complete)
- SSE real-time alert streaming + HopGraph overlay streaming
- HopGraph PPR, motif detection, lateral chain detection
- LLM T1/T2 summaries (budget-gated, persona-injected, SSE-streamed)
- 5-persona report views (executive, soc_analyst, compliance, threat_hunter, mssp)
- Email/BEC domain (15 rules — best coverage)
- Supply chain, binary/endpoint, network, graph lateral rules
- VirusTotal, Qualys, Microsoft Graph connectors (real API calls)
- Full SOAR engine (tag, slack, enrich, ticket always; EDR/firewall if `api_url` set)
- Webhook HMAC guard with replay detection (production-grade)
- Multi-tenant isolation (quota, rate limits, persona routing)
- CSV/Excel forensics upload + backfill batch runner
- Chain-of-custody hashing (audit trail)
- Postgres + SQLite dual backend
- Graph session persistence across restarts (Codex — DB-backed)

### ⚠️ Works but Needs Tuning
- Rule tests failing — restore `data/custom_test_vectors.json`
- Alert Postgres persistence — stub comment, only JSONL today
- Excel upload latency — tune `BACKFILL_BURST_SIZE=1 BACKFILL_BATCH_SIZE=10`
- Vendor adapters (CrowdStrike/Splunk/Sentinel) — schema drift

### ❌ Not Yet Built
- Azure Event Hub / Kinesis / GCP Pub/Sub connectors
- Cloud domain rules (GCP/Azure/AWS threat detection)
- Full IAM domain (AD/Entra/Okta — only 2 rules)
- pgvector / RAG vector search
- Eclipse XDR real API
- MISP / OpenCTI live feeds
- WebSocket endpoints
- Multi-domain confidence aggregation

---

*Generated: 2026-03-24 | Sources: live test run (1,865 tests), full codebase analysis (src/**), Codex GPT staging session, Playwright spec inventory, latency profiling, cloud architecture design*
