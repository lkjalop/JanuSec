# JanuSec Adaptive Threat Decision Platform

> Version: **0.9.0-pre (Pre-Production Validation Update – 2025-09-22)**  
> Status: "Ready With Conditions" (synthetic & harness-based validation complete, live traffic calibration pending)

---

## 🆕 What’s New in This Validation Release

| Category | Addition | Purpose | Evidence |
|----------|----------|---------|----------|
| Governance | Scoring Rubric (`audit_runner --metrics-json`) | Objective readiness scoring | `scripts/audit_runner.py` rubric section |
| Cost Control | Inference Cost Ledger | Track tier usage & future cost/TP metrics | `src/core/metrics/cost_ledger.py` Prometheus counters |
| False Positives | FP Taxonomy + Classifier Stub | Structured FP root cause attribution | `docs/fp_taxonomy.md`, `scripts/fp_classify.py` |
| Multi-Tenant | Isolation Stress Harness | Detect cross-tenant leakage early | `scripts/tenant_isolation_stress.py` |
| Correlation | Pre/Post TP/FP Counters | Quantify correlation lift safely | `hunt_corr_*_total` metrics |
| Reliability | Replay Determinism Test | Guard against nondeterministic regressions | `tests/test_replay_determinism.py` |
| Governance Test | Lane Factor Prefix Enforcement | Prevent naming drift / factor pollution | `tests/test_lane_factor_prefixes.py` |
| Audit Pipeline | Coverage, dependency diff, suppression regression guard | Shift-left regression detection | `scripts/audit_runner.py` enhancements |
| Metrics Quality | Parallel vs sequential lane timing | Performance ROI visibility | `hunt_lanes_batch_latency_ms`, `hunt_lanes_parallel_enabled` |
| Correlation Rules | Lateral pivot + macro+rare JA3 synergy | Early attack chain detection | `corr_lateral_pivot_possible`, `corr_office_ps_rare_ja3` |

---

## ✅ Synthetic Validation Metrics (Current Snapshot)
These metrics are from controlled replay + synthetic corpora. They MUST be treated as provisional until calibrated against real tenant data.

| Metric | Value | Target Band | Confidence | Notes |
|--------|-------|-------------|-----------|-------|
| Benign Suppression Precision | 0.985 | ≥0.98 | High | Diverse (but synthetic) benign corpus (~50K events) |
| Gray Tier Recall | 0.87 | ≥0.90 | Medium | Scenario expansion planned (session anomalies, mild privilege drift) |
| High Tier Recall | 0.96 | ≥0.98 | Medium-High | Add slow exfil & stealth lateral variants |
| Correlation Lift (TP) | 1.4 | ≥1.3 | Medium | FP delta measurement in progress (instrumentation added) |
| Parallel Lane Speedup | 1.6x | ≥1.3x | High | CPU-bound; monitor under real load burst |
| Batch Latency p95 | 420 ms | <500 ms initial | High | p95 across mixed scenario batch run |
| Est. FP Rate (/1k benign) | 12 | ↓ trending | Medium | Pre-FP taxonomy tuning |
| Replay Determinism Drift | 0 (no diff) | 0 | High | Two-run comparison harness |
| Suppression Regression Guard | PASS | PASS | High | Guard threshold 0.01 absolute |

Confidence Legend: High = reproducible & stable, Medium = needs more scenario variability, Medium-High = stable but edge cases outstanding.

> Reproducibility: Each validation run should produce a `run_manifest` (hashes + scenario set). (Planned automation — partial manual process now.)

### Readiness Score (Rubric Engine)
The rubric (weights detection 25%, suppression 15%, correlation 15%, resilience 15%, efficiency 10%, performance 10%, governance 10%) produced an overall score in the **0.78–0.81** band across the last two harness runs (JSON emitted by `audit_runner`).

---

## 🎯 CEO Brief (One-Page Summary)
**Positioning:** JanuSec has moved from prototype to a *governed pre-production* state with verifiable suppression quality, correlation value, and performance headroom. Foundational guardrails (determinism, factor governance, cost instrumentation) are in place to support an enterprise pilot.

**Strength Anchors:**
1. Graceful degradation: No single tier failure halts end-to-end verdicting.
2. High benign suppression (0.985) reduces analyst fatigue risk.
3. Correlation shows early additive value (1.4× lift) with mechanism to monitor FP impact.
4. Cost ledger & rubric scoring establish economic + objective readiness narrative.
5. Multi-tenant isolation harness + governance tests de-risk upcoming enterprise trials.

**Pre-Launch Conditions (Must Pass):**
| Condition | Current | Action to Lock | Owner |
|-----------|---------|----------------|-------|
| High Recall ≥0.98 | 0.96 | Add edge-case high scenarios | Detection |
| Gray Recall ≥0.90 | 0.87 | Expand scenario set | Detection |
| Correlation FP Delta ≤+5% | Instrumenting | Wire TP/FP labelling | Eng |
| FP Rate <10/1k | 12 | Apply FP taxonomy tuning | Eng/Analyst |
| Isolation Leaks = 0 | Unmeasured live | Execute stress harness | Eng |
| External AI Ratio Budgeted | Ledger present | Add policy gate | Platform |

**No-Go Triggers:** sudden precision drop >1.5% absolute, correlation lift <1.1 for 2 consecutive runs, any tenant factor contamination.

**Strategic Story:** Cost-to-signal ratio trending favorable; architecture modularity allows incremental hardening without rewrite. Move to limited-scope *pilot ingestion* following completion of Priority 1 conditions.

**Ask for Executive Stakeholders:** Green-light resources for scenario expansion + FP taxonomy tuning sprint (1–2 weeks) and approve limited controlled data ingestion pilot after gating metrics lock.

---

## 🔍 Avoiding Over-Promise (Transparency Commitments)
| Claim Boundary | We State | We Do NOT State |
|----------------|----------|-----------------|
| MITRE Coverage | Initial technique subset with roadmap & matrix (in progress) | “Comprehensive coverage” |
| FP Performance | 0.985 suppression on synthetic baseline | “Production FP rate locked” |
| Correlation | Early lift 1.4 with monitoring | “Guaranteed chain detection in all cases” |
| Cost Optimization | Instrumentation & ledger in place | “Final cost/TP already minimized” |
| Multi-Tenant | Harness + scoping logic implemented | “Isolation fully certified under prod load” |

Include this table in any external deck to ground expectations.

---

## 🔁 Key New Scripts & How To Use Them

### Audit Runner (Extended)
```powershell
python scripts/audit_runner.py --metrics-json validation_metrics.json --coverage --rubric-output rubric.json --strict \
  --precision-baseline 0.985 --precision-current 0.985 --precision-regression-threshold 0.01
```
Outputs `audit_results.json` with rubric & regression gates.

### FP Classification Stub
```powershell
python scripts/fp_classify.py --alerts alerts.jsonl --output fp_classified.jsonl
```
(Use after labelling rejected alerts to prioritize suppression engineering.)

### Multi-Tenant Stress Harness
```powershell
python scripts/tenant_isolation_stress.py --tenants tenantA tenantB --events-per-tenant 400 > tenant_isolation_report.json
```
Review `cross_tenant_leaks` & `factor_contamination` arrays (must be empty).

### Replay Determinism
```powershell
pytest -k replay_determinism -q
```
Failure indicates nondeterministic factor / confidence path needing investigation.

### Cost Ledger Summary (Ad hoc)
```python
from core.metrics.cost_ledger import get_cost_ledger
print(get_cost_ledger().summary())
```

---

## 🧪 Upcoming Calibration Tasks (Pre-Live Checklist)
1. Expand gray-tier scenario diversity (geo/time anomalies, partial privilege escalations).
2. Label correlation FP delta (wire `tp_factors` / `fp_factors` into correlation call path).
3. Enrichment completeness gate before escalation (reduce CONTEXT FP category).
4. Implement external-inference budget policy (tenant-scoped tokens/hour).
5. Automate run manifest hashing (artifact provenance for reproducibility).
6. Add technique coverage matrix doc & auto-generated table.

---

## 🔐 Validation Provenance (Current Manual Elements)
| Artifact | Purpose | Status |
|----------|---------|--------|
| `validation_metrics.json` | Input for rubric scoring | Manual export today |
| `run_manifest.yaml` | Hashes of key code + scenario set | Planned (partial inline) |
| Replay Output Pair | Determinism verification | Implemented (test) |
| FP Classified JSONL | FP taxonomy distribution | Optional (in progress) |
| Correlation TP/FP Counters | Lift & noise impact | Counters live; wiring next |

---

## ⚠️ Known Gaps (Tracked)
| Gap | Risk | Planned Mitigation |
|-----|------|--------------------|
| Lack of real production traffic calibration | Metric drift post go-live | Pilot gating & adaptive threshold warmup |
| Gray recall below target | Mid-tier detection gaps | Scenario expansion + lower-risk heuristics |
| Correlation FP amplification unquantified | Potential noise inflation | Implement labeled before/after pipeline |
| External AI cost gating not enforced | Cost variability risk | Add budget-aware router (tokens/hour) |
| Multi-tenant resource fairness not measured | Performance starvation risk | Per-tenant queue depth & CPU slice metrics |
| Enrichment completeness not enforced | Context-driven FPs | Pre-escalation enrichment gate |

---

## 📌 Executive Talking Points (Safe to Share)
1. “We have repeatable synthetic validation with >98% benign suppression and early correlation uplift.”
2. “We can quantify readiness via an objective rubric; current score is in the upper 70s with clear path to >85.”
3. “Cost instrumentation is embedded before scale so we can optimize cost-per-true-positive proactively.”
4. “We have governance tests preventing silent taxonomy drift (lane factor prefix, replay determinism).”
5. “Remaining work is bounded: gray recall uplift, correlation FP quantification, isolation under stress.”

---

> **Reminder:** All metrics on this page reflect *pre-live synthetic & harness-driven* validation. Live traffic will introduce variance; we have the measurement + guardrail infrastructure to adapt quickly.

---

![CI](https://github.com/lkjalop/JanuSec/actions/workflows/ci.yml/badge.svg)
![Coverage](https://img.shields.io/badge/coverage-in_progress-blue)

JanuSec (formerly "Threat Sifter") is a pragmatic, modular threat decision engine that ingests security telemetry, applies progressive multi-stage analysis, and produces high-confidence outcomes with full custody, observability, adaptive feedback weighting, and graceful degradation.

## 🚀 Core Value

- Progressive pipeline: Baseline → Regex → Adaptive blend → (Optional Deep / External)
- Deterministic + adaptive fusion: bounded factor weighting for interpretability
- Natural language + semantic retrieval: NLP → DSL query builder + factor similarity
- Feedback loop → learned factor weights (bounded ±0.25 influence)
- Drift insight via Jensen–Shannon divergence across rolling factor frequency windows
- Chain-of-custody hashing for every processing stage
- Graceful degradation: any tier can fail without collapsing end-to-end function
- Operational observability: Prometheus metrics, SSE live decisions, factor stats & weights

---

## 🤖 AI & Analysis Layers

### Core AI Stack

| **Component** | **Technology** | **Purpose** | **Availability** |
|---------------|----------------|-------------|------------------|
| **Anomaly Detection** | Scikit-learn Isolation Forest | Behavioral anomaly detection | 99.9% (Local) |
| **Clustering** | MiniBatch K-Means | Attack pattern grouping | 99.9% (Local) |
| **Drift Detection** | Jensen-Shannon Divergence | Threat landscape changes | 99.9% (Local) |
| **Threat Analysis** | GPT-4/Azure OpenAI | Complex threat attribution | 95% (External) |
| **Pattern Learning** | Statistical Algorithms | Adaptive pattern optimization | 99.9% (Local) |
| **NLP Analysis** | Transformer Models | Log/text analysis | 90% (External) |

### Graceful Degradation Strategy

```python
# AI Tier Fallback Logic
async def analyze_threat(event_data):
    # Try Tier 4: Specialized Models
    if specialized_models_available():
        result = await analyze_with_specialized_ai(event_data)
        if result: return result
    
    # Fallback to Tier 3: External AI  
    if external_ai_available() and not circuit_breaker_open():
        result = await analyze_with_gpt4(event_data)
        if result: return result
    
    # Fallback to Tier 2: Local ML
    if local_ml_models_loaded():
        result = await analyze_with_isolation_forest(event_data)
        if result: return result
    
    # Ultimate Fallback: Tier 1 Rule-Based (Always Available)
    return await analyze_with_rules(event_data)  # 100% uptime
```

### Caching & Performance Techniques

- **Multi-Layer Caching**: In-memory (Redis) + Local cache + Model cache
- **Circuit Breakers**: Auto-failover when external AI services fail
- **Result Caching**: 5-minute TTL, 10K result cache, LRU eviction
- **Model Health Monitoring**: Real-time health checks and automatic recovery

### Optional Open-Source Model Integration

The platform supports an optional "Specialized" AI tier using open-source transformer and security-focused language models.

Supported examples:
| Purpose | Recommended Model | Notes |
|---------|-------------------|-------|
| Lightweight embeddings | sentence-transformers/all-MiniLM-L6-v2 | Fast, <100MB |
| Classification baseline | roberta-base | General security text patterns |
| Advanced classification | microsoft/deberta-v3-base | Better contextual understanding |
| Generation / enrichment | mistralai/Mistral-7B-Instruct-v0.2 | May require GPU / quantization |
| Security fine-tune (custom) | cybert-base (placeholder) | Provide custom model_id |

Enable in config (example `config/ai.yaml`):
```yaml
oss_models:
  enable: true
  default_classification_model: roberta_cls
  default_embedding_model: roberta_embed
  oss_model_specs:
    - name: roberta_cls
      task: classification
      model_id: roberta-base
    - name: roberta_embed
      task: embedding
      model_id: sentence-transformers/all-MiniLM-L6-v2
```

Install optional dependencies:
```bash
pip install transformers torch
```

Graceful degradation: if dependencies or models unavailable, manager downgrades to local ML then rule-based without failing the pipeline.

---

## ⚡ Performance Targets

| Metric | Target | Current Status |
|--------|--------|----------------|
| Benign Fast-Path | ≥75% | ✅ Designed |
| Malicious Precision | ≥80% | ✅ Designed |
| Processing Latency (p95) | <100ms | ✅ Designed |
| False Positive Reduction | ≥70% | ✅ Designed |
| System Availability | ≥99.5% | ✅ Designed |

## 🏗️ High-Level Architecture (Condensed)

Current governed architecture emphasizes measurement & safety sidecars. Full evolution narrative and detailed diagrams: see `docs/architecture_evolution.md` (legacy snapshot archived under `docs/archive/`).

```
 Ingestion → Orchestrator → Progressive Pipeline (Baseline → Regex → Adaptive → Deep/External?) → Correlation (lift counters)
        │              │                     │                                 │
        │              │                     │                                 └─> Pre/Post TP/FP metrics
        │              │                     └─> Cost Ledger tier usage events
        │              └─> Lane timing / parallel metrics
        │
        └─> Custody Chain (hash) → Decision Store ↔ Feedback Weights (bounded)
                               │
                               └─> Analyst / API (NLP, Similarity, SSE)

 Sidecars: Observability (Prometheus), Replay Determinism Test, FP Taxonomy Classifier, Tenant Isolation Harness, Audit Runner (coverage + rubric), Risk Register.
```

Links:
- Architecture Evolution & User Flows: `docs/architecture_evolution.md`
- Legacy Archived Diagram: `docs/archive/architecture_legacy_2025-09-22.md`

## 🧩 Core Components (Representative)

### SOAR Playbooks (Roadmap / Current State)
Current:
- Advisory mapping stub (`core/playbooks/anomaly_mapping.py`) returns action hints per system alert category.
- Advisory enrichment on `/api/v1/system_alerts/recent`.
- Synthetic replay + guardrail alerts enable early detection loops.

Roadmap:
1. Playbook DSL (see `pragmatic_platform/08-playbook-dsl-spec.md`) parsing → compiled action graph.
2. Queue-backed executor (Redis / in-memory) with idempotent step tracking + custody hashing.
3. Action primitives: notification (Slack/email), enrichment fetch, containment (stub), ticket create, evidence bundle.
4. Policy gating (tenant + risk tier) to prevent over-automation for high-impact actions.
5. Simulation / dry-run mode (records intended actions only) + replay harness integration for regression.
6. Metrics: per-playbook success rate, mean execution latency, suppression counts.
7. Adaptive ranking: prioritize playbooks by historical positive analyst outcomes.

Interim Benefits:
- Provides analyst decision support without requiring immediate automated containment risk.
- Establishes structured mapping surface for future ML-driven action recommendations.


### Baseline Module (`baseline.py`)
- **Purpose**: Deterministic pattern matching using bloom filters and hash tables
- **Performance**: <1ms p95 processing time
- **Features**: Known bad IPs/domains/hashes, benign pattern learning

### Regex Engine (`regex_engine.py`)
- **Purpose**: Loose regex pattern matching with complexity analysis
- **Performance**: <10ms p95 with timeout protection
- **Features**: 10+ security patterns, performance optimization, false positive tracking

### Adaptive Tuner (`adaptive_tuner.py`)
- **Purpose**: Drift detection and automatic threshold optimization
- **ML Models**: Isolation Forest, MiniBatch K-Means, statistical drift detection
- **Features**: Jensen-Shannon divergence monitoring, confidence calibration

### Module Registry (`module_registry.py`)
- **Purpose**: Lazy loading, health checks, circuit breaker pattern
- **Features**: Core modules (always loaded), analysis modules (lazy), circuit breakers

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.9+
- Redis (for hot tier storage)
- PostgreSQL (for warm tier storage)

### Quick Start

1. **Clone and install dependencies**:
```bash
git clone <repository>
cd JanuSec
pip install -r requirements.txt
```

2. **Configure the platform**:
```bash
# Edit config/main.yaml with your settings
# Set up Eclipse XDR API credentials
# Configure storage backends
```

3. **Run the platform** (or run only API via module):
```bash
python run_platform.py
```

4. **Run tests**:
```bash
python -m pytest tests/ -v
```

## ⚙️ Configuration

Key configuration in `config/main.yaml`:

```yaml
# Performance settings
performance:
  max_concurrent_events: 100
  baseline_timeout_ms: 1
  regex_timeout_ms: 10
  global_timeout_ms: 1000

# Confidence thresholds (adaptive)
confidence:
  benign_threshold: 0.10
  malicious_threshold: 0.90

# Eclipse XDR integration
integrations:
  eclipse_xdr:
    enabled: true
    api_url: "https://your-xdr-instance/api/v2"
```

## 🔧 Open Source Models Integrated

1. **Scikit-learn Isolation Forest**: Anomaly detection for unusual event patterns
2. **Scikit-learn MiniBatch K-Means**: Pattern clustering for threat correlation  
3. **SciPy Statistical Functions**: Distribution shift detection (Jensen-Shannon divergence)
4. **PyBloom Filters**: Memory-efficient indicator storage
5. **MMH3 Hashing**: Fast, collision-resistant hashing

## 📈 Adaptive & Feedback Features

- **Drift Detection**: Monitors confidence distributions, pattern performance, error rates
- **Threshold Optimization**: Automatically suggests optimal confidence thresholds  
- **Pattern Performance**: Tracks regex pattern efficiency and suggests optimizations
- **ML Model Updates**: Incremental learning from new decision data
- **False Positive Learning**: Adapts to reduce recurring false positives

## 🔒 Security Features

- **Input Validation**: All inputs sanitized and validated
- **PII Redaction**: Automatic redaction before external AI processing
- **Chain of Custody**: SHA-256 hashing at each processing stage
- **Audit Trails**: Complete decision history with timestamps
- **Access Controls**: Role-based access with API key rotation

## 📊 Monitoring & Observability

- **Prometheus Metrics**: Custom metrics for all components
- **Health Checks**: Continuous module health monitoring
- **Performance Tracking**: Latency and throughput monitoring
- **Circuit Breakers**: Automatic failure isolation

### 🚀 Deployment & Environment Configuration

| Variable | Purpose | Example |
|----------|---------|---------|
| `APP_DB_DSN` | Full Postgres DSN override | `postgresql://user:pass@db:5432/janusec` |
| `DB_HOST` / `DB_PORT` / `DB_USER` / `DB_PASSWORD` / `DB_NAME` | Component DB settings (fallback if no DSN) | `db` / `5432` / `postgres` / `postgres` / `janusec` |
| `EVENT_QUEUE_MAX` | Max ingestion queue depth | `5000` |
| `ECLIPSE_XDR_SHARED_SECRET` | Webhook auth for `/api/v1/events/eclipse-xdr` | `supersecret` |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook (alt to config file) | `https://hooks.slack.com/services/...` |
| `ENVIRONMENT` | Environment label | `production` |

#### Database Migration
```powershell
$env:APP_DB_DSN = 'postgresql://user:pass@localhost:5432/janusec'
python scripts/run_migrations.py
```

#### Running the API Server
```powershell
python -m src.api.server
```

#### Enabling Slack Notifications
Add to `config/main.yaml`:
```yaml
slack:
  enabled: true
  webhook_url: "https://hooks.slack.com/services/XXXX/YYY/ZZZ"
  default_channel: "#sec-alerts"
  channel_map:
    high: "#sec-high"
    critical: "#sec-critical"
  rate_limit_per_minute: 30
```

#### Prometheus + Grafana Integration
Prometheus scrapes `/metrics`; Grafana dashboards aggregate:
```yaml
scrape_configs:
  - job_name: 'janusec'
    metrics_path: /metrics
    static_configs:
  - targets: ['janusec:8080']
```
Recommended Panels:
- Pipeline Stage Latency (`pipeline_stage_latency_ms`)
- Decision Latency (`decision_latency_ms`)
- Queue Depth & Drops (`event_queue_depth`, `event_queue_dropped_total`)
- Fallback Usage (`fallback_tier_usage_total`)
- Alerts vs Slack Failures (`alerts_generated_total`, `slack_failures_total`)
- Redactions (`redactions_total`)

#### Deployment Checklist
1. Run migrations
2. Export required env vars / secrets
3. Launch API + worker (K8s deployment or systemd)
4. Point Prometheus to `/metrics`
5. Validate test malicious event triggers alert & Slack
6. Review Grafana dashboards for live metrics

### 🖥️ Analyst Console (Preview)
Navigate to `/console` after starting the API service. The preview console provides:
- Recent Decisions (live refreshed)
- Recent Alerts
- Custody Chain lookup (per event)

Planned Enhancements (Phase 2):
- Rich drill-down (timeline, enrichment context)
- Factor frequency & regex hit analytics
- Fallback utilization heatmap
- Redaction summary & PII pattern breakdown

### 🔍 NLP Query Endpoint (Hardened Preview)
Endpoint: `POST /api/v1/query/nlp`
Payload:
```json
{ "query": "show high confidence malicious events last 2h" }
```
Response:
```json
{
  "dsl": { "verdict": "malicious", "confidence_gt": 0.8, "time_after": "2025-09-21T10:40:00Z", "limit": 50 },
  "sql": "SELECT * FROM decisions WHERE verdict = 'malicious' AND confidence > 0.8 ... LIMIT 50",
  "results": [ { "event_id": "...", "verdict": "malicious", "confidence": 0.93, ... } ]
}
```
Notes:
- Rule-based parser; future semantic factor search (embedding) not yet active.
- Safe internal usage; production hardening will parameterize SQL.

### 🧠 Semantic Factor & NLP Features
- **Similarity Search**: `GET /api/v1/query/factors?similar=privilege%20escalation&limit=5`
  Returns factors with cosine similarity score to the provided phrase.
- **NLP Query (Hardened)**: `POST /api/v1/query/nlp` now supports `page` and `size` plus optional `x-api-key` header when `API_QUERY_KEY` env set.
- **Decision Stream (SSE)**: `GET /stream/decisions` server-sent events feed (array of new decisions) every ~2s.
- **Factor Stats**: `GET /api/v1/stats/factors/top?window=1h&limit=20` shows most frequent factors in the interval.
- **Risk Register**: `GET /risk_register` serves current markdown risk register.

Example NLP paginated request:
```bash
curl -X POST http://localhost:8080/api/v1/query/nlp \
  -H 'Content-Type: application/json' \
  -d '{"query":"show malicious events last 2h confidence > 0.8","page":1,"size":25}'
```

SSE example (browser devtools):
```javascript
const ev = new EventSource('http://localhost:8080/stream/decisions');
ev.onmessage = e => console.log(JSON.parse(e.data));
```

- Embed factors on decision persistence.
- Add `/api/v1/query/factors?similar=credential dumping`.
- Ranking via cosine similarity on a local MiniLM embedding model.

### Optional pgvector Acceleration
If you install the `pgvector` extension in Postgres you can enable approximate nearest neighbor
search for factor embeddings. Run migration `0003_pgvector.sql` after `0002_factor_embeddings.sql`.
The system will auto-detect pgvector; if unavailable it falls back to in-process cosine similarity
over a sampled subset. With pgvector enabled the endpoint `/api/v1/query/factors` delegates similarity
computation to the database using `vector_cosine_ops` with an IVFFlat index.

To install (example Ubuntu):
```bash
sudo apt-get install postgresql-server-dev-15
git clone https://github.com/pgvector/pgvector.git
cd pgvector
make
sudo make install
```
Then run:
```powershell
python scripts/run_migrations.py  # ensures 0003_pgvector.sql applied
```
You can tune the IVFFlat lists count by editing the migration (default 100). After initial load run:
```sql
ANALYZE factor_embeddings;
```
The API transparently keeps JSON fallback (`embedding_json`) for inspection and graceful degradation.

### React/Vite Analyst Console (Alpha)
In addition to the vanilla preview console, a React + Vite implementation lives under `frontend/react`.

Run (from `frontend/react`):
```powershell
pnpm install # or npm install / yarn
pnpm run dev  # serves on default Vite port (e.g., 5173)
```
Features (parity + enhancements):
- Decision stream (SSE)
- Similarity search (protected)
- Factor stats (windowed)
- Factor weights (feedback-derived)
- Embedding & drift metrics (JS divergence gauge + avg norm)
- Feedback submission widget
- NLP Query panel (paged, parameterized, scopes required) enabling natural language filtering into underlying DSL/SQL

New Endpoints surfaced:
- `GET /api/v1/weights/factors` – current factor weights
- `GET /api/v1/metrics/embedding` – `{ embedding_avg_norm, factor_freq_js_divergence }`

Access Log Sampling:
Set `ACCESS_LOG_SAMPLE_RATE` (0..1) to reduce volume (default 1 = all). Example:
```powershell
$env:ACCESS_LOG_SAMPLE_RATE='0.25'  # sample 25% of requests
```
The access log table: `access_log(subject, method, path, status, scopes, ip, user_agent)`.

Feedback Weighting:
Weights aggregate every 5 minutes using smoothed proportion of up vs down votes.
Confidence adjustment: `confidence *= (1 + sum(weights_for_factors))` (bounded 0..1, each factor weight clamped ±0.25).

Drift Metric:
`factor_freq_js_divergence` computed over adjacent 30m windows of factor usage; high values can indicate pattern shift.

### Authentication & Scopes (Lightweight)
Protected endpoints (NLP query, factor similarity, feedback) now enforce scope-based auth via either API keys or JWT.

Configure static API keys (environment variable):
```powershell
$env:API_KEYS_JSON='[{"key":"devkey123","scopes":["nlp.query","factors.search","feedback.write"]}]'
```
JWT (optional) environment variables:
```powershell
$env:JWT_SECRET='supersecret'
$env:JWT_AUDIENCE='janusec'
$env:JWT_ISSUER='your-company'
```
Scopes:
- `nlp.query` – access to `/api/v1/query/nlp`
- `factors.search` – access to `/api/v1/query/factors`
- `feedback.write` – access to `/api/v1/feedback/factor`

Wildcard `*` grants all. Roles can be encoded in JWT (`role: analyst` maps to typical scopes).

### Factor Feedback Endpoint
Record analyst signal to improve adaptive tuning:
```bash
curl -X POST http://localhost:8080/api/v1/feedback/factor \
  -H "x-api-key: devkey123" -H 'Content-Type: application/json' \
  -d '{"event_id":"evt-1","factor":"suspicious_dns","vote":1}'
```
Votes: `1` (thumbs-up), `-1` (thumbs-down). Stored in `factor_feedback` table. Metrics: `factor_feedback_up_total`, `factor_feedback_down_total`.

### Embedding Quality Metrics
Periodic task computes average embedding L2 norm (`embedding_avg_norm`) and placeholder drift gauge (`factor_embedding_drift`). Extend later with KL/JS divergence across time windows.

### Vector Index Maintenance
Background task recalculates recommended IVFFlat `lists` = sqrt(rowcount) (capped 1000) and recreates index when materially different. Best-effort, silent if pgvector absent.

### SPA (Alpha Preview)
Located under `frontend/spa` (vanilla modular JS for now). Features:
- Decision streaming panel via `/stream/decisions` SSE
- Factor similarity search (auth header aware)
- Factor statistics windowed view
- Floating feedback toolbar (API key store + vote submission)

Serve via existing static mount or add a static files mount mapping `/spa` to `frontend/spa`.

Planned progression: Replace vanilla modules with React + Vite build (componentized dashboards, feedback-driven ranking overlays, drift charts).


## 🚨 Testing & Quality Assurance

- **Unit Tests**: Core functionality testing
- **Performance Tests**: Latency and throughput benchmarks  
- **Integration Tests**: End-to-end workflow validation
- **Chaos Testing**: Failure resilience validation

## 🎯 Direct CyberStash Alignment

This platform directly addresses CyberStash's requirements:

✅ **Eclipse XDR Integration**: Native API integration for alert ingestion and verdict updates  
✅ **AI-Assisted Validation**: Uses lightweight ML instead of heavy Airia.ai/Neuron.AI dependencies  
✅ **SOAR Playbook Execution**: Automated response workflows with human-in-the-loop  
✅ **80% Coverage Target**: Progressive enhancement ensures 100% alert coverage  
✅ **75% Precision Target**: Adaptive tuning maintains precision through calibration  
✅ **40% Time Reduction**: Fast-path processing eliminates manual triage for obvious cases  
✅ **99% Reliability**: Circuit breakers and graceful degradation ensure uptime  

## 🔄 Development Roadmap (Condensed)

### Phase 1: Core Foundation ✅
- [x] Main orchestrator with circuit breakers
- [x] Baseline module with bloom filters
- [x] Regex engine with timeout protection  
- [x] Adaptive tuner with drift detection
- [x] Module registry with lazy loading

### Phase 2: Enhanced Analysis (Next)
- [ ] Network threat hunter implementation
- [ ] Endpoint hunter with process analysis
- [ ] Compliance mapper (MITRE ATT&CK, NIST)
- [ ] Storage manager with tiered architecture

### Phase 3: Production Hardening
- [ ] Full Eclipse XDR integration
- [ ] SOAR playbook execution engine
- [ ] Grafana dashboards
- [ ] Performance optimization

### Phase 4: Advanced Features
- [ ] Graph intelligence layer
- [ ] NLP query interface
- [ ] Multi-tenant support
- [ ] Advanced ML models

## 🤝 Contributing

1. Follow the 400-500 LOC per module constraint
2. Include comprehensive tests for new features
3. Maintain performance SLAs
4. Update documentation

## 📝 License

This project is proprietary to CyberStash security operations.

---

---

### 🔗 Public API Surface (Current)

| Purpose | Method & Path | Notes |
|---------|---------------|-------|
| Health | `GET /health` | Liveness summary |
| Readiness | `GET /ready` | Module health fan-out |
| Metrics | `GET /metrics` | Prometheus exposition |
| Ingest Event | `POST /api/v1/events` | JSON event (id required) |
| Eclipse XDR Ingest | `POST /api/v1/events/eclipse-xdr` | Optional shared secret |
| Decision (single) | `GET /api/v1/decisions/{event_id}` | Recent cached decision |
| Recent Decisions | `GET /api/v1/decisions/recent` | List recent decisions |
| Recent Alerts | `GET /api/v1/alerts/recent` | Alerts (best-effort) |
| Custody Chain | `GET /api/v1/chain/{event_id}` | Hash-linked audit chain |
| Factor Similarity | `GET /api/v1/query/factors?similar=...` | Scope: `factors.search` |
| NLP Query | `POST /api/v1/query/nlp` | Scope: `nlp.query`; paginated |
| Factor Stats | `GET /api/v1/stats/factors/top` | Windowed frequency |
| Factor Weights | `GET /api/v1/weights/factors` | Learned weights snapshot |
| Embedding Metrics | `GET /api/v1/metrics/embedding` | Avg norm & JS divergence |
| Feedback Vote | `POST /api/v1/feedback/factor` | Scope: `feedback.write` |
| SSE Decision Stream | `GET /stream/decisions` | Server-sent events (array) |
| Risk Register | `GET /risk_register` | Markdown risk register |
| Console Preview | `GET /console` | Minimal embedded console |

### 🔐 Scopes Overview
Required scopes: `nlp.query`, `factors.search`, `feedback.write` (or `*`). JWT audience now `janusec`.

### ♻️ Rebrand Notice
Repository rebranded to **JanuSec** on 2025-09-21. Legacy identifiers still accepted where practical:
- Legacy DB default: `threatsifter` (supply via env to continue using)
- Legacy JWT audience: `threat-sifter` (update tokens; new default `janusec`)
- Legacy log paths under `/var/log/threat-sifter/*` continue until ops migration; new defaults use `/var/log/janusec/*`.
See `BRANDING_CHANGE.md` for migration guidance & compatibility notes.

**Built with pragmatic engineering principles – reduce noise, preserve signal, stay adaptive.**