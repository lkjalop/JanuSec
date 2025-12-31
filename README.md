# JanuSec (Public Project Showcase)

This repository contains public, sanitized documentation and example artifacts for JanuSec — an AI-powered XDR triage platform. The goal of this repo is to demonstrate architecture, design decisions, and reproducible examples without exposing proprietary detection logic or customer data.

See `docs/` for architecture and deployment details, `examples/` for synthetic detection rule templates and correlation patterns, and `tools/` for a synthetic event generator used in demos and benchmarks.

For maintainers: keep private IP, real rules, and production telemetry out of this repository.

## Quickstart

Generate 10 synthetic events for demos:

```bash
python tools/data-ingestion-simulator/generate_events.py --count 10
```

## Structure

- docs/: Architecture & deployment guides
- examples/: Sanitized rule templates and sample configs
- tools/: Synthetic data and benchmark scripts
- images/: Diagrams
- whitepapers/: Executive & technical briefs

## License
See LICENSE
# JanuSec Adaptive Threat Decision Platform

> Version: **0.9.0-pre (Pre-Production Validation Update – 2025-09-22)**  
> Status: "Ready With Conditions" (synthetic & harness-based validation complete, live traffic calibration pending)

[![pytest-lite](https://github.com/lkjalop/JanuSec/actions/workflows/pytest-lite.yml/badge.svg)](https://github.com/lkjalop/JanuSec/actions/workflows/pytest-lite.yml)
[![pytest-full](https://github.com/lkjalop/JanuSec/actions/workflows/pytest-full.yml/badge.svg)](https://github.com/lkjalop/JanuSec/actions/workflows/pytest-full.yml)


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

## Risk Explain API (New)

This release adds an explainable risk composer and an API for retrieving
component-level explanations for decisions.

- Endpoint: GET /api/v1/risk/{event_id}/explain
- Returns: JSON with fields: score, raw_score, breakdown (list of factors),
  variance, ci95, method, confidence

### Header accept eviction note (testing)

The `NetworkThreatHunter` maintains in-memory frequency maps for `Accept` and `Accept-Language` headers.
To avoid unbounded memory growth we cap these maps and perform eviction when they exceed ~2000 entries. Unit tests that exercise this behavior are under `tests/test_header_accept_eviction.py` and validate that the map size is reduced to <= 1500 while still recording new values.

### HopGraph & Investigate CLI

The lightweight hop graph is populated during event analysis (host->ip, ip->domain, proc->host edges).

Generate an HTML evidence card for a node:

```
python scripts/investigate.py host:hostz --hops 2 --html -o evidence.html
```

Stream events (newline JSON) into the graph and auto-select first host:

```
cat events.ndjson | python scripts/investigate.py --from-events --html -o stream_evidence.html
```

Key environment variables:
- RISK_HIGH_THRESHOLD (float) — high risk marker threshold (default 0.8)
- RISK_FACTOR_WEIGHTS (CSV) — inline mapping e.g. "f1=0.5,f2=0.2"
- RISK_WEIGHTS_YAML (path) — optional YAML file path for hot-reloadable weights
- RISK_COMPLETENESS_EXPECTED_CLASSES — comma-separated factor classes for completeness checks
- RISK_COMPLETENESS_MIN_PRESENT — minimum distinct classes required to avoid completeness penalty
- RISK_COMPLETENESS_PENALTY — penalty magnitude applied when completeness gate fails
- RISK_SIGMOID_CALIBRATION — if set, applies logistic calibration to the raw score; use with RISK_SIGMOID_K and RISK_SIGMOID_X0

### New Detection & Heuristic Environment Variables
These variables were recently added to tune new network & endpoint heuristics:

| Variable | Purpose | Default |
|----------|---------|---------|
| PORTSCAN_WINDOW_SECONDS | Sliding aggregation window for port scan tracking | 300 |
| PORTSCAN_VERTICAL_THRESHOLD | Distinct dst ports to one host before vertical scan factor | 20 |
| PORTSCAN_HORIZONTAL_THRESHOLD | Distinct destination hosts for same port before horizontal scan factor | 30 |
| ACCEPT_RARE_THRESHOLD | Occurrence count threshold (<=) for rare Accept header factor | 2 |
| ACCEPT_LANGUAGE_RARE_THRESHOLD | Occurrence count threshold (<=) for rare Accept-Language factor | 2 |
| DISABLE_LOLBIN_REGISTRY | If set (1/true) disables loading `data/lolbins.yaml` | off |
| PORT_SCATTER_WINDOW_SECONDS | (Existing) egress port scatter window | 300 |
| PORT_SCATTER_THRESHOLD | (Existing) distinct ports threshold for scatter factor | 12 |
| INCIDENT_SNAPSHOT_INTERVAL_SECONDS | Interval for background incident snapshot persistence (0 disables) | 0 |

### Geo Enrichment & Heuristics (New)

The platform now performs lightweight Geo-IP + ASN enrichment (CSV-backed) and exposes early geo-based rarity / risk factors. All geo logic is bounded and optional.

## Unified HopGraph Architecture (Core + Lite)

- Core: `src/core/graph/hopgraph_core.py` re-exports the production HopGraph from `src/graph/hopgraph.py` and provides `get_core_graph()` for final-stage correlation and explainability.
- Lite: `src/core/graph/hopgraph_lite.py` is the early-stage cache/time-window graph used for fast temporal checks in the pipeline.
- Light (compat): `src/core/hunt/hopgraph_light.py` retains late-stage lightweight tracking and now includes a deprecation note; prefer Core/Lite for new code.
- Goal: minimize fragmentation, keep two canonical implementations (Core/Lite) without creating a monolith. Shims keep legacy imports working.

## CEO Demo Quick Start

- See `docs/QUICK_START_CEO_DEMO.md` for a 5-minute run-through using the LIVE console and Multi-Source Correlator (`/static/csv_multi_analyzer.html`).
- Simulated streaming helper:
  - `python -m scripts.demo_ceo tests/fixtures/api_gateway_sample.csv tests/fixtures/database_query_sample.csv tests/fixtures/vpn_access_sample.csv tests/fixtures/rdp_sessions_sample.csv`

| Variable | Purpose | Default |
|----------|---------|---------|
| GEOIP_ENABLED | Enable Geo-IP/ASN enrichment module | 1 (on) |
| GEOIP_CSV | Path to CSV (start_ip,end_ip,country,asn) loaded at runtime | data/geoip_demo.csv |
| COUNTRY_RARE_THRESHOLD | Emit `net:country_rare` for a country until its observation count exceeds this threshold | 3 |
| HIGH_RISK_ASNS | Comma list of ASNs that trigger `net:asn_high_risk` factor when observed | AS15169,AS13335,AS9009 |
| GEO_RARITY_DECAY_SECONDS | Inactivity window after which per-country/ASN counts decay (halved) to allow resurfacing rarity for sporadic geos | 3600 |

Geo factors (confidence deltas capped inside NetworkThreatHunter overall MAX_CONFIDENCE=0.15):
| Factor | Description | Approx Added Delta* |
|--------|-------------|---------------------|
| net:country_rare | Country seen <= COUNTRY_RARE_THRESHOLD times (after decay) | 0.01 |
| net:asn_high_risk | Destination in HIGH_RISK_ASNS list | 0.015 |

*Deltas are routed through `adjust_delta` and then clipped by the hunter's cumulative confidence ceiling; they will never push a single hunter above its `MAX_CONFIDENCE` cap.

Decay Behavior: Every event triggers a check; if a country/ASN has not been seen for GEO_RARITY_DECAY_SECONDS its count is halved (integer floor). Entries reaching 0 are evicted, keeping state bounded and allowing legitimately rare regions to surface again after quiet periods.

Testing: `tests/test_geoip_enrichment.py` validates enrichment lookups; `tests/test_geo_correlation_integration.py` ensures geo factors integrate with temporal correlation while respecting the confidence cap.

Operational Notes:
- CSV loading is lazy (first lookup) and cached in-memory with a binary search over sorted ranges.
- Lookups are LRU memoized (size 2048) to reduce repeated int conversions and searches.
- Prometheus counters `geoip_lookups_total` & `geoip_hits_total` track enrichment usage; module reloads in tests reuse existing collectors to avoid duplicate registration errors.


### Correlation & Graph / Runner Environment Variables (New)

| Variable | Purpose | Default |
|----------|---------|---------|
| CORR_TEMPORAL_WINDOW_SEC | Time window seconds for multi-hop temporal correlation pattern tracking | 900 |
| CORR_TEMPORAL_MAX_EVENTS | Max events retained per entity for temporal correlation | 200 |
| CORR_TEMPORAL_COOLDOWN_SEC | Cooldown before emitting same temporal correlation factor again for an entity | 300 |
| COOCC_ENABLED | Enable factor co-occurrence PMI correlation | 1 (on) |
| COOCC_MIN_COUNT | Minimum pair co-occurrence count before PMI evaluated | 3 |
| COOCC_PMI_THRESHOLD | Natural log PMI threshold to emit high-PMI pair factor | 0.8 |
| COOCC_MAX_PAIRS | Soft cap on distinct pairs tracked (skip new beyond cap) | 50000 |
| COOCC_COOLDOWN_SEC | Cooldown between emitting high-PMI pair factor for same pair | 600 |
| HOPGRAPH_SOFT_EDGE_WM | Optional soft watermark for total HopGraph edges (gauge only) | unset |
| HOPGRAPH_HARD_EDGE_WM | Optional hard watermark; exceed triggers edge trimming (75% newest retained) | unset |
| HOPGRAPH_EXPLAIN_CACHE_MAX | LRU explain cache entry cap | 256 |
| HOPGRAPH_EXPLAIN_CACHE_TTL_SECONDS | Optional TTL for explain cache items | 5 |
| TEST_PER_FILE_TIMEOUT_SEC | Sequential runner per-file timeout (diagnostics harness) | 40 |
| TEST_TWO_PASS | Enable two-pass sequential test run (fast sync pass then async pass) | 1 |

Correlation emitted factors:
- `corr:multi_stage_lateral_beacon` – Temporal sequence: rare lineage → lsass access → periodic beacon.
- `corr:pair_high_pmi` – High pointwise mutual information factor pair (stable statistical co-occurrence) after minimum count & PMI threshold.

### Session Persistence Backend (HopGraph Sessions)

The graph session build endpoint supports pluggable persistence backends for session summaries:

| Env Var | Purpose | Default |
|---------|---------|---------|
| SESSION_BACKEND | Persistence backend selector (`json` or `sqlite`) | json |
| SESSION_PERSIST_DIR | Directory for JSON session files | data/sessions |
| SESSION_PERSIST_SQLITE_PATH | SQLite database file path (used when backend=`sqlite`) | data/sessions/sessions.db |
| SESSION_TTL_SECONDS | TTL for session records (applies to both backends) | 86400 |
| SESSION_CLEAN_INTERVAL_SECONDS | Background cleanup interval (0 disables scheduler) | 0 |

Behavior:
- JSON backend writes one file per session (`<id>.json`). TTL enforced by mtime during load/cleanup.
- SQLite backend stores rows in `sessions` table (`id`, `json`, `created_at`, `updated_at`). TTL enforced via `updated_at` cutoff during load and periodic cleanup.
- Switching backends is instantaneous; existing JSON files remain untouched when moving to SQLite and vice versa. Dual-write during build is best-effort when a SQLite path is explicitly provided (for migration scenarios).
- Cleanup loop removes expired JSON files or purges expired rows (`updated_at < now - SESSION_TTL_SECONDS`). Enable by setting `SESSION_CLEAN_INTERVAL_SECONDS` to a positive number.

EWMA history persistence (optional):
- `EWMA_HISTORY_PATH` sets the JSON file holding smoothing state (default `data/sessions/ewma_history.json`).
- `EWMA_HISTORY_TTL_SECONDS` prunes stale entries in the same cleanup loop.

Testing: See `tests/test_graph_session_sqlite.py` for round-trip and TTL expiration coverage.

Migration Tip: Set `SESSION_BACKEND=sqlite` and `SESSION_PERSIST_SQLITE_PATH` early in deployment to accumulate historical session graph summaries with efficient pruning. Leave unset to retain legacy file-based behavior.

## Automated Playbooks (authoring)

You can author playbooks as JSON files under `src/data/playbooks/`.

Basic structure:

```json
{
  "name": "example-playbook",
  "trigger": {"factor": "identity:pass_the_cookie_reuse"},
  "dry_run": true,
  "steps": [
    {"type": "open_case", "params": {"title": "Detected ${user}"}},
    {"type": "revoke_sessions", "params": {"user": "${user}"}},
    {"type": "notify", "params": {"webhook_url": "${webhook}", "msg": "Remediated ${user}"}}
  ]
}
```

Triggers supported:
- `factor` — exact factor match
- `factor_any` — list of factors (matches any)
- `factor_prefix` — prefix match for factor keys

Templating:
- Jinja2 is used if installed (recommended). Example: `{{ user|default('unknown') }}`
- If Jinja2 is not available, simple `${var}` substitution via `string.Template` is used.
- The platform exposes a small context extracted from events: `user`, `host`, `ip`, `file_hash`. You can supply additional context at runtime when previewing via `/api/v1/playbooks/resolve`.

## Detection Rule Authoring (YAML Example)

You can author detection rules using a simple YAML structure which maps to the Pydantic `DetectionRule` model at `src/core/rules/schema.py`.

Example rule (YAML):

```yaml
meta:
  id: rule-office-macro-powershell
  name: Office Macro -> PowerShell chain
  description: Detect Office macro invoking encoded PowerShell
  author: security-team
  version: '1.0'
  tags: [office,macro,powershell]

conditions:
  - field: lane_process_lineage
    op: contains
    value: office_macro_spawn_powershell
  - field: process_command_line
    op: regex
    value: "(?i)powershell\\s+.*-enc"

actions:
  - type: emit_factor
    params:
      factor: corr_office_macro_ps
  - type: create_alert
    params:
      title: "Office macro spawned encoded PowerShell"
      severity: HIGH

score: 0.75
enabled: true
```

Loader snippet (Python) using Pydantic model:

```python
import yaml
import json
from src.core.rules.schema import DetectionRule, export_json_schema

def load_rule_from_yaml(path: str) -> DetectionRule:
    with open(path, 'r', encoding='utf-8') as fh:
        data = yaml.safe_load(fh)
    rule = DetectionRule(**data)
    return rule

# Export JSON Schema for tooling (CLI or web UI)
schema = export_json_schema()
open('rule_schema.json','w',encoding='utf-8').write(json.dumps(schema, indent=2))
```

Runner steps supported (demo runnner):
- `enrich`, `open_case`, `block_ip`, `notify`, `revoke_sessions`, `quarantine_file`, `policy_rollback`, `disable_mailbox_rule`, `reset_credentials`

Auto-run behavior:
- Enable auto-run by setting `AUTO_RUN_PLAYBOOKS=1`. Playbooks will be resolved for emitted rules and enqueued for background execution (dry-run by default).
- Async queue worker count configurable via `PLAYBOOK_QUEUE_WORKERS` (default 1).

Preview API:
- POST `/api/v1/playbooks/resolve` with `{"factor":"net:tor_outbound_contact"}` to preview matching and rendered playbooks.

Best practices:
- Use dry-run in production by default and integrate secure connectors (IdP/firerwall) in the runner before enabling non-dry execution.
- Keep playbooks idempotent and quick — long-running steps should be offloaded to external workflows.


Watermark behavior:
- Hard watermark breach triggers proportional trimming (per adjacency list keep newest 75%). Gauges exported: `hopgraph_total_edges`, `hopgraph_soft_edge_watermark`, `hopgraph_hard_edge_watermark`.
- Explain cache metrics: `hopgraph_explain_cache_hits_total`, `hopgraph_explain_cache_misses_total` for cache efficiency tracking.

Sequential two-pass test runner (`scripts/run_tests_sequential.py`):
1. Pass 1: disables plugin autoload for speed & isolation (`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`).
2. Pass 2 (if enabled): detects files containing async tests and reruns them with `pytest_asyncio` plugin only.
Set env `TEST_TWO_PASS=0` to revert to single pass; adjust per-file timeout via `TEST_PER_FILE_TIMEOUT_SEC`.

### Sample Prometheus Metrics Snapshot (Representative)

```
# HELP hopgraph_edges_total Total edges currently stored
hopgraph_edges_total 4213
# HELP hopgraph_total_edges Total HopGraph edges (for watermarks)
hopgraph_total_edges 4213
# HELP hopgraph_soft_edge_watermark Configured HopGraph soft edge watermark
hopgraph_soft_edge_watermark 0
# HELP hopgraph_hard_edge_watermark Configured HopGraph hard edge watermark
hopgraph_hard_edge_watermark 0
# HELP hopgraph_explain_cache_hits_total LRU explain cache hits
hopgraph_explain_cache_hits_total 88
# HELP hopgraph_explain_cache_misses_total LRU explain cache misses
hopgraph_explain_cache_misses_total 12
# HELP correlation_temporal_matches_total Temporal correlation pattern matches
correlation_temporal_matches_total 3
# HELP correlation_cooccurrence_high_pmi_total High PMI factor pair matches
correlation_cooccurrence_high_pmi_total 1
```

Counts are illustrative only; real values depend on runtime load and event mix.


Beacon Periodicity Gating:
- Base factor `net:beacon_periodic` triggers when CV < BEACON_CV_THRESHOLD (default 0.20) OR moderately low CV with strong autocorr / spectral (Lomb-Scargle) evidence.
- Elevation to `net:beacon_periodic` requires very tight CV (< 0.5 * threshold) OR tight CV plus high autocorrelation (>0.92) or Lomb-Scargle peak power (>0.8).
- High jitter flows therefore emit at most `net:beacon_periodic` (or nothing) reducing false positives.

Optional SciPy Integration:
If SciPy is installed, Lomb-Scargle (`scipy.signal.lombscargle`) refines periodic strength; failures or absence gracefully degrade (`lomb_power=0`).

Multi-Scale Beacon Explanation:
See `BEACONING.md` for detailed multi-scale algorithm, explanation payload fields, and tuning environment variables (`MULTISCALE_BEACON_ENABLED`, `BEACON_CONN_MAXLEN`, `BEACON_CONN_RETENTION_SECONDS`).

Registry file: `data/lolbins.yaml` (extend by adding entries & reloading service). Set `DISABLE_LOLBIN_REGISTRY=1` to revert to legacy inline heuristics only.

The explain endpoint is best-effort and will compute the score on-demand if the decision cache entry is not pre-enriched.

### Quick Usage

```powershell
# Retrieve explain breakdown for a decision
curl -s http://localhost:8000/api/v1/risk/DECISION_ID/explain | python -m json.tool
```

### CSV Analyzer / Excel upload troubleshooting

If you see client-side errors like "XLSX is not defined" or server errors saying the Excel library is unavailable, here are fast fixes:

- Preferred quick fix (bundled starter — installs deps and relaxes CSP):

  Run the included starter which installs Python deps (including openpyxl) and sets `DISABLE_CSP=1` so the client can load the XLSX script:

  ```powershell
  .\start_server.bat
  ```

- If you launch the server another way, install the Python Excel library in the active environment:

  ```powershell
  python -m pip install openpyxl
  # optional legacy formats
  python -m pip install xlrd pyexcel-ods3
  ```

- If your network blocks CDNs (client can't fetch SheetJS), prefer the local vendor copy. Use the helper to copy or download it:

  ```powershell
  ./scripts/fetch_sheetjs.ps1
  ```

- If you prefer server-side parsing only, use the CSV Analyzer's "Upload (Server Parse)" button — it will parse on the backend (requires openpyxl).

These steps should eliminate common causes for Excel parsing failures.

### Response Shape (Representative)

| Field | Type | Description |
|-------|------|-------------|
| score | float | Calibrated (final) risk score in [0,1] |
| raw_score | float | Pre-calibration multiplicative fused score |
| breakdown | list[{factor,weight,delta,contribution}] | Sorted by absolute contribution descending |
| variance | float | Heuristic variance across factor contributions |
| ci95 | [low, high] | 95% confidence interval bounds |
| mean_contribution | float | Mean per-factor contribution |
| method | str | Composer implementation identifier |
| confidence | float | Downstream decision confidence (unchanged) |

See full sample in `docs/risk_explain_example.json`.

### Logistic Calibration (Optional)

| Env Var | Purpose | Default |
|---------|---------|---------|
| RISK_SIGMOID_ENABLED | Enable logistic mapping of raw_score | off |
| RISK_SIGMOID_SLOPE | Sigmoid k (steepness) | 4.0 |
| RISK_SIGMOID_CENTER | Sigmoid x0 (midpoint) | 0.5 |

Generate calibrated parameters from labeled historical data:

```powershell
# decisions.csv must contain columns: raw_score,label (label ∈ {0,1})
python scripts/calibrate_risk_sigmoid.py --input decisions.csv --format csv --score-col raw_score --label-col label --metric auc
```

> Tip: Persist `raw_score` so you can retroactively re-calibrate without recomputing factor fusion.


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

## � Development / Contributing

For local reliability:

| Command | Purpose |
|---------|---------|
| `make test` | Standard pytest run (plugins auto) |
| `make test-seq` | Two-pass sequential (fast first, then async) |
| `make test-async` | Async-only test subset |

Two-pass runner uses `TEST_PER_FILE_TIMEOUT_SEC` (default 40) and `TEST_TWO_PASS=1` to control behavior. To skip async second pass: `TEST_TWO_PASS=0 make test-seq`.

See `CONTRIBUTING.md` for:
- Correlation module architecture
- HopGraph watermark behavior & metrics
- Naming governance (factor prefixes)
- PR checklist (tests, docs, metrics cardinality)

Keep tests deterministic (avoid wall-clock sleeps >0.1s). Use environment overrides for intervals instead of long delays.

---

---

## �🔐 Validation Provenance (Current Manual Elements)
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
## Optional: Enable MinHash-based clustering

For very large similarity signatures, you can optionally enable MinHash to compress signatures before clustering. This can reduce memory and improve duplicate detection for high-token events.

This feature is optional. If the package is not present or the flag is disabled, the system falls back safely to SHA-1 signatures.

Steps:

1) Install the library

```powershell
# Windows PowerShell
pip install datasketch
```

```bash
# macOS/Linux
pip install datasketch
```

2) Enable the feature flag at runtime

```powershell
$env:CLUSTER_MINHASH_ENABLED = '1'
# optional: adjust clustering TTL (seconds) for membership decay
$env:CLUSTER_TTL_SECONDS = '3600'
```

```bash
export CLUSTER_MINHASH_ENABLED=1
# optional
export CLUSTER_TTL_SECONDS=3600
```

Notes:
- The code path is guarded: if datasketch is unavailable or the flag is not set, SHA-1 hashing is used instead.
- MinHash is only applied when token volume justifies it (e.g., iocs + factors > 32 tokens).
- You can revert by unsetting the environment variable or setting it to 0/false.

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
   *Optional warm-up / regression helpers (run in another terminal once the API is listening at http://localhost:8080):*
   ```bash
   python scripts/prewarm_ollama.py --model llama3:8b
   python scripts/verify_loop_closure.py --server http://localhost:8080
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

## 🧵 Redis Streams Worker (Durable Ingest)

The platform supports a Redis Streams-backed durable ingest path. A background worker consumes events from a stream, forwards them to the API batch endpoint, performs idempotent dedupe, reclaims stale messages, and exposes Prometheus metrics.

Key script: `scripts/redis_streams_consumer.py`

Environment variables (common):
- `REDIS_URL` – e.g. `redis://localhost:6379/0`
- `STREAM_INGEST_NAME` – stream name (default `ingest_stream`)
- `STREAM_INGEST_GROUP` – consumer group (default `ingest_group`)
- `STREAM_CONSUMER_NAME` – consumer name (auto-generated by default)
- `INGEST_URL` – API batch endpoint (default `http://127.0.0.1:8000/api/v1/endpoints/log_batch`)
- `STREAM_BLOCK_MS` – XREADGROUP block timeout (ms)
- `STREAM_RECLAIM_MIN_IDLE_MS` – idle time before auto-claim
- `STREAM_RECLAIM_INTERVAL_SEC` – reclaimer loop interval
- `STREAM_DEDUPE_TTL_SEC` – dedupe TTL (seconds)
- `STREAM_DLQ_NAME` / `STREAM_DLQ_DEAD` – DLQ streams
- `STREAM_DLQ_MAX_ATTEMPTS` – DLQ retry attempts before dead-letter
- `WORKER_METRICS_PORT` – if >0, starts an HTTP server at `/metrics` for Prometheus
- `WORKER_BYPASS_HEADER` – header name for internal bypass (default `X-Worker-Secret`)
- `WORKER_BYPASS_TOKEN` – shared secret; when set, worker injects this header to bypass API rate limits intended for external clients

Run locally (PowerShell):
```powershell
$env:REDIS_URL='redis://localhost:6379/0'
$env:INGEST_URL='http://127.0.0.1:8000/api/v1/endpoints/log_batch'
$env:WORKER_METRICS_PORT='9108'
$env:WORKER_BYPASS_TOKEN='changeme'  # also set same value for API
python scripts/redis_streams_consumer.py
```

Docker Compose (provided: `docker-compose.redis.yml`) wires Redis + API + Worker:
- Sets `INGEST_URL` to the correct batch endpoint
- Exposes worker metrics on `9108`
- Passes `WORKER_BYPASS_HEADER`/`WORKER_BYPASS_TOKEN` to both API and worker so internal traffic can bypass per-tenant/global rate limits

Build images and run:
```powershell
docker compose -f docker-compose.redis.yml build
docker compose -f docker-compose.redis.yml up -d
```

Prometheus scrape example for the worker:
```yaml
scrape_configs:
  - job_name: 'janusec-worker'
    static_configs:
      - targets: ['worker:9108']
```

Notes:
- The API will still enforce backpressure if internal queues are near saturation; the bypass only skips external rate limits.
- Dedupe uses SHA-256 keys with TTL to avoid re-processing duplicates.
- DLQ processing retries and eventually moves events to a dead-letter stream after the configured maximum attempts.
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

## ASCII Architecture & Userflows (Public, Sanitized)

Below are ASCII diagrams and step-by-step userflows for three core interactions: the Pipeline flow, HopGraph attack reconstruction, and Manual Log Analysis. These are high-level, non-proprietary, and safe for public distribution.

1) Pipeline Userflow (Ingress → Triage → Decision)

```
    +--------------------+
    |   External Feeds   |  <-- Cloud CSPM / EDR / Network / Mail / SBOM
    +---------+----------+
        |
        v
    +--------------------+
    |     Ingestor       |  (validation, dedupe, custody hash)
    +---------+----------+
        |
        v
    +--------------------+
    |  Orchestrator /    |  (lane routing, parallel lanes, module registry)
    |  Pipeline Runner   |
    +---------+----------+
        |
      +-------------------+-------------------+
      |                   |                   |
      v                   v                   v
  Lightweight         Enrichment          Heavy Stages
  (baseline/regex)  (intel/identity/sbom) (e.g., binary_payload, beacon, egress)
      |                   |                   |
      +---------+---------+---------+---------+
        |
        v
    +--------------------+
    |  Correlation (Hop) |  (HopGraph joins, temporal windows, PMI co-occurrence)
    +---------+----------+
        |
        v
    +--------------------+
    |  Composer / Scorer |  (factor fusion, calibration, persona routing)
    +---------+----------+
        |
      +-------------+--------------+
      |                            |
      v                            v
   Decision Store (DB)           Analyst UI / API (T1/T2 reports, SSE)
   (persisted custody)           (playbook suggestions, evidence cards)
```

Pipeline notes (public):
- Ingest performs basic validation and produces a custody chain hash at each stage.
- Lightweight stages always run; heavy stages are gated by configurable confidence thresholds to save compute.
- Enrichment layers add context (geo, sbom, threat intel) and are optional fallbacks.
- Correlation joins partial evidence across domains into a HopGraph for attack reconstruction and scoring.

2) HopGraph Attack Reconstruction Userflow

```
  Analyst triggers investigation -> select root entity (e.g., host-123 or event-evt-999)
    |
    v
  Load session -> Build local HopGraph view (N hops) using persisted edges/nodes
    |
    v
  Visualize graph: nodes (host,user,process,file,ip,domain) and edges (executed_on,connected_to,downloaded)
    |
    v
  Automated path-finding: find high-confidence paths from initial access -> lateral movement -> exfil
    |
    v
  Emit a walkthrough report: timeline of events, key factors per hop, recommended playbook steps
    |
    v
  Analyst accepts/annotates: feedback stored to factor feedback table → future weight updates
```

HopGraph notes (public):
- The public repo includes a sanitized `examples/correlation-patterns/` file showing synthetic nodes/edges.
- Reconstruction is follow-the-evidence: HopGraph is a join surface, not a deterministic oracle — analysts review suggested chains.
- Explainability: each edge and node includes provenance (source feed, timestamp, confidence delta) so the chain can be audited.

3) Manual Log Analysis Userflow (Analyst-driven)

```
  Upload / Paste Logs -> CSV/Excel Analyzer (header auto-detect)
    |
    v
  Field mapping UI -> map sheet headers to canonical fields (user, host, ip, process, ts)
    |
    v
  Run local correlation preview -> show matching HopGraph candidates & suggested joins
    |
    v
  Generate evidence card -> include extracted artefacts, suggested factors, and recommended next steps
    |
    v
  Export to incident (create incident + attach artifacts) or re-ingest into pipeline for automated correlation
```

Manual Log Analysis notes:
- The analyzer supports client-side parsing; if dependencies are missing it falls back to server-side parsing.
- Example configs and a synthetic CSV are included under `examples/` to reproduce the flow without real data.

Security & Privacy reminder
- Do not upload real customer logs or PII to public demos. Use the included synthetic generators and examples to create representative datasets.

---

End of public architecture & userflows.

## Canonical Frontend & API (for Copilot/Claude)

- React source lives in `frontend/react`; build output is `frontend/react/dist`.
- The API serves the React build at `/react` and, when present, also returns the React index at `/`.
- The React app resolves the backend URL via `VITE_API_BASE` (if set) or `window.location.origin`.
- Use the detachable right panel at `/sidepanel` for Live stream, Dashboards (Grafana), Metrics (/metrics), and Notify (SOAR demo).

Build and run:

```
cd frontend/react && npm ci && npm run build
uvicorn src.api.app:app --host 0.0.0.0 --port 8000
```

Optional Vite override (dev): create `frontend/react/.env` with `VITE_API_BASE=http://localhost:8000`.

## Frontend of Record (READ ME)

- Canonical LIVE console UI: `frontend/static/janusec-platform-complete-LIVE.html`
- The API serves this page at `/` and `/live` when `DEFAULT_FRONTEND=console` (see `src/api/app.py`).
- Extend the UI via static pages under `frontend/static/` and link from the left sidebar. Do not replace the LIVE console.
- See `AGENTS.md` for agent/collaborator guidance and the list of supported API endpoints used by the UI.

### New Multi-Format Upload & Spreadsheet Support (Added Q4 2025)

The upload pipeline and File/CSV/Excel Analyzer now support these formats:

| Format | Extensions | Detection Path | Notes |
|--------|------------|----------------|-------|
| CSV / TSV | .csv, .tsv, .log, .txt | Extension | Delimiter auto-detection (comma, tab, semicolon, pipe) in frontend; server uses Python csv. |
| Excel (modern) | .xlsx, .xlsm | Extension → openpyxl | Read-only streaming parsing; pagination session created for large files. |
| Excel (legacy) | .xls | Extension → xlrd (optional) | Requires `xlrd`; graceful error if missing. |
| OpenDocument | .ods | Extension → pyexcel-ods3 (optional) | Requires `pyexcel-ods3`; graceful error if missing. |
| Gzip-compressed | *.csv.gz, *.xlsx.gz etc. | Extension `.gz` | Frontend attempts client-side gzip for CSV; server transparently decompresses for csv/excel. |
| ZIP archive (CSV bundle) | .zip | ZIP signature | Server inspects up to 10 CSV members, aggregates union headers + IoC scan. |

Optional Python dependencies (install only what you need):

```bash
pip install openpyxl          # .xlsx / .xlsm
pip install xlrd              # legacy .xls
pip install pyexcel-ods3      # .ods
```

If a dependency is missing the API returns a structured error for that file (does not crash batch). The frontend hybrid parser uses SheetJS for client-side `.xlsx/.xlsm` preview and falls back to server parsing for legacy or large files.

Environment overrides:
| Variable | Purpose | Default |
|----------|---------|---------|
| MAX_UPLOAD_BYTES | Per-file size cap (bytes) | 10485760 (10MB) |
| CERT_CHECK_TTL_SEC | Cert cache TTL | 86400 |

### Certificate Reputation & Validation (CT/OCSP) Module

Background worker performs opportunistic CT + OCSP lookups with caching, batching, metrics, and durable webhook retry.

| Variable | Purpose | Default |
|----------|---------|---------|
| CERT_CT_API_URL | Base URL queried as `${base}/ct/{fp}` returning JSON `{suspicious: bool}` | unset (heuristic fallback) |
| CERT_OCSP_API_URL | Base URL queried as `${base}/ocsp/{fp}` returning JSON `{status: good|revoked|unknown}` | unset (heuristic fallback) |
| CERT_CHECK_TTL_SEC | Cache TTL for cert_results | 86400 |
| CERT_CHECK_RATE_PER_MIN | Max outbound CT/OCSP queries per minute (token bucket) | 60 |
| CERT_CHECK_BATCH_SIZE | Findings per webhook batch | 10 |
| CERT_CHECK_BATCH_INTERVAL_SEC | Max seconds before flushing partial batch | 15 |
| CERT_CHECK_WEBHOOK_URL | Destination for batched suspicious/revoked findings | unset |
| CERT_CHECK_WEBHOOK_SECRET | HMAC-SHA256 signing secret (header `X-Signature`) | unset |
| CERT_CHECK_WEBHOOK_MAX_ATTEMPTS | Max retry attempts for failed webhook batches | 5 |

Durable Retry: Failed batches are stored in sqlite table `webhook_batches` and retried opportunistically on subsequent flush cycles until success or attempt limit reached.

Metrics (Prometheus):
| Metric | Description |
|--------|-------------|
| cert_checks_processed_total | Total cert fingerprints processed |
| cert_checks_errors_total | Errors during individual CT/OCSP operations |
| cert_checks_webhook_sent_total | Successful webhook batches (including retries) |
| cert_checks_latency_seconds | Histogram of individual CT/OCSP call latencies |

API Endpoint:
`GET /api/v1/cert_checks/{fingerprint}` returns `{ fingerprint, cached: bool, status, last_checked, details }` or `cached:false` when absent/stale.

Frontend Integration:
- `certificate_analysis` and `network_hunter` enqueue cert fingerprints; cached results instantly enrich factors (`ssl:ct_suspected`, `ssl:revoked_cert`).

Manual Test Snippet (PowerShell):
```powershell
$env:CERT_CHECK_WEBHOOK_URL='http://localhost:8001/mock'
$env:CERT_CHECK_WEBHOOK_SECRET='devsecret'
python - <<'PY'
from src.integrations import cert_checks as cc
cc.queue_cert_check('flag-cert-demo')
cc.start_worker(background=False)
cc._flush_batch_if_needed(force=True)
print(cc.get_cert_check('flag-cert-demo'))
PY
```

## Mailbox OAuth & Polling Setup

Follow these steps to register OAuth apps, configure secrets, and validate the hardened polling worker:

1. **Register client apps**
   - *Microsoft Graph*: create an app registration with `Mail.Read` + `offline_access`. Record `MSGRAPH_CLIENT_ID`, `MSGRAPH_CLIENT_SECRET`, and set `MSGRAPH_REDIRECT` (e.g., `http://localhost:8080/api/v1/integrations/oauth/msgraph/callback`).
   - *Google Workspace / Gmail*: create OAuth credentials with Gmail read-only scope. Record `GMAIL_CLIENT_ID`, `GMAIL_CLIENT_SECRET`, and set `GMAIL_REDIRECT`.

2. **Pick a secret backend**
   Set `SECRET_BACKEND` (alias `SECRET_MANAGER_BACKEND`) to one of:
   - `tenant` *(default)* – encrypted file store under `data/tenant_store`.
   - `vault` – requires `VAULT_ADDR`, `VAULT_TOKEN`, and optional `VAULT_KV_MOUNT`.
   - `azure` – requires `AZURE_KEY_VAULT_URL` and `AZURE_KEY_VAULT_TOKEN` (Bearer token or MSI).
   Missing env vars automatically fall back to the file backend. For CI/tests you can use `SECRET_BACKEND=memory`.

3. **Run OAuth start/callback**
   Call `/api/v1/integrations/oauth/{msgraph|gmail}/start?tenant_id=demo` to obtain the authorization URL, complete the flow, then hit `/callback` which persists tokens via the selected backend. Tokens now include `client_id`, `client_secret`, and `expires_at`.

4. **Configure the polling worker**
   - `POLLING_MAX_ATTEMPTS` (default `5`) and `POLLING_BACKOFF_BASE` (default `1.0`) control exponential backoff with jitter.
   - `POLLING_TENANT_RATE_CAPACITY`, `POLLING_TENANT_RATE_REFILL`, `POLLING_TENANT_RATE_TTL` feed the per-tenant token bucket leveraging the core `RateLimiter`. Set capacity/refill to `0` to disable throttling.
   - The worker automatically persists `delta_link` (MS Graph) and `history_id` (Gmail) inside `data/polling_state` or the directory defined by `POLLING_STATE_DIR`.

5. **Validate polling**
   Run `python -m integrations.polling_worker TENANT_ID msgraph --loop` (or `gmail`). The worker now:
   - Applies exponential backoff with jitter on HTTP 429/5xx responses.
   - Detects token revocation (401) and clears tenant secrets so operators can restart the OAuth flow.
   - Respects per-tenant rate limits before hitting provider APIs or pipelines.
   - Stores `deltaLink`/`historyId` to drive incremental syncs and reports missing telemetry in logs.

6. **Run focused tests**
   ```bash
   pytest tests/test_oauth_router.py
   pytest tests/test_polling_worker.py
   ```
   These tests exercise the OAuth router, secret backend toggle, and polling worker behaviors (backoff, state persistence, revocation handling).

7. **Exercise secret backend swaps**
   ```bash
   pytest tests/test_secret_backends.py
   ```
   This suite covers Vault/Azure integrations plus the fallback path so you can confirm `SECRET_BACKEND` and related env vars are wired correctly before enabling Vault or Key Vault in staging.

Use the `PIPELINE_ENDPOINT` env var to post processed events to your ingestion API; otherwise the worker appends CSV rows under `data/polled_events/`.
