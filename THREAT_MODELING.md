# Threat Modeling & Scenario Layer (STRIDE / DREAD / MAESTRO / PASTA Phase 1)

This document describes the unified threat modeling surfaces now exposed by the platform.

## Overview

## Controls Matrix

This Controls Matrix maps major threat families to implemented controls, where the control is enforced in code, and residual risk notes.

| Threat / Factor | Implemented Control | Code Reference | Residual Risk |
|---|---|---|---|
| Process Injection (T1055) | Pattern-based detection, complexity throttling, timeouts | src/modules/regex_engine.py (_test_pattern, _execute_regex_with_timeout) | May miss novel API usage; signature drift |
| Registry Persistence | Pattern-based detection, category mapping | src/modules/regex_engine.py (pattern definitions) | False positives for benign installers |
| Suspicious Domains | TLD-based heuristics, combined field scanning | src/modules/regex_engine.py, src/core/threat_modeling/factor_taxonomy.py | Evasion via benign-looking domains |
| PowerShell Obfuscation | Encoded command detection, pattern complexity scoring | src/modules/regex_engine.py (_analyze_pattern_complexity) | Obfuscation variants may evade patterns |
| Credential Access Tools | High-confidence pattern matching, scenario overlays | src/modules/regex_engine.py, src/core/threat_modeling/pasta_scenarios.py | Packed/renamed binaries reduce signature match rate |
| Lateral Movement Tools | Process and network pattern correlation | src/modules/regex_engine.py, src/core/event_pipeline/stages/advanced.py | Chaining across hosts requires reliable correlation state |
| Web Shell Indicators | Combined content scanning, scenario mapping | src/modules/regex_engine.py, core/threat_modeling | Large web apps may produce false positives |

Notes:
- Code references are current as of the last commit. When refactoring, ensure the Controls Matrix is updated.
- Residual risk indicates known detection gaps and where additional telemetry or ML-based models would reduce false positives/negatives.

The pipeline emits low-level detection factors. A unified taxonomy layer aggregates these factors into:
- STRIDE categories
- DREAD component averages (1–5) + composite
- MAESTRO / kill-chain phase counts & dominant phase
- PASTA Phase 1 scenarios (higher-level attack narratives)

## Decision Object Enrichment
Each decision (in-memory `DECISION_CACHE`) may now include an optional field:
```
scenarios: [
  {
    id: "SCN-DNS-EXFIL",
    status: "observed" | "weak_signal" | "missing_required" | "not_applicable" | "invalidated",
    matched: { required: [...], any: [...], optional: [...] },
    adjusted_dread: { damage: n, reproducibility: n, ... },
    composite_risk: float,
    pasta_stages: [3,4,5,6],
    tags: ["dns","exfiltration"],
    mitigations: ["..."],
  }
]
```
Feature gated by env var `ENABLE_SCENARIOS` (enabled by default) and visible in report outputs when requested.

## Ingestion Report Extensions
Endpoint: `GET /api/v1/report/ingestion`
Query flags:
- `include_scenarios=true` – adds `scenario_summary` and per-event `scenarios` for flagged/autoblocked.
- `include_model=true` – adds `threat_model_summary` with:
  - `stride_categories`
  - `dread_average_across_events`
  - `maestro_phase_density`

Report version incremented to 3.

## Scenario Report Endpoint
`GET /api/v1/report/pasta`
Returns aggregated scenario statistics across recent decisions.
Parameters:
- `limit_events` (default 500)
- `include_events=true` (optional sample event list)

## Threat Model Aggregate Endpoint
`GET /api/v1/report/threat_model`
Aggregates STRIDE/DREAD/MAESTRO coverage over recent decisions.
Parameters:
- `limit_events` (default 500)

## Metrics (Prometheus)
Provided when `prometheus_client` is available:
- `scenario_matches_total{scenario_id, status}` – Count of scenario evaluations by outcome.
- `scenario_eval_latency_ms` (histogram) – Evaluation latency per decision enrichment cycle.

## Taxonomy Unification
Legacy `core.mappings.mitre_stride.map_factors` is deprecated and now delegates to the unified taxonomy (`aggregate_threat_model`). New development should use the `decision_threat_model` endpoint or the ingestion report with `include_model=true`.

## PASTA Phase 1 Scope
Implemented subset:
- Scenario mapping & risk overlay based on factor sets (Stages 3–6 emphasis)
- DREAD adjustments per scenario
Not yet implemented:
- Asset inventory (Stage 1/2 contextualization)
- Dynamic threat enumeration (Stage 3 automated generation)
- Full vulnerability correlation modeling

## Extending Scenarios
Add new `Scenario` objects in `core/threat_modeling/pasta_scenarios.py` with:
```
Scenario(
  id="SCN-...",
  name="...",
  description="...",
  pasta_stages=[3,4,5],
  required_factors={...},
  any_factors={...},
  optional_factors={...},
  exclusions={...},
  risk_adjustments={"damage":+1},
  mitigation_recs=["..."],
  tags=["..."]
)
```
Restart service (hot reload not yet implemented in Phase 1).

## Backward Compatibility
- No report schema changes unless flags are used.
- Existing clients ignoring new fields remain unaffected.
- Deprecation notice in `mitre_stride.py` for future removal planning.

## Roadmap (Next)
- Hot-reload external taxonomy/scenario config (JSON/YAML)
- Asset criticality weighting in scenario composite risk
- Temporal linkage (scenarios forming chains)
- Coverage dashboard/time-series snapshots

Configuration note:

- `correlation_window_seconds` (int) - Number of seconds to retain recent factor events per host for temporal correlation checks. Default: 300. This is read by `CorrelationEngine` and can be set in the platform config or per-test via the config object.

### Hot-Reload Design (Proposed)
1. Externalize scenarios to `resources/scenarios/*.yaml` and taxonomy to `resources/taxonomy/*.yaml`.
2. File watcher thread (interval 5–10s) computing SHA256 of concatenated file contents.
3. On change:
  - Parse new scenarios into temporary list.
  - Validate required keys and uniqueness of IDs.
  - Swap `ENGINE.scenarios` atomically under a threading lock.
4. Expose reload endpoint `POST /api/v1/threat_modeling/reload` (manual trigger) returning new version hash.
5. Metrics:
  - `scenario_reload_success_total`
  - `scenario_reload_failure_total`
6. Guardrails: max scenarios count (e.g., 200) & per-scenario required/any set size to prevent pathological load.

### Scenario Risk Threshold Factor Injection (Planned)
Goal: Surface a high-level factor (e.g., `scenario:high_risk_dns_exfil`) when composite risk ≥ threshold.
Implementation Sketch:
1. Configure thresholds env vars: `SCENARIO_HIGH_RISK>=3.5`, `SCENARIO_CRITICAL_RISK>=4.2`.
2. After scenario evaluation, for each scenario with status `observed`:
  - If composite ≥ critical: add factor `scenario:critical:{id_lower}`
  - Else if composite ≥ high: add factor `scenario:high:{id_lower}`
3. Ensure factors added before publishing decision SSE (modify `_record_decision`).
4. Prometheus counters: `scenario_risk_flags_total{level}`.
5. Add suppression rule integration (allow tuning if too noisy).
6. Extend ingestion report flagged event rendering to highlight scenario risk factors.

### Grafana Integration (Scenario Metrics)
Example Prometheus queries:
```
sum by (scenario_id) (increase(scenario_matches_total{status="observed"}[5m]))
sum(increase(scenario_matches_total{status="observed"}[1h])) / sum(increase(scenario_matches_total[1h]))
histogram_quantile(0.95, rate(scenario_eval_latency_ms_bucket[5m]))
```
Panel Ideas:
1. Scenario Volume (stacked by status)
2. Top 5 Scenarios by Max Risk (table)
3. Scenario Risk Flag Count (post future risk factor injection)
4. Evaluation Latency p95 / p99

Dashboard JSON seed (excerpt):
```
{
  "title": "Scenarios Overview",
  "panels": [
   {"type":"graph","title":"Scenario Matches (Observed)","targets":[{"expr":"sum by (scenario_id)(increase(scenario_matches_total{status='observed'}[5m]))"}]},
   {"type":"stat","title":"Eval Latency p95","targets":[{"expr":"histogram_quantile(0.95, rate(scenario_eval_latency_ms_bucket[5m]))"}]}
  ]
}
```

---
Document version: 1.0
