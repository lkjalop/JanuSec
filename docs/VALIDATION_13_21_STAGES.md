# JanuSec Pipeline Stages 13–21: Validation Plan (Azure-Ready)

Purpose: provide a reproducible way to validate stages 13–21 of the event pipeline and demonstrate detection capability for APT tradecraft, Living-off-the-Land (LOLbins), credential misuse, HopGraph attack reconstruction, and cost/FinOps metrics. The plan runs on Azure Pipelines or locally and emits a Markdown report artifact summarizing what passed, what failed, and next steps.

Pipeline stage ordering comes from `src/core/event_pipeline/stages/__init__.py`.

Stages 13–21
- 13 `beacon` – network beaconing/cadence detection
- 14 `egress` – exfil patterns and port scatter anomalies
- 15 `domain_novelty` – rare/new domains, DNS anomalies
- 16 `rare_token` – rare command/token ratios (LOLbins & suspicious cmds)
- 17 `hunt_lanes` – lane-specific hunters (e.g., JA3 novelty, process lineage)
- 18 `correlation` – multi-factor rule engine, sequences and campaigns
- 19 `quality_filter` – factor precision tracking and suppression
- 20 `mapping` – factor→MITRE ATT&CK mapping and report tags
- 21 `cluster_dedupe` – similarity/dedup (cluster markers)

How to run (local)
- Prereqs: Python 3.10+ and `pip`.
- Commands:
  - `pip install -r requirements.txt -r requirements-dev.txt`
  - `python scripts/generate_stage_validation_report.py --preset full --out artifacts/pipeline_13_21_validation_results.md`
- Output:
  - Markdown report at `artifacts/pipeline_13_21_validation_results.md` with per-stage coverage, per-threat coverage, pass/fail tallies, and next steps.

How to run (Azure Pipelines)
- Add `azure-pipelines.yml` from repo root (see file for full CI config).
- The pipeline publishes `validation-report.md` and JUnit XML as build artifacts.

Threat coverage (examples and where validated)
- APT & multi-stage: correlation and incident aggregation
  - Tests: `tests/test_correlation_rules*.py`, `tests/test_campaign_correlation.py`, `tests/test_incident_aggregator.py`
  - Stages: correlation (18), mapping (20), cluster_dedupe (21)
- Living-off-the-Land (LOLbins): office macro → PowerShell, scheduled task, signed-binary-proxy
  - Tests: `tests/test_week1_rules.py`, `tests/test_week2_rules.py`, `tests/test_lolbin_tfidf_basic.py`, `tests/test_lolbin_tfidf_tokenizer.py`, `tests/test_report_mitre_tags.py`
  - Stages: rare_token (16), correlation (18), mapping (20)
- Credential misuse: valid accounts, LSASS openprocess bursts, auth bursts
  - Tests: `tests/test_week2_rules.py`, `tests/test_t1078_t1133_rules.py`, `tests/test_auth_smoke.py`, `tests/test_baseline_service.py`
  - Stages: correlation (18), mapping (20); earlier stage 5 `auth_burst` contributes factors
- HopGraph attack reconstruction & explain
  - Tests: `tests/test_hopgraph_*.py`, `tests/test_graph_explain_api.py`, `tests/test_graph_trace_endpoints.py`, `tests/test_graph_enrichment_pipeline.py`
  - Stages: graph (6 upstream), hunt_lanes (17), correlation (18), mapping (20)
- Cost/FinOps metrics: cost ledger, summaries, forecasts
  - Tests: `tests/test_finops_endpoints.py`, `tests/test_finops_cost_summary.py`, `tests/test_metrics_guard.py`, `tests/test_server_metrics.py`
  - Modules: `src/core/finops/*`, exposed via `/api/v1/finops/*`

AI techniques used (by stage)
- Beacon (13):
  - Low-jitter periodicity via coefficient-of-variation windowing (`src/modules/network_hunter.py`), optional Lomb–Scargle path when SciPy present (tested in `tests/test_beacon_lomb_scargle.py`).
- Egress (14):
  - Heuristics for vertical/horizontal port scatter and exfil cadence (`src/modules/network_hunter.py`).
- Domain Novelty (15):
  - Frequency baselining of SLDs and DNS entropy heuristics (`src/modules/network_hunter.py`).
- Rare Token (16):
  - Token-frequency modeling on cmdlines; rare-ratio thresholds for anomaly (`src/core/detect/rare_token_detector.py`).
- Hunt Lanes (17):
  - Lane-specific novelty (e.g., JA3 rarity) and process lineage patterns (`src/core/hunt/lanes/*`).
- Correlation (18):
  - Rule-based multi-factor correlation with MITRE tags and scenarios (`src/core/correlation/rules/*`).
- Quality Filter (19):
  - Online precision tracking to suppress high-FP factors (`src/core/quality/factor_quality.py`).
- Mapping (20):
  - Deterministic factor→MITRE mapping (`src/core/mappings/factor_to_mitre.py`).
- Cluster/Dedupe (21):
  - Hash-based signature of factor sets, first/duplicate/repeated markers (`src/core/correlation/cluster_dedupe.py`).

Report contents (what you get)
- Overall summary: pass/fail/error/skip counts
- Stage coverage table (13–21): tests discovered, pass/fail tallies
- Threat coverage table: APT, LOLbins, credentials, hopgraph, cost/FinOps
- Notable factors observed (from test names/fixtures) and linked modules
- Next steps (auto-generated): retry guidance, gaps, and suggested follow-ups

Quick smoke (subset) if time-constrained
- `python scripts/generate_stage_validation_report.py --preset smoke --out artifacts/pipeline_13_21_validation_results.md`
  - Runs: beacon, hunt_lanes, correlation, mapping, finops, hopgraph core tests only

Integrations and dashboards (optional live checks)
- After `scripts/start_server.ps1`, open:
  - Console: `http://localhost:8080/` (LIVE console)
  - Metrics: `http://localhost:8080/metrics` (check stage latency, finops counters)
  - Report: `/api/v1/report/ingestion?format=html&include_model=true&include_scenarios=true`

Next steps (typical)
- If stage coverage gaps remain, expand the test glob mapping in `scripts/generate_stage_validation_report.py`.
- For cluster_dedupe explicit validation, add a micro-test for `cluster_mark()` if needed.
- To include runtime latency stats, run the server and have the script scrape `/metrics` and embed top lines in the report (flag `--include-metrics`).

