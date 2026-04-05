# Threat → AI Technique Mapping (Executive Summary)

This summary maps key security scenarios to concrete AI/analytic techniques and code locations in JanuSec.

APT / Multi-Stage Campaigns
- Techniques: multi-factor correlation rules + scenario engine; hopgraph path context; incident aggregation.
- Modules: `src/core/correlation/rules/*`, `src/core/threat_modeling/scenario_engine.py`, `src/incidents/aggregator.py`, `src/graph/hopgraph.py`.
- Evidence: tests `tests/test_correlation_rules*.py`, `tests/test_campaign_correlation.py`, `tests/test_incident_aggregator.py`.

Living-off-the-Land (LOLbins)
- Techniques: rare token ratio on command-lines, rule signatures for office→PowerShell and scheduled task abuse, signed-binary proxy patterns.
- Modules: `src/core/detect/rare_token_detector.py`, `src/core/correlation/rules/week1/*`, `src/core/correlation/rules/week2/*`.
- Evidence: tests `tests/test_lolbin_tfidf_*.py`, `tests/test_week1_rules.py`, `tests/test_week2_rules.py`, `tests/test_report_mitre_tags.py`.

Credential Misuse
- Techniques: login burst heuristics (stage 5), LSASS OpenProcess and token theft rules, valid account abuse (T1078) correlation.
- Modules: `src/core/correlation/rules/week2/lsass_openprocess.py`, `src/core/correlation/rules/week2/registry_run_keys.py`, `src/core/correlation/rules/weekX/t1078_valid_accounts.py`.
- Evidence: tests `tests/test_t1078_t1133_rules.py`, `tests/test_week2_rules.py`, `tests/test_auth_smoke.py`.

Beaconing / C2 Cadence
- Techniques: coefficient-of-variation on inter-arrival deltas; optional Lomb–Scargle spectral path when SciPy present; multi-scale heuristics.
- Modules: `src/modules/network_hunter.py`, `src/core/detect/beacon_analyzer.py`.
- Evidence: tests `tests/test_beacon_*.py`, `tests/test_network_hunter.py`.

Egress / Port Scatter / Exfil
- Techniques: rolling per-host port activity windows with vertical/horizontal scatter thresholds; exfil over web patterns.
- Modules: `src/modules/network_hunter.py`.
- Evidence: tests `tests/test_network_header_and_portscan.py`, `tests/test_detection_metrics.py`.

Domain Novelty / DNS Tunneling
- Techniques: SLD frequency baselining; subdomain entropy; DNS QPS rate thresholds.
- Modules: `src/modules/network_hunter.py`.
- Evidence: tests `tests/test_network_hunter.py`, `tests/test_geoip_enrichment.py`.

HopGraph Attack Reconstruction
- Techniques: graph construction from event relations; path discovery; enrichment overlay; explain endpoints.
- Modules: `src/graph/hopgraph.py`, `src/graph/unified.py`, `src/api/graph_endpoints.py`.
- Evidence: tests `tests/test_hopgraph_*.py`, `tests/test_graph_explain_api.py`, `tests/test_graph_trace_endpoints.py`.

MITRE ATT&CK Mapping & Reporting
- Techniques: deterministic factor→technique mapping; report tag injection.
- Modules: `src/core/mappings/factor_to_mitre.py`, `src/analysis/explain_mapping.py`.
- Evidence: tests `tests/test_explain_mapping.py`, `tests/test_report_mitre_tags.py`, `tests/test_report_mitre_styles.py`.

Factor Quality & FP Reduction
- Techniques: online precision tracking with suppression lifecycle; entropy monitoring.
- Modules: `src/core/quality/factor_quality.py`, `src/core/quality/factor_entropy.py`.
- Evidence: tests `tests/test_fp_metrics.py`, `tests/test_detection_metrics.py`.

Cost & FinOps
- Techniques: streaming cost ledger, hourly/daily rollups, simple monthly forecast; Prometheus metrics.
- Modules: `src/core/finops/finops_manager.py`, `src/core/metrics/cost_ledger.py`, `src/api/finops_endpoints.py`.
- Evidence: tests `tests/test_finops_endpoints.py`, `tests/test_finops_cost_summary.py`, `tests/test_server_metrics.py`.

