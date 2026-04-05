Precision & Closed-Loop Metrics Overview
=====================================

This document describes the newly added precision metrics and safe closed-loop scaffolding.

Components added:
- `src/repositories/precision_aggregator.py` – aggregates daily TP/FP from human adjudications (JSONL fallback) into `precision_daily` table.
- `src/repositories/feature_store_repo.py` – lightweight event feature store for deterministic enrichment storage.
- `src/repositories/weight_staging_repo.py` – stage proposed weight deltas for manual review / simulated A/B evaluation.
- `scripts/daily_precision_aggregator.py` – CLI runner to aggregate a day's adjudications.
- `src/api/precision_dashboard.py` – simple API to fetch daily TP/FP rows for dashboarding.

How it works (high-level):
- Human adjudications are appended to `data/precision_metrics.jsonl` by the feedback endpoint (existing). The aggregator reads this file and writes daily aggregates to `precision_daily`.
- Daily aggregator can be scheduled via `DAILY_PRECISION_AGG_ENABLED=1` and runs inside the API process on startup.
- Weight staging allows safe staging of model/rule weight changes; `WeightStagingRepo` stores proposals which must be applied via an operator flow after A/B validation.

Next steps / Recommendations:
- Hook Grafana to the `precision_daily` table (export to Prometheus or pushgateway if preferred).
- Implement a small UI that queries `/api/v1/precision/daily` and renders precision curves and AB comparisons.
- Implement `ClosedLoopManager` to simulate proposed weight deltas against historical feature-store exports before staging.
