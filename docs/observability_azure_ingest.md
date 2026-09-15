# Observability: Azure Ingestion

## Metrics (Platform)
- `posture_ingest_total{tenant}`: total posture findings ingested.
- `posture_ingest_lag_seconds{tenant}`: EWMA/average lag between Azure `source_ts` and ingest time.
- Available at `/metrics` from the platform container.

## Dashboards
- Grafana loads `grafana/dashboards/azure_gap_lag.json` via provisioning.
- Key panels:
  - Ingest totals by tenant
  - Ingest lag recent trend by tenant

## Alerts (Prometheus-style)
- Examples in `grafana/alert_rules.example.yaml`:
  - `AzureIngestLagHigh`: lag above threshold
  - `AzureIngestGapNoData`: no findings for N minutes
  - SLO/MTTC examples by tenant

## Tracing & Correlation
- Function/worker sends `X-Request-ID` per chunk; platform logs the same header for correlation.
- DLQ contains failed records; replay updates both totals and lag once successful.

## Suggested SLOs
- < 5 minutes P50 ingest lag during steady state
- No gaps > 15 minutes during business hours (per tenant)

## Tuning
- Increase/decrease `BATCH_MAX` in the Function to balance throughput and API load.
- Use `POST_MAX_RETRIES`, `POST_BACKOFF_BASE`, `PLATFORM_POST_TIMEOUT` to tune retry behavior.
- Cap Event Hub trigger concurrency in `host.json` to control cost.
