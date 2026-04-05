# Monitoring: Enrichment Scheduler

This folder contains a Grafana dashboard and alerting rules for the enrichment scheduler.

Files:

- `grafana/enrichment_dashboard.json` - initial dashboard skeleton.
- `grafana/enrichment_dashboard_grafana9.json` - ready-to-import JSON for Grafana 9+ (includes folder metadata and panel UIDs).
- `grafana/alerts/enrichment_alerts.yml` - Prometheus alerting rules skeleton.

Prometheus scrape config
------------------------

Add a scrape job for the enrichment service. Example `prometheus.yml` snippet:

```yaml
scrape_configs:
  - job_name: 'threat_thy_sniffer_enrichment'
    static_configs:
      - targets: ['127.0.0.1:8000']
        labels:
          service: 'enrichment'
    metrics_path: '/metrics'
    scheme: 'http'
    # If your app is behind auth or uses a bearer token, add relabeling / basic_auth here
```

Notes:
- Ensure your enrichment service exposes Prometheus metrics at `/metrics` using `prometheus_client` or equivalent.
- The dashboard expects the following metrics to be present:
  - `enrich_scheduler_jobs_migrated` (counter or gauge)
  - `enrich_scheduler_rate_drops_total` (counter)
  - `enrich_scheduler_run_errors_total` (counter)

Importing the Dashboard (Grafana 9+)
----------------------------------

1. In Grafana, go to "Dashboards > Manage > Import".
2. Upload `enrichment_dashboard_grafana9.json` or paste its contents.
3. Select the Prometheus data source when prompted (or ensure the `datasource` field matches your Prometheus name).
4. Import into the folder named "Enrichment" (the JSON sets `folderName`).

Alerting
--------

The provided `grafana/alerts/enrichment_alerts.yml` is a Prometheus-style rule file. Deploy it to your Prometheus `rule_files` path and reload Prometheus.

Questions / Next steps
- I can add Grafana panel thresholds, annotations, and linked drilldowns.
- If you provide your Grafana version and data source name, I will tailor the JSON to match exact expected schema and data source names.

Prometheus metrics added by the durable DLQ module
-------------------------------------------------

- `writeback_dlq_s3_backup_success_total` (counter): successful S3 backups
- `writeback_dlq_s3_backup_failure_total` (counter): failed S3 backups
- `writeback_dlq_sqs_send_success_total` (counter): successful SQS sends
- `writeback_dlq_sqs_send_failure_total` (counter): failed SQS sends
- `writeback_dlq_depth` (gauge): approximate number of queued messages (SQS approx)

Scrape example (prometheus.yml):

```yaml
scrape_configs:
  - job_name: 'janusec_app'
    static_configs:
      - targets: ['localhost:8080']
```

