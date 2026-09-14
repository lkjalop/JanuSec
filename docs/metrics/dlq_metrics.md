DLQ Metrics and Alerts

Metrics exposed by the DLQ components (Prometheus):

- `writeback_dlq_s3_backup_success_total`: Counter of successful S3 backups.
- `writeback_dlq_s3_backup_failure_total`: Counter of failed S3 backups.
- `writeback_dlq_sqs_send_success_total`: Counter of successful SQS pointer sends.
- `writeback_dlq_sqs_send_failure_total`: Counter of failed SQS pointer sends.
- `writeback_dlq_s3_archive_total`: Counter of successful archive operations (copy -> delete).
- `writeback_dlq_s3_delete_total`: Counter of S3 deletes performed by drain/archive.
- `writeback_dlq_depth`: Gauge representing current DLQ backlog depth (ingest queue length or SQS approximate count).

Suggested alerts (Prometheus rule examples):

1) High DLQ Depth

- Alert: `DLQHighDepth`
- Expr: `writeback_dlq_depth > 100`
- For: `10m`
- Labels: `severity=warning`
- Summary: "DLQ backlog high: {{ $value }} messages"

2) S3 Backup Failures Spike

- Alert: `DLQS3BackupFailures`
- Expr: `rate(writeback_dlq_s3_backup_failure_total[5m]) > 0.1`
- For: `5m`
- Summary: "DLQ S3 backup failures detected"

3) Archive Failures / Deletes Unexpected

- Alert: `DLQArchiveAnomaly`
- Expr: `rate(writeback_dlq_s3_archive_total[5m]) == 0 and writeback_dlq_depth > 50`
- For: `10m`
- Summary: "No archive operations despite backlog" (investigate permissions/KMS)

Dashboards
- Add a small DLQ dashboard panel with the following charts:
  - `writeback_dlq_depth` (time series)
  - `writeback_dlq_s3_backup_success_total` / `_failure_total` (rates)
  - `writeback_dlq_sqs_send_success_total` / `_failure_total` (rates)
  - `writeback_dlq_s3_archive_total` (time series)

Notes
- Ensure the Prometheus client is initialized early in the application runtime and the `/metrics` endpoint is reachable by the Prometheus server.
- Tune thresholds (100 messages, 0.1 failure rate) to match your operating baseline.
