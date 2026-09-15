DLQ Recovery Runbook

Purpose
- Describe steps for operators to inspect, replay, and restore DLQ items stored in S3 and referenced by SQS pointers.

Prerequisites
- AWS CLI configured with appropriate permissions for S3/KMS/SQS as described in infra/terraform/dlq_main.tf
- Environment variables: DLQ_S3_BUCKET, DLQ_SQS_URL, DLQ_ARCHIVE_PREFIX (default: archive/)

Common Tasks

1) Inspect queue depth
- Get approximate number of messages in SQS (visible + not-visible):

```powershell
aws sqs get-queue-attributes --queue-url $env:DLQ_SQS_URL --attribute-names ApproximateNumberOfMessages,ApproximateNumberOfMessagesNotVisible
```

2) List objects in DLQ S3 bucket

```powershell
aws s3 ls s3://$env:DLQ_S3_BUCKET/ --recursive | sort
```

3) Replay a single S3 object (by key)
- Download object, optionally apply idempotency filtering, then POST to the configured ingest endpoint.

```powershell
$key = "dlq/2025-12-01-...json"
aws s3 cp s3://$env:DLQ_S3_BUCKET/$key .
# replay using curl (example)
curl -X POST -H "Content-Type: application/json" --data-binary @${key} https://your-ingest-endpoint.local/api/v1/ingest
```

4) Batch drain from S3 (example scripted approach)
- A recommended script `scripts/dlq_drain_s3.py` can be added to iterate over objects, re-post, and optionally move to archive/ or delete on success.

5) Move object to archive prefix (if not already)

```powershell
aws s3 mv s3://$env:DLQ_S3_BUCKET/$key s3://$env:DLQ_S3_BUCKET/$env:DLQ_ARCHIVE_PREFIX$key
```

6) Set retention tag for an object (TTL days)

```powershell
# Example: set retention tag 'retention_days=90' for object
aws s3 put-object-tagging --bucket $env:DLQ_S3_BUCKET --key $key --tagging 'TagSet=[{Key=retention_days,Value=90}]'
```

Notes & Best Practices
- Prefer replaying from S3 rather than from SQS pointer payloads when objects are large or when you need idempotency checks.
- Use `DLQ_ARCHIVE_ON_SUCCESS=true` in combination with the S3 lifecycle rule for `archive/` prefix to keep a copy for forensic purposes before deletion.
- Add monitoring on the `writeback_dlq_depth` Prometheus gauge and alert when it grows above your normal thresholds.
