DLQ S3 Backup & Archive
=======================

This project supports a durable DLQ backed by S3 with optional SQS pointer messages.

Environment variables
- `DLQ_S3_BUCKET` — S3 bucket used to store DLQ payload bodies (required for S3 backup).
- `DLQ_SQS_URL` — SQS queue URL used to store lightweight pointers to S3 objects.
- `DLQ_S3_SSE_KMS_KEY` — optional KMS key id/arn to enable server-side encryption (aws:kms).
- `DLQ_ARCHIVE_ON_SUCCESS` — when set to `1` or `true`, objects retrieved during operator drains are moved to the archive prefix instead of deleted.
- `DLQ_ARCHIVE_PREFIX` — destination prefix for archived objects (default `archive/`).

Retention and lifecycle
- Use S3 lifecycle rules (via Terraform or console) to expire archived objects after a retention window (e.g. 90 days).

Operator notes
- When `DLQ_ARCHIVE_ON_SUCCESS` is enabled, operator drains will copy the S3 object to the archive prefix and delete the original to avoid reprocessing.
- If archive is not enabled, DLQ objects are deleted after successful drain.

Metrics
- Prometheus counters published: `writeback_dlq_s3_backup_success_total`, `writeback_dlq_s3_backup_failure_total`, `writeback_dlq_s3_archive_total`, `writeback_dlq_s3_delete_total`, and SQS counters. These can be scraped and alerted on for abnormal DLQ activity.
# Durable DLQ (S3 + SQS) Guidance

This document provides example IAM policy snippets, S3 lifecycle, and KMS usage for the durable DLQ implemented in `src/core/durable_dlq.py`.

## Example IAM policy (least privilege)
Grant the service principal access to put/get/delete objects under the `dlq/` prefix and to send/receive messages on the SQS queue.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject"
      ],
      "Resource": ["arn:aws:s3:::my-dlq-bucket/dlq/*"]
    },
    {
      "Effect": "Allow",
      "Action": [
        "sqs:SendMessage",
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes"
      ],
      "Resource": ["arn:aws:sqs:REGION:ACCOUNT:my-dlq-queue"]
    }
  ]
}
```

## S3 Lifecycle rule (expire `dlq/` after X days)

Example lifecycle configuration to expire objects under `dlq/` after 30 days:

```xml
<LifecycleConfiguration>
  <Rule>
    <ID>ExpireDLQ</ID>
    <Prefix>dlq/</Prefix>
    <Status>Enabled</Status>
    <Expiration>
      <Days>30</Days>
    </Expiration>
  </Rule>
</LifecycleConfiguration>
```

## KMS (server-side encryption)

To enable KMS encryption, configure `DLQ_S3_SSE_KMS_KEY` with your KMS key ARN or alias. The code will include `ServerSideEncryption='aws:kms'` and `SSEKMSKeyId` when uploading.

Required KMS permissions on the IAM role:

```json
{
  "Effect": "Allow",
  "Action": [
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:GenerateDataKey"
  ],
  "Resource": ["arn:aws:kms:REGION:ACCOUNT:key/KEY-ID"]
}
```

## Notes
- Ensure the bucket policy allows the role to put objects into the `dlq/` prefix.
- Consider adding CloudWatch alarms for SQS queue growth and S3 lifecycle metrics.
