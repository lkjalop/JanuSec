# DLQ Operator Runbook

1) Provision infra (Terraform)

 - Create `terraform.tfvars` in `infra/terraform/` with:

```
dlq_bucket_name = "your-dlq-bucket"
dlq_queue_name  = "your-dlq-queue"
region = "us-east-1"
dlq_retention_days = 90
```

 - Run:

```bash
cd infra/terraform
terraform init
terraform apply -var-file=terraform.tfvars
```

2) Extract outputs for app configuration

 - After `apply`, note outputs:
   - `dlq_s3_bucket` -> set `DLQ_S3_BUCKET`
   - `dlq_sqs_url` -> set `DLQ_SQS_URL`
   - `dlq_kms_arn` -> set `DLQ_S3_SSE_KMS_KEY`

3) Deploy app with env vars (example systemd env or Kubernetes secret)

 - Example env vars:

```
DLQ_S3_BUCKET=your-dlq-bucket
DLQ_SQS_URL=https://sqs.us-east-1.amazonaws.com/123456789012/your-dlq-queue
DLQ_S3_SSE_KMS_KEY=arn:aws:kms:us-east-1:123456789012:key/abcd-ef01
AWS_ASSUME_ROLE_ARN=arn:aws:iam::123456789012:role/janusec_connector_role
```

4) Drain procedure

 - Operators can use `scripts/drain_writeback_dlq.py` to attempt reposts.
 - For S3 retention policy, decided policy: Move to `archive/` prefix on success (recommended) or delete (configurable in drain script).

5) Alerting

 - Configure alerts for:
   - SQS ApproximateNumberOfMessagesVisible high
   - S3 put_object errors
   - KMS permission errors
