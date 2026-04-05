# AWS Hardening & Production Checklist

This document outlines concrete steps to bring AWS connectors and ingestion to production parity with the Azure deployment.

P0 (2 weeks, critical)
- Security Hub connector hardening
  - Implement resilient ingestion with retries, exponential backoff, and a durable DLQ (use `src/integrations/resilient_ingest.py` and `src/core/writeback_dlq.py`).
  - Add mapping tests for Security Hub findings → platform factors (unit tests under `tests/`)
  - Ensure idempotency keys on batches (use `src/core/idempotency.py` when writing to ingestion API)

- CloudTrail multi-account ingestion
  - Implement cross-account S3 aggregation + AssumeRole automation
  - Add canonical normalization (see `src/integrations/cloudtrail_adapter.py`) and large-file backpressure handling

- DLQ Monitoring & Operator Tools
  - Add DLQ drain runner as a cron or maintenance job (`scripts/drain_writeback_dlq.py`)
  - Add Prometheus metrics for DLQ length and failed reposts

P1 (4-8 weeks)
- Performance & Load
  - Add SQS/Kinesis buffering for spikes; set proper retention + redrive policies
  - Add 1k req/s load-test harness (see `load_tests/locustfile.py`) and CI gating

- Security Controls
  - Enforce IAM least privilege for connectors and assume-role policies
  - Use KMS CMKs for S3 + RDS encryption; rotate keys via policies

- Observability
  - Instrument CloudWatch exporter / Prometheus sidecar to scrape ingress metrics
  - Add Grafana dashboards for ingestion latency, batch size, DLQ depth

Implementation pointers & code locations
- `src/integrations/security_hub_adapter.py` - scaffolded connector using resilient_post
- `src/integrations/cloudtrail_adapter.py` - canonicalizer and local file ingestion example; now wired to resilient_post
- `src/integrations/resilient_ingest.py` - helper that wraps post attempts and writes to DLQ on repeated failure
- `src/core/writeback_dlq.py` - simple file-backed DLQ for operator recovery. Consider replacing with S3/Redis-backed durable queue in production.
- `scripts/drain_writeback_dlq.py` - operator tool to retry failed writebacks

Quick operator checklist
1. Provision IAM role for connector with least privileges.
2. Deploy connector with environment variables: `PLATFORM_API_BASE`, `PLATFORM_API_KEY`, `TENANT_ID`.
3. Enable DLQ drain as a scheduled job and subscribe alerts for DLQ > 10 items.
4. Run load tests and tune batch sizes and concurrency.
