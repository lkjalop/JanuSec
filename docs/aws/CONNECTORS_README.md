AWS Connectors - Overview

This folder contains connectors for common AWS telemetry sources. Each connector
is designed to be imported without requiring `boto3` at import time. Use the
`AWSConnectorConfig` in `src.connectors.aws.base` to configure region and
assume-role options.

Quick start example (CloudTrail):

```python
from src.connectors.aws.base import AWSConnectorConfig
from src.connectors.aws.cloudtrail import CloudTrailConnector

cfg = AWSConnectorConfig(role_arn='arn:aws:iam::123456789012:role/ReadOnly', region='us-east-1')
ct = CloudTrailConnector(cfg)
for ev in ct.fetch_events():
    # send to ingestion pipeline
    print(ev)
    # commit progress when appropriate
ct.commit(last_ts=int(time.time()))
```

Checkpointing
- Checkpoints are saved to `data/checkpoints/aws_<connector>.checkpoint.json` by default.
- Implementations should write a stable marker (timestamp or S3 key) to allow safe resume/backfill.

Envelope
- Use `canonical_envelope(raw, source, account_id, region)` to produce a pipeline-friendly dict.

Error handling
- Connectors should catch and log exceptions and avoid raising at import time.

Security
- Prefer cross-account `AssumeRole` to a short-lived ingestion role. Keep IAM permissions as narrow as possible.
