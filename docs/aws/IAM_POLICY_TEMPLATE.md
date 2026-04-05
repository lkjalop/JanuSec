IAM Policy Template for Ingestion Role

Use this template to request a cross-account or same-account role for the connector to assume. Tailor actions/resources to the minimum required by the connector(s).

Example role trust policy (resources in the monitoring account should allow this role to be assumed):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::MONITORING_ACCOUNT_ID:role/INGESTOR_ROLE"},
      "Action": "sts:AssumeRole",
      "Condition": {}
    }
  ]
}
```

Example permissions policy (least-privilege example covering CloudTrail + S3 + GuardDuty + CloudWatch + Config + SecurityHub):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect":"Allow","Action":["cloudtrail:LookupEvents","cloudtrail:GetTrailStatus","cloudtrail:DescribeTrails"],"Resource":"*"},
    {"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::YOUR_LOG_BUCKET","arn:aws:s3:::YOUR_LOG_BUCKET/*"]},
    {"Effect":"Allow","Action":["cloudwatch:FilterLogEvents","logs:GetLogEvents","logs:DescribeLogGroups","logs:DescribeLogStreams"],"Resource":"*"},
    {"Effect":"Allow","Action":["guardduty:ListDetectors","guardduty:GetFindings","guardduty:ListFindings","guardduty:DescribePublishingDestination"],"Resource":"*"},
    {"Effect":"Allow","Action":["config:GetResourceConfigHistory","config:ListDiscoveredResources","config:DescribeConfigurationRecorders"],"Resource":"*"},
    {"Effect":"Allow","Action":["securityhub:GetFindings","securityhub:DescribeProducts"],"Resource":"*"},
    {"Effect":"Allow","Action":["iam:ListRoles","iam:GetRole","iam:ListUsers","iam:ListAccessKeys"],"Resource":"*"}
  ]
}
```

Notes:
- Replace `YOUR_LOG_BUCKET` with the bucket(s) containing CloudTrail / VPC Flow Logs.
- If you only use API `LookupEvents` for CloudTrail, S3 read access is not required.
- Consider restricting resources and adding `Condition` blocks (e.g., source IPs, MFA) for additional controls.
