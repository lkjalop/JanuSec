Missing Logs Checklist — AWS

Use this checklist when connectors or pipeline factors indicate missing telemetry.

1) CloudTrail
- Ensure CloudTrail is enabled for all regions (multi-region trail recommended).
- Request access to CloudTrail S3 bucket or API `LookupEvents`.
- Ask for data events for S3 and Lambda (if you need object-level access).

2) VPC Flow Logs
- Confirm VPC Flow Logs are enabled for critical VPCs/subnets.
- Request S3 bucket access or CloudWatch Logs subscription for flow logs.

3) CloudWatch Logs
- Identify relevant Log Groups (application, lambda, auth components).
- Request permission to read and set subscription filters or export streams.

4) S3 Access Logs & Inventory
- Ask whether S3 Access Logs are enabled; if not, request enabling or provide access to existing logs.
- Request S3 Inventory generation for large buckets for object metadata.

5) GuardDuty & Security Hub
- Ensure GuardDuty is enabled and provide read access to findings and detectors.
- Enable Security Hub aggregation and grant read access.

6) Config & Resource Snapshots
- Request AWS Config snapshots or read access to `GetResourceConfigHistory`.

7) IAM & CloudFormation events
- Request CloudTrail access for `iam:*` and `cloudformation:*` events; ensure policy-change events are logged.

8) Other
- Provide list of CI/CD systems and where deployment events are recorded.

Request template (short):
- "Please grant the monitoring role `arn:aws:iam::MONITOR_ACCOUNT_ID:role/INGESTOR_ROLE` the following read-only permissions: CloudTrail LookupEvents, S3 GetObject/ListBucket on buckets: [list], CloudWatch Logs Read, GuardDuty GetFindings, Config GetResourceConfigHistory. Also enable CloudTrail data events for S3 and Lambda where feasible."
