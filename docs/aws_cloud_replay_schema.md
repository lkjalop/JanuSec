# AWS Cloud Replay Schema

Use this schema when uploading AWS export files through [cloud_replay.html](C:/AI/janusec/frontend/static/cloud_replay.html).

## Required Upload Metadata

- `tenantId`: account label such as `aws-123456789012`
- `provider`: `aws`
- Per-file `source_kind`

## Supported `source_kind` Values

- `cloudtrail`
- `iam_policy_history`
- `guardduty`
- `securityhub`
- `config_history`
- `vpc_flow`
- `resource_access`
- `mailbox_trace`
- `click_telemetry`

## Minimum Fields By Source

### `cloudtrail`
- `eventTime`
- `eventName`
- `eventSource`
- `sourceIPAddress`
- `userIdentity`
- `recipientAccountId`

### `iam_policy_history`
- `eventTime`
- `eventName`
- `userIdentity`
- `requestParameters`
- `responseElements`

### `guardduty`
- `id`
- `type`
- `severity`
- `accountId`
- `service.eventFirstSeen`

### `securityhub`
- `Id`
- `Title`
- `Severity`
- `Resources`
- `UpdatedAt`

### `config_history`
- `resourceType`
- `resourceId`
- `configurationItemStatus`
- `complianceType`
- `configurationItemCaptureTime`

### `vpc_flow`
- `start`
- `srcaddr`
- `dstaddr`
- `dstport`
- `action`
- `bytes`

## Expected Response Shape

The analysis response should expose both nested and flattened fields:

- `final_verdict`
- `final_confidence`
- `severity`
- `semantic_top_factors`
- `supporting_model_factors`
- `upload_provenance`
- `risk_quantification`
- `decision_record.hopgraph_context`

## Scrutiny Checks

A valid AWS replay should let the reviewer answer:

1. Is the evidence connected or isolated?
2. Which provider-native findings outrank raw telemetry?
3. What would falsify the current theory?
4. What follow-on provider logs should be pulled next?
