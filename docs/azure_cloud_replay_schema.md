# Azure Cloud Replay Schema

Use this schema when uploading Azure export files through [cloud_replay.html](C:/AI/janusec/frontend/static/cloud_replay.html).

## Required Upload Metadata

- `tenantId`: human-readable tenant label such as `contoso-dev`
- `provider`: `azure`
- Per-file `source_kind`

## Supported `source_kind` Values

- `entra_signin`
- `entra_audit`
- `conditional_access`
- `identity_protection`
- `defender_incident`
- `activity_log`
- `keyvault_access`
- `nsg_flow`
- `mailbox_trace`
- `click_telemetry`
- `resource_access`

## Minimum Fields By Source

### `entra_signin`
- `createdDateTime`
- `userPrincipalName`
- `appDisplayName`
- `ipAddress`
- `status`

### `entra_audit`
- `activityDateTime`
- `activityDisplayName`
- `initiatedBy`
- `targetResources`
- `result`

### `conditional_access`
- `createdDateTime`
- `userPrincipalName`
- `policyName`
- `result`

### `identity_protection`
- `detectedDateTime`
- `userPrincipalName`
- `riskType`
- `riskLevel`

### `defender_incident`
- `incidentId`
- `title`
- `severity`
- `createdDateTime`
- `alerts`

### `activity_log`
- `time`
- `operationName`
- `caller`
- `resourceId`
- `correlationId`

### `keyvault_access`
- `time`
- `caller`
- `vaultName`
- `operationName`
- `secretName`

### `nsg_flow`
- `time`
- `srcIp`
- `destIp`
- `destPort`
- `protocol`
- `flowState`
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

A valid Azure replay should let the reviewer answer:

1. Is the evidence connected or isolated?
2. Which provider-native records support the theory?
3. What evidence is inferred vs confirmed?
4. What logs are still missing?
