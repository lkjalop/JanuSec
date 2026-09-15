# Real Tenant Validation Runbook

## Goal

Validate the Azure-first cloud triage workflow with:

1. Exported tenant replay packs
2. One live Azure tenant connector validation
3. LIVE console operator checks

## Start The Platform

Preferred local start:

```powershell
$env:PROD_SCOPE="azure_cloud_funnel"
python start_simple.py --no-reload --port 8080
```

Repo launcher still works:

```powershell
start_server.bat
```

## Export Replay Validation

Azure export pack example:

```powershell
python scripts/offline_replay_harness.py `
  tests\fixtures\export_packs\azure_realish_tenant `
  --mock-llm `
  --out dump\azure_export_pack_report.json
```

AWS export pack example:

```powershell
python scripts/offline_replay_harness.py `
  tests\fixtures\export_packs\aws_realish_tenant `
  --mock-llm `
  --out dump\aws_export_pack_report.json
```

Combined validation through the live validation helper:

```powershell
python scripts/live_connector_validation.py `
  --tenant-id contoso-demo `
  --scope azure `
  --azure-export-pack tests\fixtures\export_packs\azure_realish_tenant `
  --out dump\azure_validation_report.json
```

## Expected Export Replay Checks

- `semantic_top_factors` should lead with cloud or identity factors, not generic ML factors.
- `supporting_model_factors` should contain isolation-forest / TF-IDF / DBSCAN support.
- `decision_record.hopgraph_context.edges` should be populated for correlated chains.
- `tier_metadata.calibration_status.live_labeled_corpus` should remain `false` until real labeled samples exist.

## Live Azure Connector Validation

Current live connector coverage in the control plane:

- `entra_signin`
- `entra_audit`
- `defender_cloud`
- `eventhub`

Current export-only validation coverage:

- Conditional Access
- Identity Protection
- Azure Activity Log
- NSG flow

Run:

```powershell
python scripts/live_connector_validation.py `
  --tenant-id <tenant> `
  --scope azure `
  --since-seconds 3600 `
  --out dump\live_azure_connector_validation.json
```

## LIVE Console Operator Workflow

Open:

- `http://localhost:8080/`

Check:

1. connector status is visible and healthy
2. recent decisions exist for the tenant
3. evidence summary is present
4. semantic factors lead the incident story
5. approval state is visible
6. Tier 2 is either real and configured or hidden

## Push / Commit Sequence

1. Commit offline replay + validation tooling locally.
2. Replay one exported Azure tenant pack.
3. Run one live Azure validation.
4. Fix any evidence gaps found in LIVE.
5. Push branch and open review.
