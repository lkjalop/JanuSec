## Azure Live Validation Runbook

### Preconditions
- Server running with `PROD_SCOPE=azure_cloud_funnel`
- Valid API key
- Real Azure tenant configured for:
  - `entra_signin`
  - `entra_audit`
  - `defender_cloud`

### Validation Command
```powershell
python scripts/live_connector_validation.py `
  --base http://localhost:8080 `
  --api-key devkey123 `
  --tenant-id <tenant-id> `
  --scope azure `
  --since-seconds 86400 `
  --limit 100 `
  --out data/validation/azure_validation.json
```

### What Must Pass
- Connector config exists and is accepted
- Status shows connected/healthy
- Poll/checkpoint calls advance
- Poll returns non-zero live events
- `decisions_emitted` is greater than zero for suspicious Azure events
- `/api/v1/decisions/recent` shows:
  - `hopgraph_context`
  - `dependency_status`
  - `evidence_summary`
  - `approval_state`

### Gold Scenario 1
- Suspicious Entra sign-in
- Expected evidence:
  - unusual IP / geo / risk state
  - `risk:*` in `risk_signals`
  - decision verdict `suspicious`
  - Tier 1 summary explains identity risk

### Gold Scenario 2
- Entra privilege or policy change
- Expected evidence:
  - audit action containing role/admin/privilege/policy/credential signal
  - `privilege_change` in `risk_signals`
  - decision verdict `suspicious`
  - analyst approval required

### Gold Scenario 3
- Defender for Cloud high-severity finding
- Expected evidence:
  - severity `high` or `critical`
  - decision verdict `bad`
  - recommendation action present
  - evidence coverage and dependency badges visible in the LIVE console

### Demo Capture
- Record:
  - connector health
  - ingest counts
  - one recent decision per scenario
  - Tier 1 summary
  - approval state
  - recommended action
