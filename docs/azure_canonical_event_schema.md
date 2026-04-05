## Azure Canonical Event Schema

All Azure launch-scope events should normalize into the same shape before correlation.

### Required Fields
- `tenant_id`
- `source`
- `event_type`
- `event_ts`
- `user`
- `ip`
- `resource`
- `action`
- `factors`
- `risk_signals`
- `raw_ref`

### Normalized Sources
- `azure_entra_signin`
- `azure_entra_audit`
- `azure_defender_cloud`
- `azure_eventhub`

### Compatibility Fields
The normalizer may also preserve source-specific fields for existing consumers:
- `ts`
- `provider`
- `actor`
- `status`
- `operation`
- `resource_id`
- `subscription_id`
- `severity`
- `title`
- `category`
- `correlation_keys`

### Launch Intent
This schema exists to keep the Azure-only funnel consistent across:
- connector ingestion
- HopGraph correlation
- decision recording
- Tier 1 summaries
- LIVE console rendering
