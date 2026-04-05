# Email Pull Connectors (Delivery/Click/Quarantine)

The log-pull endpoints for email evidence (`/api/v1/email/delivery/pull`, `/api/v1/email/click/pull`, `/api/v1/email/quarantine/pull`) will return empty arrays unless the relevant connectors are configured.

## Required environment variables

### Delivery (O365/Gmail collectors)
- `O365_TENANT`
- `O365_CLIENT_ID`
- `O365_CLIENT_SECRET`
- `O365_USER_ID`

- `GMAIL_SERVICE_ACCOUNT_JSON` (service account file path) or delegated token flow
- `GMAIL_USER_ID` (optional, default `me`)

### Quarantine (Abnormal/Mimecast/Defender)
- Abnormal:
  - `ABNORMAL_CLIENT_ID`
  - `ABNORMAL_CLIENT_SECRET`
  - `ABNORMAL_BASE_URL` (optional override)
  - `ABNORMAL_TOKEN_ENDPOINT` (optional override)
  - `ABNORMAL_ALERTS_ENDPOINT` (optional override)

- Mimecast:
  - `MIMECAST_CLIENT_ID`
  - `MIMECAST_CLIENT_SECRET`
  - `MIMECAST_BASE_URL` (optional override)
  - `MIMECAST_TOKEN_ENDPOINT` (optional override)
  - `MIMECAST_DETECTIONS_ENDPOINT` (optional override)

- Defender for O365:
  - `DEFENDER_TENANT_ID` (or `AZURE_TENANT_ID`)
  - `DEFENDER_CLIENT_ID` (or `AZURE_CLIENT_ID`)
  - `DEFENDER_CLIENT_SECRET` (or `AZURE_CLIENT_SECRET`)

### Click telemetry
Click pulls read from the persisted click store (`data/clicks.db`). Configure inbound click webhooks so clicks are stored before pulling:
- `/api/v1/webhooks/email/*` (see `src/api/routes/email_webhooks.py`)

## Notes
- All pull endpoints require `x-api-key` and tenant headers (`X-Tenant-Id`) in production.
- If these connectors are not configured, the endpoints return `events: []` but still emit custody metadata for chain-of-custody.
