# Webhook & Chat Integration Design

## Overview
This document specifies inbound and outbound webhook plus Slack / Microsoft Teams / WhatsApp (Twilio) notification mechanisms added to the JanuSec platform.

## Goals
- External systems can push artifact observations for analysis (inbound webhook).
- External subscribers receive near real-time notifications about high risk artifact verdicts.
- Analysts can manually push a summarized report to collaboration channels.
- Delivery is reliable (retry/backoff) and secure (HMAC signatures where possible).

## Components
1. Inbound Webhook Endpoint: `POST /api/v1/webhook/ingest`
2. Outbound Subscription Endpoints:
   - `GET /api/v1/integrations/webhooks`
   - `POST /api/v1/integrations/webhooks`
   - `DELETE /api/v1/integrations/webhooks/{id}`
3. Push Report Endpoint: `POST /api/v1/artifacts/push_report`
4. Background Outbound Notifier Worker
5. Chat Integrations (Slack, Teams, WhatsApp) via environment-configured webhooks / Twilio credentials.

## Inbound Webhook
Request:
```
POST /api/v1/webhook/ingest
Headers: X-Signature: <hex-hmac-sha256> (optional if INBOUND_WEBHOOK_SECRET set)
Body JSON:
{
  "artifacts": [ { "sha256": "...", "name": "file.exe", "host": "acme01", ... }, ... ],
  "batch_id": "optional-batch-ref"
}
```
Signature Calculation (if `INBOUND_WEBHOOK_SECRET` present):
```
hex(hmac_sha256(secret, raw_body)) -> X-Signature
```
Response:
```
{ "accepted": N, "processed": N, "suspicious_or_worse": M }
```

Processing Path:
- Artifacts passed to existing `ArtifactPipeline.process_batch`.
- Suspicious/Malicious artifacts enqueue an outbound event `artifact.verdict`.

## Outbound Subscriptions
Subscription JSON schema:
```
{
  "id": "auto-generated if absent",
  "url": "https://example/webhook",
  "secret": "optional-shared-secret",
  "event_types": ["artifact.verdict", "artifact.report.push"],
  "min_risk": 0.70,
  "active": true,
  "max_attempts": 5
}
```
Persistence: `data/webhook_subscriptions.json`.

Filtering:
- `event_types` restricts which events are delivered.
- `min_risk` filters out low risk items for verdict events.

Security:
- Each outbound POST includes `event_type`, `payload`, `ts`.
- If `secret` supplied, `X-Signature = hex(hmac_sha256(secret, body))`.

Retry Strategy:
- Exponential backoff base 2 seconds: attempts spaced (2^attempt) up to 30s cap.
- `max_attempts` limit per subscription.

## Event Types
- `artifact.verdict`: Emitted for SUSPICIOUS/MALICIOUS artifacts with fields: `artifact_id`, `verdict`, `risk`, `risk_confidence`, `ambiguity`, `factors`.
- `artifact.report.push`: Emitted when user invokes manual push.

## Chat Integrations
Environment Variables:
- Slack: `INTEGRATION_SLACK_WEBHOOK_URL`
- Teams: `INTEGRATION_TEAMS_WEBHOOK_URL`
- WhatsApp (Twilio): `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_WHATSAPP_FROM`, `TWILIO_WHATSAPP_TO` (comma list)
- Risk Threshold Overrides: `SLACK_NOTIFY_MIN_RISK` (default 0.75), `WHATSAPP_NOTIFY_MIN_RISK` (default 0.9)

Formatting:
- Slack / Teams: simple text payload `{ "text": "Artifact <id> verdict=... risk=..." }`.
- WhatsApp: text message via Twilio REST API; only for MALICIOUS or risk >= threshold.

## Manual Report Push
```
POST /api/v1/artifacts/push_report
{
  "targets": ["slack", "teams", "whatsapp", "webhook"],
  "webhook_url": "optional ad-hoc URL"
}
```
Builds summary of top 10 risky artifacts (id, risk, verdict, top factors) -> posts.

## Failure Handling
- Outbound worker isolates network errors; failures do not affect ingestion.
- Twilio / Slack / Teams errors are logged (best-effort).
- Subscription updates are atomic under a thread lock.

## Future Enhancements
- Persistent delivery log with status and latency metrics.
- Dead-letter queue for permanently failed deliveries.
- Web UI to manage subscriptions & test delivery.
- Structured adaptive cards for Teams.
- Rich Slack block kit formatting & factor context.

## Security Considerations
- Encourage users to use HTTPS endpoints and rotate secrets.
- Rate limit inbound webhook (future token bucket per IP).
- Validate artifact fields to prevent injection in chat messages.

## Open Questions
- Multi-tenant subscription scoping (future: add `tenant_id`).
- Fine-grained event filters (e.g., verdict == MALICIOUS only).
- Back-pressure metrics for outbound queue.
