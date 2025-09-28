## FAST_LIVE_MODE Runbook (MVP)

### Environment Variables
| Variable | Purpose | Default |
|----------|---------|---------|
| FAST_LIVE_MODE | Enable lightweight ingest path | 0 |
| SLACK_WEBHOOK_URL | Slack alert target | (unset) |
| ALERT_DEDUP_TTL_SECONDS | Dedup window seconds | 300 |
| ENDPOINT_BATCH_MAX | Max events per batch | 1000 |
| RULES_CONFIG_PATH | External rule weights file | config/fast_rules.yaml |
| FAST_ALERT_THRESHOLD | Alert score threshold | 0.75 |
| FAST_AMBIG_LOW / HIGH | Ambiguity band | 0.45 / 0.60 |
| CORR_WINDOW_TTL_SECONDS | Correlation retention | 900 |

### Key Endpoints
| Endpoint | Description |
|----------|-------------|
| POST /api/v1/endpoints/log_batch | Ingest endpoint / Zeek-adapted events |
| GET /api/v1/events/sanitized | Recent normalized events (sanitized) |
| GET /api/v1/alerts/dlq | Slack DLQ inspection |
| GET /api/v1/correlation/stats | Correlation window stats |
| GET /metrics | Prometheus metrics |

### Sample Curl
```bash
curl -X POST http://localhost:8000/api/v1/endpoints/log_batch \
  -H 'Content-Type: application/json' \
  -d '{"events":[{"host":"WIN10","user":"alice","proc":{"name":"powershell.exe","parent":"winword.exe"}}],"include_rules":true,"send_alerts":false}'
```

### Slack Setup
1. Create Incoming Webhook in Slack workspace.
2. Export URL as `SLACK_WEBHOOK_URL`.
3. (Optional) Tune dedup env vars.

### Replay Testing
```bash
python -m scripts.log_replay --file sample.jsonl --include-rules --send-alerts
```

### Metrics to Watch
- events_ingested_total{source}
- decisions_total{verdict}
- notifications_sent_total{channel}
- ingest_buffer_size
- ingest_validation_errors_total{field}

### Escalation Logic
Score = max(rule_weight) + artifact_risk*0.4 (capped 1.0)
Bands: <0.45 IGNORE, 0.45–0.60 OBSERVE (ambiguity), >=0.75 ALERT.

### Tuning Rule Weights
Edit file at RULES_CONFIG_PATH and save; server auto-reloads on mtime change.

### Failure Modes & Mitigations
| Symptom | Likely Cause | Action |
|---------|--------------|--------|
| No alerts | thresholds too high | lower FAST_ALERT_THRESHOLD to 0.7 |
| DLQ growth | Slack webhook failing | rotate webhook / inspect /api/v1/alerts/dlq |
| High false positives | rule weights too high | reduce weights in config file |
| Memory growth | correlation retention large | reduce CORR_WINDOW_TTL_SECONDS |
