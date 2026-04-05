# On-Call Runbook - JanuSec Threat Sifting Platform

Version: 0.1
Owner: SecEng / Detection On-Call
Last Updated: 2025-09-25

---
## 1. Purpose
Provide concise, actionable steps for the on-call engineer to restore service quality, maintain data integrity, and preserve detection efficacy during incidents.

---
## 2. Golden Signals & Where to Look
| Domain | Metric / Signal | Where | Healthy Range | Action if Out of Range |
|--------|-----------------|-------|---------------|------------------------|
| Ingest | `events_ingested_total` rate | /metrics | Baseline +/- 30% | Check upstream sender; validate backlog size |
| Pipeline Latency | `ingest_decision_latency_seconds` histogram (P95) | /metrics | < 0.8s | Capture thread dump; scale vertically; reduce batch size |
| Alert Volume | `decisions_total{verdict="alert"}` delta | /metrics | Stable diurnal pattern | Check for new noisy rule; verify config digests |
| Rule Noise | `rule_hits_total` top offenders | /metrics | No single rule >40% | Temporarily reduce weight / disable via config override |
| Ring Capacity | `alert_ring_utilization` gauge | /metrics | < 0.85 | Increase `ALERT_RING_MAX` or drain to storage |
| Persist Health | rotations counters + integrity verify | script / verify() | Rotations succeed, no gaps | Run integrity verifier; isolate corrupted segment |
| Domain/ASN State | `domain_distinct_current` / `asn_distinct_current` | /metrics | Slow growth, periodic decay | If runaway, tune decay factor or interval |
| Notifications | `notifications_sent_total` vs failures | /metrics | Fail rate <1% | Requeue dead-letter, validate webhook creds |

---
## 3. Quick Reference Commands (PowerShell)
```powershell
# Health & readiness
curl http://localhost:8000/health
curl http://localhost:8000/ready

# Metrics snapshot to file
curl http://localhost:8000/metrics > metrics_snapshot.txt

# Recent alerts (requires API key if enabled)
$env:API_KEY="<KEY>"
curl -H "X-API-Key: $env:API_KEY" http://localhost:8000/api/v1/alerts/recent?limit=25

# Search alerts in time window (unix ts)
$since=[int][double]::Parse((Get-Date).AddMinutes(-30).ToUniversalTime().Subtract([datetime]'1970-01-01').TotalSeconds)
curl -H "X-API-Key: $env:API_KEY" "http://localhost:8000/api/v1/alerts/search?since_ts=$since&limit=100"

# Verify alert log integrity (invoke helper if exposed)
python -c "from api.server import verify_alerts_integrity; print(verify_alerts_integrity())"
```

---
## 4. Common Incident Scenarios
### 4.1 Detection Spike (Sudden High Alert Volume)
Symptoms:
- Sharp rise in `decisions_total{verdict="alert"}`
- Rule hits concentrated in 1–2 heuristics
Actions:
1. Pull last 5 minutes top rules: inspect `rule_hits_total` lines in metrics.
2. Identify rule name; apply temporary override (weight -> 0 or disable) via config override endpoint or config file.
3. Capture sample events driving spike (search recent alerts with `since_ts`).
4. Open incident ticket; tag with `rule-noise`.
5. Post interim status in incident channel.
6. After stabilization, tune rule threshold or add suppression factors.

### 4.2 Slack / Notification Failures
Symptoms:
- Plateau in `notifications_sent_total` while alerts continue
- Increase in `notification_delivery_attempts_total{outcome="failure"}`
Actions:
1. Check webhook validity & network egress.
2. Inspect dead-letter gauge `notification_dead_letter_items`.
3. Requeue or manually replay if needed (future automation placeholder).
4. Temporarily disable noisy channels to reduce pressure.
5. Document root cause (rate limit? credential rotation?).

### 4.3 Alert Log Rotation / Integrity Failure
Symptoms:
- Missing expected rotated file; rotation counter stalls.
- Integrity verify chain mismatch.
Actions:
1. Run integrity verifier; note first failing line (chain broken where prev_hash mismatch).
2. Quarantine the corrupt segment (copy to isolated path, mark read-only).
3. Resume logging: ensure directory writable & disk space >15%.
4. If HMAC enabled: verify key not rotated unexpectedly.
5. File an incident with segment hash digests and last good anchor.

### 4.4 Disk Near Full
Symptoms:
- OS alerts or <10% free space; rotations start failing.
Actions:
1. Identify largest artifact dirs: `du -h artifacts/*` (Unix) or use Explorer on Windows.
2. Offload oldest rotated alert/evidence files to cold storage (S3, NAS).
3. Confirm new writes succeed (append a test event -> verify appears).
4. Implement temporary higher decay (faster shrink of domain/asn sets) to curb growth.
5. Add capacity planning item in backlog.

### 4.5 Elevated Latency
Symptoms:
- P95 `ingest_decision_latency_seconds` > 0.8s sustained.
Actions:
1. Collect metrics snapshot & thread dump (if possible).
2. Check for large batch ingestion or replay jobs.
3. Toggle FAST_LIVE_MODE (if acceptable) to reduce weight until root cause found.
4. Defer non-critical background tasks (disable drift or vector maintenance if toggles exist).

### 4.6 Rate Limiting Complaints on Alert Search
Symptoms:
- 429 responses from `/api/v1/alerts/search`.
Actions:
1. Confirm token bucket env vars: `ALERTS_RL_RPS`, `ALERTS_RL_BURST`.
2. If legitimate use: raise RPS modestly (<2x) and monitor.
3. If abusive pattern: temporarily revoke offending API key.

---
## 5. Configuration Tuning Cheat Sheet
| Purpose | Env Var | Default | Safe Emergency Adjustment |
|---------|---------|---------|---------------------------|
| Alert ring max size | `ALERT_RING_MAX` | 500 | Up to 2000 (watch memory) |
| Rate limit RPS | `ALERTS_RL_RPS` | 5 | <= 15 (burst unchanged) |
| Rate limit burst | `ALERTS_RL_BURST` | 10 | <= 30 |
| Domain decay interval (s) | `DOMAIN_DECAY_INTERVAL` | 900 | Decrease to 600 to accelerate shrink |
| Domain decay factor | `DOMAIN_DECAY_FACTOR` | 0.97 | 0.90 for aggressive cleanup |
| ASN decay interval (s) | `ASN_DECAY_INTERVAL` | 900 | 600 |
| ASN decay factor | `ASN_DECAY_FACTOR` | 0.97 | 0.90 |

---
## 6. Integrity Verification Procedure
1. Stop high-volume ingestion if possible.
2. Run integrity check helper (or standalone script invoking alert log verify function).
3. If mismatch detected: note (a) failing line number, (b) previous valid hash, (c) computed vs stored hash.
4. Preserve the affected file (copy + checksum); do not edit in-place.
5. Resume service with new log file; escalate with evidence bundle.

---
## 7. Communication Templates
Incident Start:
> Alert spike detected at <time>. Investigating predominant rule and potential suppression adjustments. ETA 15m for mitigation.

Interim:
> Rule <name> temporarily de-weighted. Monitoring alert volume normalization. No data loss observed.

Closure:
> Volume normalized after rule tuning. Root cause: <brief>. Follow-up: add precision guard & updated threshold.

---
## 8. Escalation Matrix
| Severity | Criteria | Escalate To | SLA Acknowledge |
|----------|----------|-------------|-----------------|
| Sev1 | Data loss risk, ingestion halted | Engineering Manager + Security Director | 5m |
| Sev2 | Sustained >2x alert noise, latency breach | On-call backup | 15m |
| Sev3 | Minor intermittent failures, self-healing | Log ticket only | 60m |

---
## 9. Post-Incident Checklist
- [ ] Root cause documented
- [ ] Metrics before/after snapshot archived
- [ ] Config overrides reverted if temporary
- [ ] Integrity chain verified post-recovery
- [ ] Capacity / tuning follow-ups created
- [ ] Runbook updated if gap found

---
## 10. Future Enhancements (Backlog)
- Automated dead-letter replay utility
- Slack notifier health endpoint
- Adaptive dynamic rate limit based on error budget
- Automated disk usage watcher w/ S3 offload

---
## 11. Fast LIVE Mode Note
When running with `FAST_LIVE_MODE=1` some heavy background tasks are skipped. Treat findings (especially performance anomalies) as approximate; always reproduce in full mode before closing a Sev1/2 incident.

---
## 12. Glossary
| Term | Definition |
|------|------------|
| Integrity Chain | Hash + prev_hash linkage ensuring tamper evidence in rotated alert logs |
| Decay | Periodic multiplicative reduction of observed domain/ASN counters to bound memory |
| Dead Letter | Holding area for failed notification deliveries pending replay |

---
End of Runbook.
---
## Appendix A: Gating & Pipeline Behavior
Heavy stages (`beacon`, `egress`, `domain_novelty`) are skipped if confidence ≥ configured skip threshold (default 0.8). Skipped stages appear in SSE payload under `skipped_stages`.

Tune via config key `pipeline.heavy_skip_confidence` or environment variable mapped into config.

If beacon detections drop unexpectedly, raise logging to DEBUG and temporarily lower threshold to 0.7.

## Appendix B: Classification Thresholds
Environment variables:
| Var | Default | Purpose |
|-----|---------|---------|
| ALERT_THRESHOLD | 0.75 | Minimum confidence for ALERT verdict |
| OBSERVE_LOW | 0.45 | Lower bound of OBSERVE ambiguity band |
| OBSERVE_HIGH | 0.60 | Upper bound of OBSERVE band |
| HEAVY_SKIP_CONFIDENCE | 0.80 | Confidence at/above which heavy stages are skipped |

## Appendix C: SSE Decision Payload
Example:
```
{
	"event_id": "abc123",
	"confidence": 0.82,
	"verdict": "ALERT",
	"factors": ["suspicious_parent_child_pair","egress_volume_spike"],
	"stage_timings": [{"name":"baseline","duration_ms":1.21,"confidence_after":0.15}],
	"skipped_stages": ["beacon"],
	"ts": 1737900000.123
}
```
Notes:
- Factors truncated (≤40) for stream efficiency.
- Stage timings tail only (last ~6) to bound payload size.

## Appendix D: Metrics Summary Enrichment
`/api/v1/metrics/summary` includes:
| Field | Meaning |
|-------|---------|
| ingest_rps_1m | Approx events/sec over last 60s |
| recent_alerts_5m | Alerts emitted in last 5 minutes |
| top_rules | Top 5 rule hit deltas since last poll |
| decision_counts | Running totals of IGNORE/OBSERVE/ALERT |
| domain_distinct / asn_distinct | Current distinct entity counts |

## Appendix E: Alert Integrity Chain
Each alert line fields: `prev_hash`, `hash`. Verification: recompute canonical JSON (excluding both fields), ensure hash matches and `prev_hash` links to prior line hash.
On failure: isolate file, rotate new file, record failing offset, escalate Sev2 if active alert loss suspected.

