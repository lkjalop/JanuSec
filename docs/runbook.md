# Operations Runbook (MVB)

## 1. Purpose
Provide actionable procedures to keep the detection & action platform stable, observable, and trustworthy during live ingestion.

## 2. Key Endpoints & Functions
| Capability | Endpoint | Notes |
|------------|----------|-------|
| Health | `/health` | Basic status + queue stats |
| Ready | `/ready` | Module health check summary |
| Ingestion (MVB) | `/ingest/eclipse_xdr_mvb` | Policy + classification + actions |
| Severity Rollup | `/metrics/severity/rollup` | Mean / p95 severity + distribution |
| Escalations list | `/escalations` | Supports tenant scope & resolved filter |
| Escalation stats | `/escalations/stats` | Open count, p95 age |
| Policy status | `/policy/status` | Current allow/block config |
| Policy reload | `/policy/reload` | Reloads env JSON config |
| Decisions recent | `/api/v1/decisions/recent` | DB backed snapshot |
| Governance report | `/detections/governance_report` | Multi-metric detection posture |

Prometheus metrics exposed at `/metrics` (e.g., `decisions_total`, `ingest_events_total`, `decision_dispatch_latency_seconds_bucket`).

## 3. Core Environment Variables
| Variable | Function | Default |
|----------|----------|---------|
| ECLIPSE_API_KEY | Ingest API key auth | (none) |
| ECLIPSE_HMAC_KEY | HMAC secret for replay protection | (none) |
| INGEST_REPLAY_WINDOW_SECONDS | Max clock drift window | 300 |
| INGEST_RATE_LIMIT_RPS | Refill rate tokens/sec per tenant | 20 |
| INGEST_RATE_BURST | Burst bucket size | 40 |
| INGEST_QUEUE_HIGH_WATER | Queue saturation fraction | 0.85 |
| BLOCK_THRESHOLD | Severity block threshold | 0.9 |
| ESCALATE_THRESHOLD | Severity escalate threshold | 0.65 |
| MIN_BLOCK_QUALITY | Quality floor for block | 0.75 |
| MIN_ESC_QUALITY | Quality floor escalate | 0.5 |
| ROLLUP_MAX_BUFFER | Severity ring buffer size | 5000 |
| ROLLUP_WINDOW_SECONDS | Rollup window | 86400 |
| ESCALATION_TTL_SECONDS | Escalation retention | 86400 |
| ESCALATION_LOG_PATH | Escalation JSONL log path | artifacts/escalations/escalations.log |
| AUDIT_LOG_PATH | Decision audit JSONL | artifacts/audit/decisions.log |

## 4. Normal Operating Targets
| Metric | Target | Alert Threshold |
|--------|--------|-----------------|
| Ingest batch latency p95 | < 1.2s | > 2s sustained 5m |
| Decision dispatch latency p95 | < 0.5s | > 1s 5m |
| Queue utilization | < 60% | > 85% immediate action |
| Escalations open | < 200 | > 500 (investigate backlog) |
| Escalation p95 age | < 4h | > 12h escalate ops |
| Block policy ratio | context | Sudden spike > 90% -> review over-block |
| Simulated block ratio (dry-run) | assess baseline | If > expected baseline, review thresholds before exiting dry-run |

## 5. Operational Procedures
### 5.0 Dry-Run (Shadow) Mode
Dry-run mode allows evaluation of would-be blocks without enforcing them.

Enable per request:
```
curl -H "X-API-Key:$ECLIPSE_API_KEY" -H "X-Policy-Dry-Run: 1" ... /ingest/eclipse_xdr_mvb
```
Or via query parameter:
```
/ingest/eclipse_xdr_mvb?dry_run=1
```
Behavior:
- All `block` decisions become `sim_block` with added reason `dry_run`.
- No outbound enforcement to Eclipse sink.
- Slack notifications: only real `block` / `escalate` (optionally include `sim_block` if `SLACK_INCLUDE_SIM_BLOCK=1`).
- Metrics: `decisions_total{decision="sim_block"}` and `ingest_events_total{outcome="sim_block"}` track simulated blocks.

Exit Criteria Before Enforcing:
1. 24h latency p95 within target.
2. Simulated block reasons reviewed; no high-noise factor dominating unexpectedly.
3. Baseline simulated block precision (via escalation overlap or analyst sampling) acceptable.
4. Queue utilization stable (<60%).

Disable: remove header/query param (system stays in normal enforcement mode).
### 5.1 Queue Saturation
1. Observe `queue_saturated` 429 responses or queue utilization > threshold.
2. Actions:
   - Scale worker concurrency (future) or reduce ingestion rate.
   - Validate rate limiter config (INGEST_RATE_LIMIT_RPS).
   - Check downstream (DB / external sinks) latency via metrics.

### 5.2 Elevated Latency
1. Confirm whether ingest batch latency or dispatch latency is spiking.
2. If pipeline factors cause CPU spikes: temporarily tighten policy allow-list to fast-path benign volume.
3. If outbound Slack or Eclipse sink slow: disable temporarily via env unset (restart) and rely on audit log.

### 5.3 Replay / Signature Failures
- Errors: `stale_or_future_timestamp`, `bad_signature`.
- Validate time sync (NTP) for calling system, ensure timestamp is epoch seconds.
- Confirm correct secret & signature formation: `HMAC_SHA256(secret, f"{timestamp}." + body)`.

### 5.4 Escalation Backlog Growth
1. Check `/escalations/stats` for p95 age.
2. If open > threshold: temporarily raise `ESCALATE_THRESHOLD` (can be added to overrides later) or promote high-frequency benign escalations to allow-list via policy.

### 5.5 Policy Drift / Over-Blocking
1. Monitor block reason distribution (`decisions_total{reason="policy_block"}` vs `severity_threshold`).
2. Spike in policy blocks -> review recent `POLICY_CONFIG_JSON` changes.
3. Use run in dry-run (future: dry-run mode) before committing large block expansions.

### 5.6 State Persistence Integrity
- Escalations: ensure JSONL file rotates if size grows (future improvement). Manual safe rotation:
  ```
  mv artifacts/escalations/escalations.log artifacts/escalations/escalations.log.$(date +%s)
  touch artifacts/escalations/escalations.log
  ```
- Decision audits unaffected; rely on custody chain when DB integrated.

## 6. Failure Modes & Mitigations
| Failure | Impact | Mitigation |
|---------|--------|-----------|
| HMAC key mismatch | Rejects ingestion | Validate secret distribution; fallback to API key only temporarily |
| High queue depth | Ingestion 429 | Increase workers / tune rate limit / expand max queue |
| Escalation file corruption | Loss of some open items | Auto-skip malformed lines; restore from backup JSONL |
| Slack outage | Lost real-time alerts | Use audit file + periodic manual scan; disable Slack to reduce latency |
| Policy misconfig (over-block) | Excessive blocking | Roll back env var; reload policy endpoint |

## 7. Verification Checklist (Before Live Feed)
- [ ] HMAC signing tested with valid & invalid signatures.
- [ ] Rate limiting returns 429 under synthetic burst.
- [ ] Queue high-water mark triggers correctly (simulate depth).
- [ ] Severity rollup shows non-zero distribution after sample events.
- [ ] Escalation persistence verified across restart.
- [ ] Metrics snapshot endpoint returns expected counts & top reasons.

## 8. Future Enhancements (Deferred)
- Persistent metrics store for long-term SLA trending.
- Automated policy suggestion / dry-run diff.
- Escalation resolution workflow UI.
- Structured rotation for JSONL logs.
- Risk context scoring feeding snapshot high-risk list.
- Slack scheduled export of /metrics/snapshot?format=slack.

## 11. Metrics Snapshot Export
Endpoint: `/metrics/snapshot?tenant_id=<t>&window_seconds=86400` (default 24h).

Fields:
- decisions_total, counts.{allow,block,sim_block,escalate}
- reason_top[] (top N reasons with counts)
- severity_distribution (mean,p50,p95,max)
- severity_rollup (per existing ring buffer snapshot)
- escalations.open / escalations.total_sampled

Slack Format:
`/metrics/snapshot?tenant_id=<t>&format=slack`
Returns pre-rendered text for posting (includes top reasons, escalation counts, severity summary).

Usage (PowerShell):
```
Invoke-RestMethod http://localhost:8080/metrics/snapshot?tenant_id=default | ConvertTo-Json -Depth 4
Invoke-RestMethod 'http://localhost:8080/metrics/snapshot?tenant_id=default&format=slack'
```

## 9. Quick Commands (Linux/macOS style examples)
Simulate signed ingestion (pseudo):
```
TS=$(date +%s); BODY='[{"id":"t1","domain":"test.bad"}]'; SIG=$(printf "%s.%s" "$TS" "$BODY" | openssl dgst -sha256 -hmac "$ECLIPSE_HMAC_KEY" -hex | awk '{print $2}')
curl -H "X-API-Key:$ECLIPSE_API_KEY" -H "X-Timestamp:$TS" -H "X-Signature:$SIG" -d "$BODY" http://localhost:8080/ingest/eclipse_xdr_mvb
```

## 10. Contacts & Escalation
- Engineering: security-platform@internal (placeholder)
- On-call rotation: TBD (pager integration pending) 

Document version: 0.2 (MVB Ops Baseline)
