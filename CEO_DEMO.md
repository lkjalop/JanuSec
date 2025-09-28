# CEO Demo: Pragmatic Threat Sifting Platform

## 1. Objective (60 Seconds)
Demonstrate: (a) low-latency adaptive pipeline, (b) cost-saving heavy stage gating, (c) selective escalation (only real or ambiguous threats), and (d) cryptographic custody of alerts.

## 2. Run the Container
```bash
# Build (if not already built)
docker build -t janusec-demo .

# Run with default gating + JSONL persistence
docker run --name janusec --rm -p 8000:8000 \
  -e ALERT_THRESHOLD=0.75 \
  -e OBSERVE_LOW=0.45 -e OBSERVE_HIGH=0.60 \
  -e PERSIST_BACKEND=jsonl \
  janusec-demo
```
Endpoint: http://localhost:8000
Health:   http://localhost:8000/health
SSE:      http://localhost:8000/api/v1/stream/decisions

## 3. Three Events (Benign, Observe, Alert)
(Use either curl or PowerShell)

### 3.1 Benign (Expected: IGNORE; may run all light stages, maybe skip heavy if factors appear later)
```bash
curl -s -X POST http://localhost:8000/api/v1/events \
  -H 'Content-Type: application/json' \
  -d '{"id":"demo-benign","details":{"parent_process":{"name":"explorer.exe"},"process":{"name":"notepad.exe"}}}'
```

### 3.2 Observe Band (Adjust thresholds to show mid confidence)
Lower threshold slightly to widen observe window for demo (optional):
```bash
# (Optional) widen window for demo
export OBSERVE_LOW=0.30; export OBSERVE_HIGH=0.55
```
Event:
```bash
curl -s -X POST http://localhost:8000/api/v1/events \
  -H 'Content-Type: application/json' \
  -d '{"id":"demo-observe","details":{"parent_process":{"name":"winword.exe"},"process":{"name":"powershell.exe"}}}'
```
Expected: factors include suspicious_parent_child_pair; confidence in OBSERVE range.

### 3.3 Forced Alert + Escalation
```bash
# Force low alert threshold for demo impact
export ALERT_THRESHOLD=0.10
curl -s -X POST http://localhost:8000/api/v1/events \
  -H 'Content-Type: application/json' \
  -d '{"id":"demo-alert","details":{"parent_process":{"name":"winword.exe"},"process":{"name":"powershell.exe"}}}'
```
Expected: verdict=ALERT, escalated=true (SSE payload), alert persisted.

## 4. Observe Live Decisions (SSE)
Open in browser: http://localhost:8000/api/v1/stream/decisions
You will see JSON lines like:
```json
{"event_id":"demo-alert","verdict":"ALERT","confidence":0.82,"skipped_stages":["beacon","egress","domain_novelty"],"escalated":true}
```

## 5. Timeline Inspection
```bash
curl -s http://localhost:8000/api/v1/decisions/timeline/demo-observe | jq .
```
Shows per-stage durations + confidence_after values.

## 6. Integrity Chain Verification (Alerts)
Alerts file: `artifacts/alerts/alerts.jsonl`
Each line contains `prev_hash` and `hash` forming a chain.
Quick verification script example (pseudo):
```bash
python - <<'PY'
import json,hashlib,sys
prev=None
for line in open('artifacts/alerts/alerts.jsonl','r',encoding='utf-8'):
  j=json.loads(line); h=j['hash']; ph=j['prev_hash']
  body={k:v for k,v in j.items() if k not in ('hash')}
  calc=hashlib.sha256(json.dumps(body,sort_keys=True,separators=(',',':')).encode()).hexdigest()
  assert calc==h, 'hash mismatch'
  assert ph==prev, 'chain break'
  prev=h
print('Chain OK, entries=', sum(1 for _ in open('artifacts/alerts/alerts.jsonl')))
PY
```

## 7. Metrics Highlights
```bash
curl -s http://localhost:8000/metrics | grep -E 'events_ingested_total|pipeline_stage_latency_ms|escalations_total'
```
Key Story Metrics:
- events_ingested_total{source="api"}
- pipeline_stage_latency_ms{stage="beacon"} (often absent if gating effective)
- escalations_total{reason="alert"}

## 8. Cost & Efficiency Narrative
1. Light stages settle most benign traffic quickly (skip heavy).  
2. Heavy stages executed only when confidence < gating threshold.  
3. Escalations limited to true or ambiguous risk → lower analyst load.  
4. Integrity chain = tamper evidence without mandatory DB dependency.  

## 9. Rollback to Default Thresholds (Optional)
```bash
export ALERT_THRESHOLD=0.75; export OBSERVE_LOW=0.45; export OBSERVE_HIGH=0.60
```

## 10. Optional: XDR Batch Demo
```bash
curl -s -X POST http://localhost:8000/api/v1/events/eclipse-xdr \
  -H 'Content-Type: application/json' \
  -d '[{"process_name":"powershell.exe","parent_process":"winword.exe"},{"process_name":"curl.exe","command_line":"curl http://safe"}]'
```
Produces batch decision list with per-event verdicts.

---
**Talking Points:** gating skip rate → CPU saved; escalation precision → reduced noise; custody chain → trust; modular registry → fast iteration.
