# Sensor Integration Quickstart (Suricata + Wazuh)

This guide accelerates validation of JanuSec by wiring Suricata (EVE JSON) and Wazuh manager events into the unified ingest endpoint.

## 1. Prerequisites
- Running JanuSec API (e.g. `start_server.bat` or `python start_simple.py`)
- An API key (`devkey123` default) or rotated key from `/api/v1/api_keys/rotate`
- Optional: HMAC shared secret (`INGEST_HMAC_SECRET`) for signature verification

## 2. Environment Variables (Optional Tuning)
```
INGEST_BATCH_MAX=250               # Flush batch size
INGEST_FLUSH_INTERVAL_SECONDS=1.5  # Background flush loop delay
INGEST_RATE_CAPACITY=200           # Token bucket capacity per sensor
INGEST_RATE_REFILL_PER_SEC=50      # Token refill rate per second
INGEST_HMAC_SECRET=changeme        # Enables HMAC signature requirement
INGEST_SSE_HEARTBEAT_SECONDS=10    # Heartbeat ping interval for SSE
```

## 3. Suricata Configuration Snippet (EVE JSON)
Add (or confirm) in `suricata.yaml`:
```yaml
eve-log:
  enabled: yes
  filetype: regular
  filename: /var/log/suricata/eve.json
  types:
    - alert
    - http
    - dns
    - tls
    - flow
```
Forward lines to JanuSec (example systemd unit using curl & jq):
```bash
# /usr/local/bin/suricata-forward.sh
tail -Fn0 /var/log/suricata/eve.json | \
while read -r line; do 
  echo "$line" | jq -c '.' | \
  curl -sS -X POST http://JANUSEC_HOST:8080/api/v1/ingest/suricata \
    -H "Content-Type: application/json" \
    -H "x-api-key: $API_KEY" \
    -d @- ;
done
```
If HMAC is enabled:
```bash
sig=$(echo "$line" | jq -c '.' | openssl dgst -sha256 -mac HMAC -macopt key:$INGEST_HMAC_SECRET | awk '{print $2}')
curl -sS -X POST http://JANUSEC_HOST:8080/api/v1/ingest/suricata \
  -H "Content-Type: application/json" -H "x-api-key: $API_KEY" -H "X-Signature: $sig" -d "$(echo "$line" | jq -c '.')"
```

## 4. Wazuh Manager Forwarding (Example)
Use Wazuh API or filebeat-like tailing. Minimal Python tailer:
```python
#!/usr/bin/env python3
import json, hmac, hashlib, requests, time
API='http://JANUSEC_HOST:8080/api/v1/ingest/wazuh'
KEY='devkey123'
SECRET='changeme'  # optional
with open('/var/ossec/logs/alerts/alerts.json','r') as f:
    f.seek(0,2)
    while True:
        line=f.readline()
        if not line:
            time.sleep(0.5); continue
        try:
            obj=json.loads(line)
        except Exception:
            continue
        body=json.dumps(obj)
        headers={'x-api-key':KEY,'Content-Type':'application/json'}
        if SECRET:
            sig=hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
            headers['X-Signature']=sig
        requests.post(API,data=body,headers=headers,timeout=3)
```

## 5. API Key Rotation
Rotate keys via:
```bash
curl -X POST http://JANUSEC_HOST:8080/api/v1/api_keys/rotate \
  -H "x-api-key: CURRENT_ADMIN_KEY" -H "x-tenant-id: default" -H "x-admin: 1" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"default","old_key":"CURRENT_ADMIN_KEY"}'
```
Response:
```json
{"status":"rotated","new_key":"<hex>"}
```
Update sensors to use the new key immediately.

## 6. Structured Error Responses
Examples returned by ingest endpoint:
```json
{"detail":{"error_code":"rate_limited","detail":"Ingest rate exceeded","hint":"Adjust INGEST_RATE_CAPACITY / REFILL or reduce sensor volume"}}
{"detail":{"error_code":"invalid_signature","detail":"Signature mismatch","hint":"Confirm shared secret and raw body consistency"}}
{"detail":{"error_code":"invalid_json","detail":"Failed to parse JSON","hint":"Validate payload structure"}}
```

## 7. Rate Limit Tuning
Increase capacity or refill for bursty sensors:
```
export INGEST_RATE_CAPACITY=500
export INGEST_RATE_REFILL_PER_SEC=150
```
Restart the API process to apply changes.

## 8. Health & Monitoring (Preview)
Use existing status endpoint:
```bash
curl -H "x-api-key: $API_KEY" http://JANUSEC_HOST:8080/api/v1/ingest/status | jq
```
Shows counts, batch pending, factor volatility. (Dedicated health endpoint planned.)

## 9. Verification Checklist
- Suricata events appear as factor pills (`net:proto_http`, `net:signature_severity_high`).
- Wazuh rule categories surface (`wazuh:cat_<group>` factors).
- Auto-incident fires when combined factor pattern emerges.
- Rate limiting not triggered (unless intentional stress test).
- HMAC signature accepted (no `invalid_signature` errors).

## 10. Troubleshooting
| Symptom | Action |
|---------|--------|
| 401 missing_signature | Ensure `INGEST_HMAC_SECRET` set on server and X-Signature header provided. |
| 429 rate_limited | Raise capacity/refill or reduce event firehose. |
| Factors not appearing | Confirm adapter fields match expected (`src_ip`, `dest_ip`, `alert.signature`, Wazuh `rule.description`). |
| Auto-incident absent | Ensure at least one of each required factors present (policy_violation, signature_severity_high, hash_domain_combo). |
| timestamp_drift error | Provide `X-Ts` header with current epoch seconds; adjust `INGEST_TS_MAX_DRIFT_SECONDS`. |
| invalid_signature after rotation | New secret active; include updated HMAC key or within grace use previous secret. |

## 11. HMAC Secret Rotation
Endpoint: `POST /api/v1/ingest/hmac/rotate` (header `x-admin: 1`)
Body:
```json
{"new_secret": "new-shared-key", "grace_seconds": 120}
```
Behavior:
- Existing active secret gets an expiration = now + grace_seconds.
- New secret is immediately accepted for signatures.
- After grace window only the new secret remains.
Example rotation (PowerShell):
```powershell
curl.exe -X POST http://localhost:8080/api/v1/ingest/hmac/rotate `
  -H "x-api-key: devkey123" -H "x-admin: 1" -H "Content-Type: application/json" `
  -d '{"new_secret":"rotatedKey123","grace_seconds":60}'
```
Client dual-sign strategy during grace period:
1. Try signing with new secret; if invalid_signature returned, fallback to old until grace ends.
2. Update automation configs before grace expiration.

## 12. Replay Protection Timestamp
Add `X-Ts: <epoch_seconds>` header to each ingest request.
- Server validates drift against `INGEST_TS_MAX_DRIFT_SECONDS` (default 120s).
- On error `timestamp_drift` structured response is returned.
Env tuning:
```
INGEST_TS_MAX_DRIFT_SECONDS=300
```
Replay script usage:
```bash
python scripts/replay_suricata_wazuh.py --suricata eve.json --wazuh alerts.json --require-ts --rate 40
```

## 13. Structured Responses Summary
All ingest controller endpoints now wrap payload under `detail` key and on errors return:
```json
{"detail":{"error_code":"rate_limited","detail":"Ingest rate exceeded","hint":"Adjust INGEST_RATE_CAPACITY / REFILL or reduce sensor volume"}}
```
Update integrations expecting raw fields accordingly.

---
Ready to validate multi-source correlation. Next: implement health endpoint & golden mapping tests (Tasks 28 & 30).
