# eBPF Forwarder (Demo Agent)

This demo forwarder streams kernel event JSON payloads to the API `POST /api/v1/ebpf/events` (router present). Use a systemd service or a simple Python loop to send batched events.

## Example Payload Schema

```json
{
  "source": "ebpf",
  "ts": 1765801000,
  "host": "node-1",
  "event": "exec",
  "process": "/usr/bin/curl",
  "pid": 4242,
  "user": "alice",
  "file_hash": "sha256:...",
  "raw": { "argv": ["curl","http://..."], "uid": 1000 }
}
```

## Minimal Python Sender

```python
import json, time, urllib.request
BASE="http://localhost:8080"; API_KEY="devkey123"; TENANT="demo"
payload = {"events": [{"source":"ebpf","ts":time.time(),"host":"node-1","event":"exec","process":"/bin/bash","pid":123,"user":"root"}]}
req = urllib.request.Request(f"{BASE}/api/v1/ebpf/events", data=json.dumps(payload).encode(), method='POST', headers={'x-api-key':API_KEY,'x-tenant-id':TENANT,'Content-Type':'application/json'})
print(urllib.request.urlopen(req, timeout=5).read())
```

Set up as a systemd unit for continuous streaming in production. 