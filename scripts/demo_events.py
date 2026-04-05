"""Demo event replay script.

Sends curated benign / observe / alert / escalated events to the generic ingest endpoint.
Usage (PowerShell):
  python scripts/demo_events.py --server http://127.0.0.1:8000
"""
from __future__ import annotations
import argparse, uuid, time, json, random
import http.client as hc
from urllib.parse import urlparse

BENIGN = {
    "event_type": "process_start",
    "details": {
        "process": {"name": "notepad.exe"},
        "parent_process": {"name": "explorer.exe"},
        "domain": "intranet.corp.local"
    }
}

OBSERVE = {
    "event_type": "process_chain",
    "details": {
        "process": {"name": "powershell.exe"},
        "parent_process": {"name": "winword.exe"},
        "domain": "cdn-assets.example.net"
    }
}

ALERT = {
    "event_type": "suspicious_beacon",
    "details": {
        "process": {"name": "powershell.exe"},
        "parent_process": {"name": "rundll32.exe"},
        "domain": "exfil.badactor.xyz",
        "dst_ip": "203.0.113.55",
        "bytes_out": 900000
    }
}

TRIO = [BENIGN, OBSERVE, ALERT]


def post_json(server: str, path: str, payload: dict) -> dict:
    u = urlparse(server)
    conn = hc.HTTPConnection(u.hostname, u.port or 80, timeout=10)
    body = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    conn.request("POST", path, body, headers)
    resp = conn.getresponse()
    data = resp.read().decode("utf-8")
    try:
        return json.loads(data)
    except Exception:
        return {"status": resp.status, "raw": data}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="http://127.0.0.1:8000")
    ap.add_argument("--delay", type=float, default=0.4, help="Delay between events")
    args = ap.parse_args()

    for idx, base in enumerate(TRIO, start=1):
        ev = {"id": uuid.uuid4().hex, **base}
        print(f"Sending {idx}/{len(TRIO)} type={base['event_type']} id={ev['id']}")
        res = post_json(args.server, "/api/v1/events", ev)
        print("  ->", res)
        time.sleep(args.delay)

    print("Done. Replay trio complete.")

if __name__ == "__main__":
    main()
