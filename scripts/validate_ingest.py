#!/usr/bin/env python3
"""
Synthetic ingest validator: checks health and posts a small log_batch.
Usage: python scripts/validate_ingest.py [--base http://localhost:8080]
Exit code 0 on success, 1 on failure.
"""
import sys
import json
import time


def _lazy_requests():
    try:
        import requests  # type: ignore
        return requests
    except Exception as e:
        print(f"requests not installed: {e}")
        sys.exit(1)


def main(argv: list[str]) -> int:
    base = "http://localhost:8080"
    for i, a in enumerate(argv):
        if a == "--base" and i + 1 < len(argv):
            base = argv[i + 1]
    requests = _lazy_requests()

    # Health
    try:
        r = requests.get(f"{base}/api/v1/health", timeout=5)
        if r.status_code != 200:
            print(f"Health check failed: status={r.status_code}")
            return 1
        j = r.json()
        if not isinstance(j, dict) or j.get("status") != "ok":
            print(f"Health payload unexpected: {j}")
            return 1
        print("Health OK")
    except Exception as e:
        print(f"Health request error: {e}")
        return 1

    # Ingest: log_batch
    events = [
        {
            "id": f"synthetic-{int(time.time()*1000)}",
            "host": "validator-host",
            "dns_rcode": 0,
            "details": {"url": "https://example.com", "ip": "1.1.1.1"},
        }
    ]
    payload = {"events": events, "classify": False, "send_alerts": False, "include_rules": False}
    try:
        r = requests.post(f"{base}/api/v1/endpoints/log_batch", json=payload, timeout=10)
        if r.status_code != 200:
            print(f"log_batch failed: status={r.status_code} body={r.text[:200]}")
            return 1
        j = r.json()
        if j.get("accepted") != len(events):
            print(f"Unexpected accepted count: {j}")
            return 1
        evs = j.get("events")
        if not isinstance(evs, list) or len(evs) != len(events):
            print(f"Unexpected events payload: {j}")
            return 1
        print("Ingest OK")
    except Exception as e:
        print(f"log_batch error: {e}")
        return 1
    print("Validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
