#!/usr/bin/env python3
"""Seed demo data for the console in a lightweight, idempotent way.

Writes a small JSON file to `scripts/demo_seed.json` which the server's
read-only endpoints can read to display overview cards. This is intentionally
file-backed (no DB writes) so it's safe for demos.
"""
import json
from pathlib import Path
import time

OUT = Path(__file__).resolve().parent / 'demo_seed.json'

DEFAULT = {
    "generated_at": None,
    "overview": {
        "recent_decisions": 42,
        "active_incidents": 3,
        "open_triage_rows": 18,
        "network_beacons": 7,
        "endpoint_anomalies": 5
    },
    "metrics": {
        "detections_last_24h": 128,
        "intel_hits": 11,
        "baseline_anomalies": 9
    },
    "samples": {
        "recent_events": [
            {"ts": int(time.time()), "src_ip": "10.0.0.5", "dst_ip": "3.211.45.12", "factors": ["network:beacon"], "host": "host-12"},
            {"ts": int(time.time())-60, "src_ip": "10.0.0.8", "dst_ip": "52.12.3.4", "factors": ["network:dns_suspicious"], "host": "host-9"}
        ]
    }
}


def main():
    data = DEFAULT.copy()
    data['generated_at'] = int(time.time())
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open('w', encoding='utf-8') as fh:
        json.dump(data, fh, indent=2)
    print(f'Wrote demo seed to: {OUT}')


if __name__ == '__main__':
    main()
