#!/usr/bin/env python3
"""Simple CLI for collector telemetry helper."""
from __future__ import annotations
import argparse
from src.collectors.client import build_telemetry_payload, send_telemetry


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--base', default='http://localhost:8080', help='API base URL')
    p.add_argument('--collector', default='demo_collector')
    p.add_argument('--status', default='ok')
    p.add_argument('--send', action='store_true')
    args = p.parse_args()
    payload = build_telemetry_payload(args.collector, args.status)
    print('Payload:')
    print(payload)
    if args.send:
        r = send_telemetry(args.base, args.collector, payload)
        print('Response:', r.status_code, r.text)


if __name__ == '__main__':
    main()
