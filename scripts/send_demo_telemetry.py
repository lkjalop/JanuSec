#!/usr/bin/env python3
from src.collectors.client import build_telemetry_payload, send_telemetry
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--base', default='http://localhost:8080')
parser.add_argument('--collector', default='demo_collector')
parser.add_argument('--status', default='ok')
args = parser.parse_args()

payload = build_telemetry_payload(args.collector, args.status)
print('Payload:', payload)
print('Sending to', args.base)
resp = send_telemetry(args.base, args.collector, payload)
print('Status', resp.status_code, resp.text)
