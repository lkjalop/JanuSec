"""Zeek integration harness.

Synthetic replay of Zeek-like DNS + conn events through /api/v1/endpoints/log_batch.
Asserts metrics counters for nx_domain_rate_events_total increment when threshold crossed.

Run: python scripts/zeek_replay_test.py
"""
from __future__ import annotations
import time, os, sys, json
import requests

API = os.getenv('API_BASE','http://localhost:8000')

DEF_HOST = 'zeek-host'

def post_batch(events):
    r = requests.post(f"{API}/api/v1/endpoints/log_batch", json={'events': events, 'classify': True, 'send_alerts': False, 'include_rules': True})
    r.raise_for_status()
    return r.json()

def fetch_metrics():
    r = requests.get(f"{API}/metrics")
    if r.status_code != 200:
        return ''
    return r.text

def assert_metric_delta(text_before, text_after, metric_name, min_delta=1):
    def extract(txt):
        for line in txt.splitlines():
            if line.startswith(metric_name):
                try:
                    return float(line.split()[-1])
                except Exception:
                    return None
        return None
    a = extract(text_before) or 0
    b = extract(text_after) or 0
    if (b - a) < min_delta:
        raise AssertionError(f"Metric {metric_name} delta {(b-a)} < {min_delta}")


def main():
    # Warm metrics snapshot
    before = fetch_metrics()
    # Feed 10 DNS queries with low NXDOMAIN to stay below threshold
    below = []
    for i in range(10):
        below.append({'id': f'b{i}','host':DEF_HOST,'proc_name':'cmd.exe','dest_ip':'1.1.1.1','dns_rcode': 'NXDOMAIN' if i < 3 else 'NOERROR'})
    post_batch(below)
    # Above threshold
    above = []
    for i in range(10):
        above.append({'id': f'a{i}','host':DEF_HOST,'proc_name':'cmd.exe','dest_ip':'1.1.1.1','dns_rcode': 'NXDOMAIN' if i < 7 else 'NOERROR'})
    post_batch(above)
    # Trigger evaluation event (no dns_rcode) so aggregator stats are read
    post_batch([{'id':'trigger','host':DEF_HOST,'proc_name':'cmd.exe','dest_ip':'1.1.1.1'}])
    time.sleep(0.5)
    after = fetch_metrics()
    assert_metric_delta(before, after, 'nx_domain_rate_events_total')
    print('Zeek replay harness OK')

if __name__ == '__main__':
    main()
