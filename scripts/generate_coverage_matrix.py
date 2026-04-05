#!/usr/bin/env python
"""Generate alert coverage matrix from Prometheus /metrics scrape.
Parses alert_type_total and alert_coverage_ratio plus route counts.
"""
from __future__ import annotations
import argparse, http.client, urllib.parse, re
from pathlib import Path

def scrape(url: str) -> str:
    p = urllib.parse.urlparse(url)
    conn = http.client.HTTPConnection(p.hostname, p.port or 80, timeout=5)
    path = p.path or '/metrics'
    conn.request('GET', path)
    resp = conn.getresponse()
    return resp.read().decode('utf-8', errors='replace')

def parse(body: str):
    type_counts = {}
    route_counts = {}
    coverage_ratio = None
    for line in body.splitlines():
        if line.startswith('#'): continue
        if line.startswith('alert_type_total'):
            # alert_type_total{alert_type="foo"} 12
            m = re.match(r'alert_type_total\{alert_type="([^"]+)"\}\s+(\d+)', line)
            if m:
                type_counts[m.group(1)] = int(m.group(2))
        elif line.startswith('alert_routed_total'):
            m = re.match(r'alert_routed_total\{route="([^"]+)"\}\s+(\d+)', line)
            if m:
                route_counts[m.group(1)] = int(m.group(2))
        elif line.startswith('alert_coverage_ratio'):
            parts = line.strip().split()
            if len(parts) == 2:
                try: coverage_ratio = float(parts[1])
                except: pass
    return type_counts, route_counts, coverage_ratio

def build_markdown(type_counts, route_counts, coverage_ratio):
    lines = ["# Alert Coverage Matrix",""]
    lines.append("## Coverage Ratio")
    lines.append(f"Current coverage ratio: **{coverage_ratio:.3f}**" if coverage_ratio is not None else "Coverage ratio metric not found")
    lines.append("")
    lines.append("## Alert Type Counts")
    lines.append("| Alert Type | Count |")
    lines.append("|------------|-------|")
    for k,v in sorted(type_counts.items(), key=lambda kv: kv[0]):
        lines.append(f"| {k} | {v} |")
    lines.append("")
    lines.append("## Route Distribution")
    lines.append("| Route | Count |")
    lines.append("|-------|-------|")
    for k,v in sorted(route_counts.items(), key=lambda kv: kv[0]):
        lines.append(f"| {k} | {v} |")
    lines.append("")
    return '\n'.join(lines)+"\n"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--metrics-url', default='http://localhost:8080/metrics')
    ap.add_argument('--output', default='docs/coverage/alert_coverage_matrix.md')
    args = ap.parse_args()
    body = scrape(args.metrics_url)
    type_counts, route_counts, coverage_ratio = parse(body)
    md = build_markdown(type_counts, route_counts, coverage_ratio)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding='utf-8')
    print(f"Wrote coverage matrix to {out}")

if __name__ == '__main__':
    main()
