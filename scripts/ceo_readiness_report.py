#!/usr/bin/env python3
"""Generate a concise JSON readiness report for executive demo.

Outputs (stdout JSON):
  routes_total: total registered FastAPI routes
  routes_sample: first N api route paths
  ingest_endpoints_present: bool for each new domain ingestion endpoint
  hopgraph: {nodes, edges}
  factor_taxonomy: {count, stride_coverage_ratio}
  domains_represented: list of domain prefixes present in taxonomy
  summary: human readable sentence

Usage:
  python scripts/ceo_readiness_report.py > readiness.json
"""
from __future__ import annotations
import json, os, sys

REPORT_VERSION = 1
REQUIRED_INGEST = [
    '/api/v1/email/ingest',
    '/api/v1/remote_access/ingest',
    '/api/v1/identity/ingest',
    '/api/v1/network/ingest',
    '/api/v1/cloud/ingest',
    '/api/v1/data/ingest',
    '/api/v1/app/ingest'
]

def main():
    # Lazy import app
    try:
        import src.api.app as appmod
        app = appmod.app
    except Exception as exc:
        print(json.dumps({'error': f'failed_import_app: {exc}'}))
        return 1
    # Routes inventory
    paths = []
    for r in app.routes:
        try:
            p = getattr(r, 'path', None)
            if p:
                paths.append(p)
        except Exception:
            pass
    paths_sorted = sorted(set(paths))
    # HopGraph stats
    hg_nodes = hg_edges = None
    try:
        hg = getattr(app, 'GLOBAL_HOPGRAPH', None)
        if hg is not None:
            hg_nodes = len(getattr(hg, 'nodes', {}) or {})
            hg_edges = sum(len(v) for v in getattr(hg, 'adj', {}) .values())
    except Exception:
        pass
    # Taxonomy
    stride_cov = None
    taxonomy_count = 0
    domain_prefixes = []
    try:
        from src.core.threat_modeling.factor_taxonomy import FACTOR_STRIDE
        taxonomy_count = len(FACTOR_STRIDE)
        stride_cov = sum(1 for v in FACTOR_STRIDE.values() if v) / float(taxonomy_count or 1)
        domain_prefixes = sorted({f.split(':',1)[0] for f in FACTOR_STRIDE})
    except Exception:
        pass
    ingest_presence = {p: (p in paths_sorted) for p in REQUIRED_INGEST}
    ok_ingest = all(ingest_presence.values())
    summary_bits = []
    if taxonomy_count:
        summary_bits.append(f"taxonomy {taxonomy_count} factors ({stride_cov:.1%} stride mapped)")
    if hg_nodes is not None:
        summary_bits.append(f"hopgraph {hg_nodes} nodes/{hg_edges} edges")
    summary_bits.append('ingest OK' if ok_ingest else 'ingest MISSING')
    report = {
        'version': REPORT_VERSION,
        'routes_total': len(paths_sorted),
        'routes_sample': [p for p in paths_sorted if p.startswith('/api/v1/')][:40],
        'ingest_endpoints_present': ingest_presence,
        'hopgraph': {'nodes': hg_nodes, 'edges': hg_edges},
        'factor_taxonomy': {'count': taxonomy_count, 'stride_coverage_ratio': stride_cov},
        'domains_represented': domain_prefixes,
        'summary': '; '.join(summary_bits)
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
