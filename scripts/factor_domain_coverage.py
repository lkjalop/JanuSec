#!/usr/bin/env python
"""Generate domain coverage and framework mapping statistics.

Usage:
  python scripts/factor_domain_coverage.py > coverage.json
Optionally set OUTPUT_FORMAT=table for a text table.
"""
from __future__ import annotations
import os, json
from collections import defaultdict
from src.core.threat_modeling.factor_taxonomy import FACTOR_MAP_PUBLIC

FRAMEWORK_KEYS = ['mitre','stride','dread','maestro','pasta_stage','cvss','controls']

def domain_of(f: str) -> str:
    if ':' in f:
        return f.split(':',1)[0]
    if f.startswith(('corr_','meta:')):
        return 'meta'
    return 'other'

def compute():
    total = len(FACTOR_MAP_PUBLIC)
    domains = defaultdict(int)
    framework_presence = {k:0 for k in FRAMEWORK_KEYS}
    per_domain_fw = defaultdict(lambda: {k:0 for k in FRAMEWORK_KEYS})
    missing = []
    for name, meta in FACTOR_MAP_PUBLIC.items():
        d = domain_of(name)
        domains[d]+=1
        for fw in FRAMEWORK_KEYS:
            if meta.get(fw) or (fw=='pasta_stage' and meta.get('pasta_stage')):
                framework_presence[fw]+=1
                per_domain_fw[d][fw]+=1
        # record missing required keys except for synthetic correlation/meta
        if not name.startswith(('corr_','meta:')):
            m = [fw for fw in FRAMEWORK_KEYS if not meta.get(fw) and not (fw=='pasta_stage' and meta.get('pasta_stage'))]
            if m:
                missing.append({'factor': name, 'missing': m})
    return {
        'total': total,
        'domains': dict(domains),
        'framework_presence_counts': framework_presence,
        'framework_presence_percent': {k: round(framework_presence[k]/max(1,total)*100,2) for k in FRAMEWORK_KEYS},
        'per_domain_framework_counts': {d: per_domain_fw[d] for d in per_domain_fw},
        'missing_framework_keys': missing,
        'missing_count': len(missing),
    }

def main():
    summary = compute()
    fmt = os.getenv('OUTPUT_FORMAT','json').lower()
    if fmt=='json':
        print(json.dumps(summary, indent=2))
    else:
        # simple table
        print(f"Total factors: {summary['total']}")
        print("Domain counts:")
        for d,c in summary['domains'].items():
            print(f"  {d:12} {c}")
        print("Framework coverage (%):")
        for fw,p in summary['framework_presence_percent'].items():
            print(f"  {fw:12} {p:6.2f}")
        if summary['missing_count']:
            print(f"Missing mappings: {summary['missing_count']}")
            for row in summary['missing_framework_keys'][:25]:
                print(f"  {row['factor']}: {','.join(row['missing'])}")

if __name__=='__main__':
    main()
