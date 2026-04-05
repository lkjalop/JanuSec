"""Prioritizer for correlation rules using DREAD + prevalence + coverage gap.

Produces prioritized_backlog.json in the same folder when invoked
programmatically. Uses compute_dread_score from core threat modeling
to normalise DREAD and combines with prevalence/coverage_gap weights.
"""
from __future__ import annotations

import json
from typing import List
from .metadata_schema import load_rule_metadata_registry, save_rule_metadata_registry, RuleMetadata
from src.core.threat_modeling.factor_taxonomy import compute_dread_score
import os


def compute_priority_for_rule(r: RuleMetadata, asset_criticality: float = 1.0, exposure: float = 1.0) -> float:
    # DREAD risk_score already available in metadata.dread.risk_score
    dread_score = 0.0
    if r.dread and r.dread.risk_score is not None:
        dread_score = r.dread.risk_score
    else:
        # fallback: compute from factors if present
        try:
            sc = compute_dread_score(r.factors, asset_criticality=asset_criticality, exposure=exposure)
            dread_score = sc['risk_score']
        except Exception:
            dread_score = 0.0

    prevalence = max(0.0, min(1.0, float(r.prevalence_factor or 0.0)))
    coverage_gap = max(0.0, min(1.0, float(r.coverage_gap_factor or 0.0)))

    # weighted composition from earlier design: 55% dread, 25% prevalence, 20% coverage
    priority = 100.0 * (0.55 * dread_score + 0.25 * prevalence + 0.20 * coverage_gap)
    return round(priority, 2)


def run_prioritizer(path: str | None = None, asset_criticality: float = 1.0, exposure: float = 1.0) -> List[RuleMetadata]:
    metas = load_rule_metadata_registry(path)
    for m in metas:
        try:
            m.priority = compute_priority_for_rule(m, asset_criticality=asset_criticality, exposure=exposure)
        except Exception:
            m.priority = 0.0
    metas_sorted = sorted(metas, key=lambda x: x.priority, reverse=True)
    # persist to prioritized file
    out_path = os.path.join(os.path.dirname(path) if path else os.path.dirname(__file__), 'prioritized_backlog.json')
    try:
        with open(out_path,'w',encoding='utf-8') as f:
            json.dump([m.to_dict() for m in metas_sorted], f, indent=2)
    except Exception:
        pass
    return metas_sorted


def export_to_csv(metas, path: str):
    import csv
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['id','name','mitre_tactic','priority'])
        for m in metas:
            w.writerow([m.id, m.name, m.mitre_tactic, m.priority])


def cli_main():
    import argparse
    parser = argparse.ArgumentParser(description='Prioritize correlation rules')
    parser.add_argument('--asset', type=float, default=1.0, help='Asset criticality multiplier')
    parser.add_argument('--exposure', type=float, default=1.0, help='Exposure multiplier')
    parser.add_argument('--out-json', type=str, default=None, help='Write prioritized JSON to path')
    parser.add_argument('--out-csv', type=str, default=None, help='Write prioritized CSV to path')
    args = parser.parse_args()
    metas = run_prioritizer(asset_criticality=args.asset, exposure=args.exposure)
    if args.out_json:
        import json
        with open(args.out_json,'w',encoding='utf-8') as f:
            json.dump([m.to_dict() for m in metas], f, indent=2)
    if args.out_csv:
        export_to_csv(metas, args.out_csv)


if __name__ == '__main__':
    cli_main()
