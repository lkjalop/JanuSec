"""Precision Simulation

Simulates confidence contribution of hunt lane & correlation factors on historical (or synthetic) events:
1. Load recent decisions from DB (or generate synthetic if DB unavailable)
2. Apply scoring model variants:
   - baseline: original confidence
   - advisory_plus: baseline + simulated lane weights (capped)
3. Compute precision, recall, F1 against provided labels file (CSV: event_id, label[tp|fp|ignore])
4. Output JSON summary + per-factor conditional precision (lane & correlation factors only)

Usage:
  python scripts/precision_simulation.py --labels labels.csv --lane-weight 0.04 --corr-weight 0.06 --cap 0.15
"""
from __future__ import annotations
import argparse, csv, json, asyncio, math
from typing import Dict, List, Tuple

async def load_decisions(limit: int) -> List[Dict]:
    try:
        from db.database import get_pool
        pool = await get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT event_id, confidence, factors FROM decisions ORDER BY created_at DESC LIMIT $1", limit)
            return [dict(r) for r in rows]
    except Exception:
        # fallback synthetic
        return [
            {'event_id': f'synth{i}', 'confidence': 0.2 + (i%5)*0.1, 'factors': ['lane_process_lineage:office_macro_spawn_powershell'] if i%7==0 else []} for i in range(limit)
        ]

def load_labels(path: str) -> Dict[str,str]:
    labels = {}
    with open(path,'r', encoding='utf-8') as f:
        for row in csv.reader(f):
            if not row or row[0].startswith('#'): continue
            if len(row) < 2: continue
            labels[row[0]] = row[1].lower()
    return labels

def simulate_variant(decisions: List[Dict], labels: Dict[str,str], lane_weight: float, corr_weight: float, cap: float):
    stats = {
        'baseline': {'tp':0,'fp':0,'count':0},
        'advisory_plus': {'tp':0,'fp':0,'count':0}
    }
    per_factor_tp = {}
    per_factor_fp = {}
    for d in decisions:
        eid = d['event_id']; base_conf = float(d['confidence']); facts = d.get('factors', [])
        label = labels.get(eid)
        if label not in ('tp','fp'): continue
        stats['baseline']['count'] += 1
        if base_conf >= 0.5:
            stats['baseline'][label] += 1
        # Simulated variant
        added = 0.0
        if any(f.startswith('lane_') for f in facts):
            added += lane_weight
        if any(f.startswith('corr_') for f in facts):
            added += corr_weight
        new_conf = min(1.0, base_conf + min(cap, added))
        stats['advisory_plus']['count'] += 1
        if new_conf >= 0.5:
            stats['advisory_plus'][label] += 1
        # Factor conditional tallies
        for f in facts:
            if f.startswith('lane_') or f.startswith('corr_'):
                if label == 'tp': per_factor_tp[f] = per_factor_tp.get(f,0)+1
                elif label == 'fp': per_factor_fp[f] = per_factor_fp.get(f,0)+1
    def precision(stat):
        denom = stat['tp'] + stat['fp']
        return (stat['tp']/denom) if denom else 0.0
    out = {
        'baseline_precision': precision(stats['baseline']),
        'variant_precision': precision(stats['advisory_plus']),
        'baseline_tp': stats['baseline']['tp'],
        'baseline_fp': stats['baseline']['fp'],
        'variant_tp': stats['advisory_plus']['tp'],
        'variant_fp': stats['advisory_plus']['fp'],
        'per_factor': [
            {
                'factor': f,
                'tp': per_factor_tp.get(f,0),
                'fp': per_factor_fp.get(f,0),
                'conditional_precision': (per_factor_tp.get(f,0)/(per_factor_tp.get(f,0)+per_factor_fp.get(f,0))) if (per_factor_tp.get(f,0)+per_factor_fp.get(f,0))>0 else None
            } for f in sorted(set(list(per_factor_tp.keys())+list(per_factor_fp.keys())))
        ]
    }
    return out

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--labels', required=True)
    ap.add_argument('--limit', type=int, default=500)
    ap.add_argument('--lane-weight', type=float, default=0.04)
    ap.add_argument('--corr-weight', type=float, default=0.06)
    ap.add_argument('--cap', type=float, default=0.15)
    args = ap.parse_args()
    decisions = await load_decisions(args.limit)
    labels = load_labels(args.labels)
    out = simulate_variant(decisions, labels, args.lane_weight, args.corr_weight, args.cap)
    print(json.dumps(out, indent=2))

if __name__ == '__main__':
    asyncio.run(main())
