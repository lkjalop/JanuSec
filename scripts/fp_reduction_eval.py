"""False Positive Reduction Evaluation Suite (Phase 1)

Compares factor emissions on benign corpora before vs after suppression / gating changes.
Assumes two runs produce raw decision dumps (JSON lines) in:
  metrics/precision/benign_before.jsonl
  metrics/precision/benign_after.jsonl

Outputs summary metrics to metrics/precision/fp_history.json
"""
from __future__ import annotations
import json, os, collections, argparse
from typing import Dict, Any, Tuple

OUT_PATH = 'metrics/precision/fp_history.json'

IGNORE_PREFIXES = ('mitre_','stride_','timings:')

def parse_severity_weights(mapping: str | None):
    if not mapping:
        return { 'low':1.0,'medium':1.0,'high':1.5,'critical':2.0 }
    result = {}
    for part in mapping.split(','):
        if not part: continue
        if '=' not in part: continue
        k,v = part.split('=',1)
        try: result[k.strip()] = float(v)
        except ValueError: pass
    return result or { 'low':1.0,'medium':1.0,'high':1.5,'critical':2.0 }

def load_factors(path: str, sev_weights: Dict[str,float]):
    counts = collections.Counter()
    total_events = 0
    weighted_sum = 0.0
    try:
        with open(path,'r',encoding='utf-8') as f:
            for line in f:
                line=line.strip()
                if not line: continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                total_events += 1
                sev = str(obj.get('severity','low')).lower()
                w = sev_weights.get(sev,1.0)
                facs = obj.get('factors') or []
                for fac in facs:
                    if fac.startswith('lane_') or fac.startswith('corr_'):
                        if not any(fac.startswith(p) for p in IGNORE_PREFIXES):
                            counts[fac]+=1
                            weighted_sum += w
    except FileNotFoundError:
        pass
    return counts, total_events, weighted_sum

def compute_metrics(before_counts, before_events, before_weighted, after_counts, after_events, after_weighted):
    def fp_density(counts, events):
        if events == 0: return 0.0
        return sum(counts.values())/events
    def fp_weighted_density(weighted_sum, events):
        if events == 0: return 0.0
        return weighted_sum / events
    before_density = fp_density(before_counts, before_events)
    after_density = fp_density(after_counts, after_events)
    reduction = (before_density - after_density)/before_density if before_density>0 else 0.0
    before_w = fp_weighted_density(before_weighted, before_events)
    after_w = fp_weighted_density(after_weighted, after_events)
    weighted_reduction = (before_w - after_w)/before_w if before_w>0 else 0.0
    return {
        'before_events': before_events,
        'after_events': after_events,
        'before_factor_density': before_density,
        'after_factor_density': after_density,
        'recent_reduction_ratio': reduction,
        'before_weighted_factor_density': before_w,
        'after_weighted_factor_density': after_w,
        'weighted_reduction_ratio': weighted_reduction,
        'timestamp': __import__('time').time()
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--before', default='metrics/precision/benign_before.jsonl')
    ap.add_argument('--after', default='metrics/precision/benign_after.jsonl')
    ap.add_argument('--severity-weights', default=None, help='Comma list e.g. low=1,medium=1,high=1.5,critical=2')
    args = ap.parse_args()
    os.makedirs('metrics/precision', exist_ok=True)
    sev_weights = parse_severity_weights(args.severity_weights)
    bc, be, bw = load_factors(args.before, sev_weights)
    ac, ae, aw = load_factors(args.after, sev_weights)
    metrics = compute_metrics(bc, be, bw, ac, ae, aw)
    with open(OUT_PATH,'w',encoding='utf-8') as f:
        json.dump(metrics, f, indent=2)
    print(json.dumps(metrics, indent=2))

if __name__ == '__main__':
    main()
