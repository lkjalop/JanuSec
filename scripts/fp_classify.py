#!/usr/bin/env python
"""False Positive Classification Stub

Heuristic classifier mapping alert artifacts to FP taxonomy categories.
Outputs JSONL of enriched FP classification records.

Usage:
  python scripts/fp_classify.py --alerts alerts.jsonl --output fp_classified.jsonl

This is an initial stub; integrate with real alert repository and enrichment later.
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from typing import Dict, Any, List

CORE_ENRICH_FIELDS = {"host_role", "user_risk", "geo"}

CATEGORY = {
    'PARSING': 'PARSING',
    'CONTEXT': 'CONTEXT',
    'THRESH': 'THRESH',
    'CORR_NOISE': 'CORR_NOISE',
    'MODEL_OVER': 'MODEL_OVER',
    'DRIFT': 'DRIFT',
    'DUPLICATE': 'DUPLICATE',
    'STALE_SUPPRESS': 'STALE_SUPPRESS',
    'ENV_TEST': 'ENV_TEST',
    'UNKNOWN': 'UNKNOWN'
}

def load_alerts(path: Path) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    with path.open('r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except Exception:
                continue
    return alerts


def classify(alert: Dict[str, Any]) -> Dict[str, Any]:
    factors = alert.get('factors', [])
    enrichment_missing = [f for f in CORE_ENRICH_FIELDS if f not in alert]

    # Heuristic rules
    if enrichment_missing and len(enrichment_missing) >= 2:
        category = CATEGORY['CONTEXT']
    elif any('macro' in f and 'corr_' in f for f in factors):
        category = CATEGORY['CORR_NOISE']
    elif any('ja3_rare' in f for f in factors) and alert.get('ja3_volume_spike'):  # placeholder field
        category = CATEGORY['THRESH']
    elif alert.get('duplicate_root_hash_count', 0) > 1:
        category = CATEGORY['DUPLICATE']
    else:
        category = CATEGORY['UNKNOWN']

    out = {
        'alert_id': alert.get('id'),
        'timestamp': alert.get('timestamp'),
        'factors': factors,
        'assigned_category': category,
        'enrichment_missing': enrichment_missing,
        'original_severity': alert.get('severity'),
        'auto_detected': True,
    }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--alerts', required=True, help='Path to alerts JSONL')
    ap.add_argument('--output', required=True, help='Output JSONL with FP classifications')
    args = ap.parse_args()

    alerts = load_alerts(Path(args.alerts))
    results = [classify(a) for a in alerts]

    with Path(args.output).open('w', encoding='utf-8') as f:
        for r in results:
            f.write(json.dumps(r) + '\n')

    print(f"Classified {len(results)} alerts -> {args.output}")

if __name__ == '__main__':
    main()
