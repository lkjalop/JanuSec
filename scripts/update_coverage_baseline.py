#!/usr/bin/env python3
"""Interactive updater for .github/coverage_baseline.json

Usage:
  python scripts/update_coverage_baseline.py [--approve]

If --approve is provided the script will overwrite the baseline file with
the counts found in coverage_report.json. Otherwise it prints a diff and exits
with non-zero so CI/tooling can prompt maintainers.
"""
import json
import sys
import os
from pathlib import Path
from datetime import datetime


def compute_baseline_from_report(report: dict) -> dict:
    # Compose a simple baseline: tactic -> count, and total rules
    tactics = report.get('tactics') or {}
    out = {'tactics': {}, 'min_rules_total': len(report.get('rules', [])), 'generated_at': datetime.utcnow().isoformat() + 'Z'}
    for k, v in tactics.items():
        if isinstance(v, list):
            out['tactics'][k] = len(v)
        else:
            try:
                out['tactics'][k] = int(v or 0)
            except Exception:
                out['tactics'][k] = 0
    return out


def main():
    rpt = Path('coverage_report.json')
    base = Path('.github/coverage_baseline.json')
    if not rpt.exists():
        print('coverage_report.json not found; run coverage generator first')
        sys.exit(2)
    report = json.loads(rpt.read_text(encoding='utf-8'))
    new_baseline = compute_baseline_from_report(report)
    if not base.exists():
        print('No existing baseline; new baseline would be:')
        print(json.dumps(new_baseline, indent=2))
        if '--approve' in sys.argv:
            base.parent.mkdir(parents=True, exist_ok=True)
            base.write_text(json.dumps(new_baseline, indent=2), encoding='utf-8')
            print('baseline written')
            sys.exit(0)
        else:
            print('Run with --approve to write the baseline file')
            sys.exit(1)
    else:
        current = json.loads(base.read_text(encoding='utf-8'))
        print('Current baseline:')
        print(json.dumps(current, indent=2))
        print('\nProposed baseline:')
        print(json.dumps(new_baseline, indent=2))
        # simple diff check
        changes = []
        for t, cnt in new_baseline.get('tactics', {}).items():
            curc = current.get('tactics', {}).get(t, 0)
            if cnt != curc:
                changes.append(f'Tactic {t}: {curc} -> {cnt}')
        if new_baseline.get('min_rules_total') != current.get('min_rules_total'):
            changes.append(f"min_rules_total: {current.get('min_rules_total')} -> {new_baseline.get('min_rules_total')}")
        if not changes:
            print('No changes detected')
            sys.exit(0)
        print('\nDetected changes:')
        for c in changes:
            print('-', c)
        if '--approve' in sys.argv:
            base.write_text(json.dumps(new_baseline, indent=2), encoding='utf-8')
            print('baseline updated')
            sys.exit(0)
        else:
            print('\nRun with --approve to apply these changes')
            sys.exit(1)


if __name__ == '__main__':
    main()
