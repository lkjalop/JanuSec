#!/usr/bin/env python3
"""Inventory correlation rules metadata and check which logic files exist.

Outputs a CSV-like report and a prioritized top-30 list by (dread_score * coverage_gap_factor).
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).parent.parent
META = ROOT / 'src' / 'core' / 'correlation' / 'rules' / 'rules_metadata.json'

def dread_score(entry):
    d = entry.get('dread', {})
    comps = d.get('components', {}) if isinstance(d, dict) else {}
    # sum components as a simple proxy
    return sum(v for v in comps.values() if isinstance(v, (int, float)))

def main():
    if not META.exists():
        print('rules_metadata.json not found', file=sys.stderr)
        return 2
    data = json.loads(META.read_text(encoding='utf-8'))
    rows = []
    for ent in data:
        logic = ent.get('logic_ref') or ent.get('logic') or ''
        # normalize to repo-relative path
        if logic and not logic.startswith('src'):
            logic_path = ROOT / 'src' / 'core' / 'correlation' / 'rules' / logic
        else:
            logic_path = ROOT / logic
        exists = logic_path.exists()
        ds = dread_score(ent)
        cg = float(ent.get('coverage_gap_factor') or 0)
        score = ds * cg
        rows.append((ent.get('id'), ent.get('name'), logic, str(logic_path), exists, ds, cg, score, ent.get('status')))

    # Print CSV header
    print('id,name,logic_ref,repo_path,exists,dread,coverage_gap,score,status')
    for r in rows:
        print(','.join(str(x).replace(',',';') for x in r))

    # Prioritize
    rows_sorted = sorted(rows, key=lambda r: float(r[7] or 0), reverse=True)
    print('\nTop 30 prioritized (dread * coverage_gap):')
    for i, r in enumerate(rows_sorted[:30], 1):
        print(f"{i}. {r[0]} | {r[1]} | score={r[7]:.2f} | exists={'YES' if r[4] else 'NO'} | logic={r[2]}")

    missing = [r for r in rows if not r[4]]
    print(f'\nTotal rules: {len(rows)}, missing logic implementations: {len(missing)}')
    return 0

if __name__ == '__main__':
    sys.exit(main())
