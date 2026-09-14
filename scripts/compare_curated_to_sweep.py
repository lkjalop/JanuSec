import json
import os
import sys
from typing import Dict, List


def load_json(path: str):
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except Exception:
        return None


def flatten_curated(curated: Dict) -> List[str]:
    rules: List[str] = []
    doms = curated.get('domains') or {}
    for _, arr in doms.items():
        if isinstance(arr, list):
            rules.extend([str(x) for x in arr])
    # unique preserve order
    seen = set()
    out = []
    for r in rules:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def main():
    curated_path = os.path.join('data', 'curated_production_set.json')
    sweep_path = os.path.join('data', 'rule_quality_report.json')
    curated = load_json(curated_path)
    if not curated:
        print('Missing curated set at', curated_path)
        return 2
    sweep = load_json(sweep_path)
    if not sweep:
        print('Missing sweep report at', sweep_path)
        return 2
    curated_rules = set(flatten_curated(curated))
    index = {ent.get('rule'): ent for ent in sweep if isinstance(ent, dict)}

    baseline = []
    missing = []
    not_fired = []
    for r in curated_rules:
        ent = index.get(r)
        if not ent:
            missing.append(r)
            baseline.append({'rule': r, 'present_in_sweep': False, 'fired_any': False})
        else:
            fired = bool(ent.get('fired_any'))
            baseline.append({'rule': r, 'present_in_sweep': True, 'fired_any': fired, 'source_module': ent.get('source_module'), 'severity': ent.get('severity')})
            if not fired:
                not_fired.append(r)

    out_path = os.path.join('data', 'curated_baseline.json')
    with open(out_path, 'w', encoding='utf-8') as fh:
        json.dump({'curated_rules': sorted(list(curated_rules)), 'baseline': baseline, 'missing_in_sweep': sorted(missing), 'not_fired': sorted(not_fired)}, fh, indent=2)
    print('Wrote baseline:', out_path)
    print('Curated rules:', len(curated_rules), '| Not fired:', len(not_fired), '| Missing in sweep:', len(missing))
    # non-zero exit when any curated rule did not fire to enable CI gating (optional)
    return 1 if not_fired or missing else 0


if __name__ == '__main__':
    raise SystemExit(main())
