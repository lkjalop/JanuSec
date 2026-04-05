import json
import os
import sys
from typing import List, Dict

REPORT_PATH = os.path.join('data', 'rule_quality_report.json')
DEFAULT_PACK_PATH = os.path.join('data', 'domain_pack_rules.json')
OUTPUT_BASELINE_PATH = os.path.join('data', 'domain_pack_baseline.json')
SUGGESTIONS_PATH = os.path.join('data', 'rule_suggestions.json')
MISSING_LOGS_OUTPUT = os.path.join('data', 'domain_pack_missing_logs.json')


def load_json(path: str) -> Dict:
    with open(path, 'r', encoding='utf-8') as fh:
        return json.load(fh)


def main(pack_path: str = DEFAULT_PACK_PATH) -> None:
    if not os.path.exists(REPORT_PATH):
        print(f"Missing sweep report at {REPORT_PATH}")
        sys.exit(1)
    if not os.path.exists(pack_path):
        print(f"Missing pack file at {pack_path}")
        sys.exit(1)

    report = load_json(REPORT_PATH)
    pack_rules: List[str] = load_json(pack_path)

    fired = set()
    missing_in_sweep = set()
    # report is a list of rule entries with key 'rule'
    all_rules = set()
    for r in report:
        rid = r.get('rule') or r.get('id') or r.get('rule_id') or r.get('name')
        if not rid:
            continue
        all_rules.add(rid)
        if rid in pack_rules and r.get('fired_any'):
            fired.add(rid)
    for rid in pack_rules:
        if rid not in all_rules:
            missing_in_sweep.add(rid)

    not_fired = [rid for rid in pack_rules if rid not in fired]

    baseline = {
        'pack_path': pack_path,
        'total_in_pack': len(pack_rules),
        'not_fired': not_fired,
        'missing_in_sweep': list(missing_in_sweep),
    }
    os.makedirs(os.path.dirname(OUTPUT_BASELINE_PATH), exist_ok=True)
    with open(OUTPUT_BASELINE_PATH, 'w', encoding='utf-8') as fh:
        json.dump(baseline, fh, indent=2)

    # Optional: collect missing log suggestions for not-fired rules
    suggestions_out = {}
    if os.path.exists(SUGGESTIONS_PATH):
        suggestions = load_json(SUGGESTIONS_PATH)
        # suggestions may be a dict keyed by rule name or a list of entries
        if isinstance(suggestions, dict):
            for rid in not_fired:
                if rid in suggestions:
                    suggestions_out[rid] = suggestions.get(rid)
        elif isinstance(suggestions, list):
            for entry in suggestions:
                name = entry.get('rule') or entry.get('id') or entry.get('name')
                if name in not_fired:
                    suggestions_out[name] = entry
    with open(MISSING_LOGS_OUTPUT, 'w', encoding='utf-8') as fh:
        json.dump(suggestions_out, fh, indent=2)

    msg = (
        f"Pack rules: {len(pack_rules)} | Not fired: {len(not_fired)} | Missing in sweep: {len(missing_in_sweep)}"
    )
    print(msg)
    if not_fired or missing_in_sweep:
        sys.exit(2)


if __name__ == '__main__':
    pack = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PACK_PATH
    main(pack)
