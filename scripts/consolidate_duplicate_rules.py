import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
scan = ROOT / 'data' / 'duplicate_rule_scan.json'
if not scan.exists():
    print('No duplicate_rule_scan.json found; run tests/test_duplicate_rule_ids.py first')
    raise SystemExit(1)

data = json.loads(scan.read_text(encoding='utf-8'))
edits = []
for rule, files in data.items():
    # canonical owner = first file in list
    owner = files[0]
    for dup in files[1:]:
        p = ROOT / dup
        if not p.exists():
            print('Missing file', p)
            continue
        text = p.read_text(encoding='utf-8')
        # replace decorator occurrences for this rule
        # look for patterns like @register_rule(name="rule" or name='rule'
        replaced = False
        lines = text.splitlines()
        out_lines = []
        i = 0
        while i < len(lines):
            ln = lines[i]
            if '@register_rule' in ln and f"name=\"{rule}\"" in ln or '@register_rule' in ln and f"name='{rule}'" in ln:
                # comment this decorator line
                out_lines.append('# DUPLICATE_DISABLED decorator for rule {} in {}'.format(rule, dup))
                out_lines.append('# ' + ln)
                replaced = True
                i += 1
                # skip possible following blank or function def? keep rest
                continue
            out_lines.append(ln)
            i += 1
        if replaced:
            p.write_text('\n'.join(out_lines), encoding='utf-8')
            edits.append(str(p))
            print('Commented duplicates for', rule, 'in', dup)

print('Edited', len(edits), 'files')
