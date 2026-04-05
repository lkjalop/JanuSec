import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
mapping = ROOT / 'data' / 'canonical_rule_owners.json'
if not mapping.exists():
    print('No canonical mapping found at', mapping)
    raise SystemExit(1)

data = json.loads(mapping.read_text(encoding='utf-8'))

def _process_rule(rule, owner_rel):
    # find all files that contain register_rule for this rule
    base = ROOT / 'src' / 'core' / 'correlation' / 'rules'
    files = list(base.rglob('*.py'))
    owner = ROOT / owner_rel
    for f in files:
        txt = f.read_text(encoding='utf-8')
        if f.samefile(owner):
            # ensure decorator is active: uncomment if commented
            new = txt.replace('# @register_rule', '@register_rule')
            if new != txt:
                f.write_text(new, encoding='utf-8')
                print('Uncommented decorator in owner', f)
            continue
        # for non-owner files: comment any decorator instances for this rule
        if f == owner:
            continue
        if f.read_text(encoding='utf-8').find("name=\"{}\"".format(rule)) >= 0 or f.read_text(encoding='utf-8').find("name='{}'".format(rule)) >= 0:
            # naive comment: prefix decorator line with '# '
            lines = txt.splitlines()
            out = []
            changed = False
            for ln in lines:
                if '@register_rule' in ln and ('name="%s"' % rule in ln or "name='%s'" % rule in ln):
                    out.append('# DUPLICATE_DISABLED decorator for %s' % rule)
                    out.append('# ' + ln)
                    changed = True
                else:
                    out.append(ln)
            if changed:
                f.write_text('\n'.join(out), encoding='utf-8')
                print('Commented duplicate decorator for', rule, 'in', f)

for rule, owner in data.items():
    _process_rule(rule, owner)

print('Canonical mapping applied')
