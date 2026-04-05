#!/usr/bin/env python3
"""Generate a factor availability inventory for given MITRE technique IDs.

Usage: python scripts/factor_inventory.py

It reads `src/core/correlation/rules/rules_metadata.json` and `src/core/correlation/rules/prioritized_backlog.json` (if present)
and lists rules matching the technique IDs, their required factors, and where those factors appear in the repo.
"""
import json
import os
import sys
from collections import defaultdict

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
RULES_META = os.path.join(ROOT, 'src', 'core', 'correlation', 'rules', 'rules_metadata.json')
PRIO = os.path.join(ROOT, 'src', 'core', 'correlation', 'rules', 'prioritized_backlog.json')

# Techniques the user asked about
TECHS = ['T1078','T1133','T1036','T1027','T1098','T1484','T1552','T1649','T1518','T1190']

def load_json(path):
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except Exception:
        return []

rules = []
for p in (RULES_META, PRIO):
    objs = load_json(p)
    if isinstance(objs, dict):
        # some files might be a registry dict
        # try to extract list values
        for v in objs.values():
            if isinstance(v, list):
                rules.extend(v)
    elif isinstance(objs, list):
        rules.extend(objs)

# normalize rules: ensure each has mitre.technique_id or mitre field
matched = []
for r in rules:
    mitre = r.get('mitre') or {}
    tid = mitre.get('technique_id') if isinstance(mitre, dict) else None
    # some entries might include arrays
    if isinstance(tid, list):
        tids = tid
    elif isinstance(tid, str):
        tids = [tid]
    else:
        tids = []
    if any(t.split('.')[0] in TECHS for t in tids):
        matched.append(r)

# Collect required factors
tech_to_rules = defaultdict(list)
factor_set = set()
for r in matched:
    mitre = r.get('mitre') or {}
    tid = mitre.get('technique_id')
    tid_key = tid if tid else 'UNKNOWN'
    facs = r.get('factors') or r.get('factors_required') or r.get('factors_required', [])
    # normalize
    if isinstance(facs, str):
        facs = [facs]
    facs = [f for f in facs if f]
    for t in (tid_key if isinstance(tid_key, list) else [tid_key]):
        tech_to_rules[t].append({'id': r.get('id') or r.get('name'), 'name': r.get('name'), 'factors': facs})
    for f in facs:
        factor_set.add(f)

# search for factor mentions in repo
occurrences = defaultdict(list)
for root, dirs, files in os.walk(ROOT):
    # skip venv, node_modules, .git
    if any(x in root for x in ('site-packages', 'node_modules', '.git', 'build', 'dist')):
        continue
    for fn in files:
        if not fn.endswith(('.py','.json','.md','.txt')):
            continue
        path = os.path.join(root, fn)
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                txt = fh.read()
        except Exception:
            continue
        for f in factor_set:
            if f in txt:
                occurrences[f].append(path.replace(ROOT + os.sep, ''))

out = []
print('\nFactor availability inventory for techniques: %s\n' % (', '.join(TECHS)))
for tech, rules_list in tech_to_rules.items():
    print('---\nTechnique: %s' % tech)
    for r in rules_list:
        print(' Rule: %s (%s)' % (r.get('id'), r.get('name')))
        facs = r.get('factors') or []
        if not facs:
            print('  Factors: (none listed)')
        for f in facs:
            found = occurrences.get(f, [])
            if found:
                print('  Factor: %-40s FOUND (%d locations)' % (f, len(found)))
                for p in found[:5]:
                    print('   - %s' % p)
            else:
                print('  Factor: %-40s MISSING' % f)
    print('')

# Summary missing factors
missing = [f for f in sorted(factor_set) if not occurrences.get(f)]
if missing:
    print('\nMissing factors (no references found in repo):')
    for m in missing:
        print(' - %s' % m)
else:
    print('\nAll factors referenced by matching rules have at least one mention in the repo.')

print('\nInventory complete.')
