import ast
import pathlib
import json
import pytest


def _find_rule_defs(file_path):
    # heuristic: find register_rule(...) calls and extract the name arg string
    src = file_path.read_text(encoding='utf-8')
    try:
        tree = ast.parse(src)
    except Exception:
        return []
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, 'id', '') == 'register_rule':
            # look for keyword arg 'name' or first positional arg
            for kw in getattr(node, 'keywords', []):
                if kw.arg == 'name' and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    names.append(kw.value.value)
            # positional
            if node.args:
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    names.append(first.value)
    return names


def test_no_duplicate_rule_ids():
    base = pathlib.Path('src') / 'core' / 'correlation' / 'rules'
    files = list(base.rglob('*.py'))
    ownership = {}
    duplicates = {}
    for f in files:
        rel = str(f.relative_to(base))
        for name in _find_rule_defs(f):
            owners = ownership.setdefault(name, [])
            owners.append(rel)
            if len(owners) > 1:
                duplicates[name] = owners

    if duplicates:
        # write audit snapshot to aid triage
        p = pathlib.Path('data') / 'duplicate_rule_scan.json'
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(duplicates, indent=2), encoding='utf-8')
    assert not duplicates, f'Duplicate rule ids found: {len(duplicates)} (see data/duplicate_rule_scan.json)'
