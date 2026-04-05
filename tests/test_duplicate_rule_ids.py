import re
import pathlib
import json


def _find_register_names(path):
    text = path.read_text(encoding='utf-8')
    pattern = re.compile(r"register_rule\s*\(\s*name\s*=\s*['\"]([a-zA-Z0-9_\-]+)['\"]")
    names = []
    for i, line in enumerate(text.splitlines()):
        # ignore full-line comments
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        # ignore inline commented occurrences (anything after #)
        code_part = line.split('#', 1)[0]
        m = pattern.search(code_part)
        if m:
            names.append(m.group(1))
    return names


def test_no_duplicate_rule_ids():
    root = pathlib.Path('src/core/correlation/rules')
    names_map = {}
    for p in root.rglob('*.py'):
        try:
            found = _find_register_names(p)
        except Exception:
            continue
        for n in found:
            names_map.setdefault(n, []).append(str(p))
    dups = {k: v for k, v in names_map.items() if len(v) > 1}
    # write a debug artifact for manual review
    out = pathlib.Path('data') / 'duplicate_rule_scan.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(dups, indent=2), encoding='utf-8')
    assert not dups, f'Duplicate rule IDs detected: {len(dups)} (see {out})'
