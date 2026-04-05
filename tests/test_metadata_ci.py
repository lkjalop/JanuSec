import json
import os
import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
META_PATH = os.path.join(ROOT, 'src', 'core', 'correlation', 'rules', 'rules_metadata.json')


def load_meta():
    with open(META_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)


REQUIRED_FIELDS = ['id', 'name', 'mitre', 'factors', 'dread', 'logic_ref']


def test_rules_have_required_fields():
    meta = load_meta()
    assert isinstance(meta, list)
    for r in meta:
        for k in REQUIRED_FIELDS:
            assert k in r, f"Missing {k} in rule {r.get('id')}"


def test_dread_components_present():
    meta = load_meta()
    for r in meta:
        dread = r.get('dread')
        assert isinstance(dread, dict), f"DREAD missing or not object for {r.get('id')}"
        comps = dread.get('components')
        assert isinstance(comps, dict), f"DREAD.components missing for {r.get('id')}"
        # required components
        for comp in ('damage', 'reproducibility', 'exploitability', 'affected_users', 'discoverability'):
            assert comp in comps, f"DREAD.components.{comp} missing for {r.get('id')}"
