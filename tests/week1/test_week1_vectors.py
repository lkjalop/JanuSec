import json
import os
import pytest

# This is a scaffold for Week1 synthetic vectors. Add vectors under tests/data/ and
# reference them in rules_metadata.json test_vectors. The test asserts the files exist
# and provides a simple harness to load them for rule logic tests.

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
DATA_DIR = os.path.join(ROOT, 'tests', 'data')
META_PATH = os.path.join(ROOT, 'src', 'core', 'correlation', 'rules', 'rules_metadata.json')


def load_meta():
    with open(META_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)


def test_week1_test_vectors_exist():
    meta = load_meta()
    # check that any declared test vector files exist
    for r in meta:
        tv = r.get('test_vectors', []) or []
        for p in tv:
            path = os.path.join(ROOT, p) if not os.path.isabs(p) else p
            assert os.path.exists(path), f"Test vector missing for rule {r.get('id')}: {path}"
