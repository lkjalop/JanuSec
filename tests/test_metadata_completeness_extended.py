import json
import os
from pathlib import Path

ROOT = Path(__file__).parent.parent
META = ROOT / 'src' / 'core' / 'correlation' / 'rules' / 'rules_metadata.json'


def test_rules_metadata_files_exist():
    assert META.exists(), 'rules_metadata.json missing'
    data = json.loads(META.read_text(encoding='utf-8'))
    assert isinstance(data, list) and data, 'rules metadata empty'
    missing_logic = []
    missing_vectors = []
    for entry in data:
        logic_ref = entry.get('logic_ref')
        if logic_ref:
            path = ROOT / logic_ref.replace('/', os.sep)
            if not path.exists():
                missing_logic.append(logic_ref)
        for tv in entry.get('test_vectors') or []:
            p = ROOT / tv.replace('/', os.sep)
            if not p.exists():
                missing_vectors.append(tv)
    assert not missing_logic, f"Missing logic_ref paths: {missing_logic}"
    assert not missing_vectors, f"Missing test vector files: {missing_vectors}"
