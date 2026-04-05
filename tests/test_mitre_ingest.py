import json
import os
from src.core.mitre_ingest import ingest_from_stix, load_local_techniques


def test_ingest_sample(tmp_path):
    sample = json.loads(open('tests/data/mitre_sample.json', 'r', encoding='utf-8').read())
    # override MITRE_DATA_DIR to a temp dir
    os.environ['MITRE_DATA_DIR'] = str(tmp_path)
    out = ingest_from_stix(sample)
    assert isinstance(out, dict)
    assert any('T1003' in k or 'T1003' == v.get('id') for k, v in out.items())
    loaded = load_local_techniques()
    assert loaded == out
