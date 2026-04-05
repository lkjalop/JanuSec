import json
import os
from src.adapters.qualys_connector import QualysConnector


def load_sample():
    base = os.path.join(os.path.dirname(__file__), 'integration', 'cassettes')
    path = os.path.join(base, 'sample_qualys_vulns.json')
    if not os.path.exists(path):
        return None
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def test_mapping_from_cassette():
    data = load_sample()
    assert data is not None, 'cassette missing'
    qc = QualysConnector('dummy', 'dummy', api_base='https://qualysapi.example.com')
    # simulate mapping each vuln
    items = data.get('vulnerabilities') or data.get('items') or data.get('data')
    mapped = [qc.map_vuln_to_artifact(v) for v in items]
    assert mapped[0]['vuln_id'] == 'vuln-123'
    assert mapped[0]['package'] == 'openssl'
    assert mapped[0]['cvss']['score'] == 7.5 or mapped[0]['cvss'].get('vector') == '7.5'
    assert 'qid' in mapped[0]
