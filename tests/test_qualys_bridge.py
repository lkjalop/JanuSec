import types

from src.adapters import register, get
from src.adapters.bridge import ingest_vulns_from_connector


def test_bridge_yields_mapped_enrichment(monkeypatch):
    # Create a fake connector class
    class FakeConn:
        def __init__(self):
            pass

        def list_vulns(self):
            yield {'id': 'V1', 'asset_id': 'A1', 'package': 'openssl', 'severity': '7.5'}
            yield {'id': 'V2', 'asset_id': 'A2', 'package': 'libxml2', 'severity': '5.0'}

        def map_vuln_to_artifact(self, vuln):
            return {
                'vuln_id': vuln.get('id'),
                'asset_id': vuln.get('asset_id'),
                'package': vuln.get('package'),
                'severity': vuln.get('severity'),
                'raw': vuln,
            }

    # Register the fake connector under a test name
    register('qualys-test', FakeConn)
    items = list(ingest_vulns_from_connector('qualys-test'))
    assert len(items) == 2
    assert items[0]['vuln_id'] == 'V1'
    assert items[0]['package'] == 'openssl'
