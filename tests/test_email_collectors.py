import os
import sys
import asyncio

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import importlib.util

# Import collectors by file path to avoid package import issues
def load_module(rel_path, name):
    path = os.path.join(ROOT, rel_path)
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_proofpoint_collector_normalization():
    mod = load_module('src/modules/collectors/proofpoint_collector.py', 'proofpoint_collector')
    collector = mod.ProofpointTAPCollector()

    payloads = collector._sample_payloads()
    assert isinstance(payloads, list)

    # Run normalization
    normalized = collector._normalize_proofpoint_threat(payloads[0])
    assert normalized['event_type'] == 'email_threat'
    assert normalized['source'] == 'proofpoint_tap'
    assert 'from_address' in normalized and normalized['from_address'] == 'attacker@evil.com'
    assert 'to_address' in normalized and normalized['to_address'] == 'victim@example.com'
    assert 'factors' in normalized and 'email:phishing' in normalized['factors']


def test_mimecast_collector_normalization():
    mod = load_module('src/modules/collectors/mimecast_collector.py', 'mimecast_collector')
    collector = mod.MimecastCollector()

    payloads = collector._sample_payloads()
    assert isinstance(payloads, list)

    normalized = collector._normalize_mimecast_alert(payloads[0])
    assert normalized['event_type'] == 'email_threat'
    assert normalized['source'] == 'mimecast'
    assert normalized['from_address'] == 'ceo@fakecorp.com'
    assert normalized['to_address'] == 'finance@example.com'
    assert 'impostor' in normalized['factors'][1]
