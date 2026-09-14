from src.collectors.email.proofpoint_tap_collector import ProofpointTAPCollector


def test_normalize_message_minimal():
    c = ProofpointTAPCollector('tenant-x')
    sample = {
        'fromAddress': 'fraud@bad.com',
        'toAddresses': ['user@acme.com'],
        'subject': 'Urgent: payment needed',
        'authenticationResults': 'spf=fail dkim=fail dmarc=fail',
        'threatsInfoMap': [],
        'messageID': 'mid-123',
        'messageTime': '2026-01-01T00:00:00Z'
    }
    out = c._normalize_message(sample)
    assert out['from'] == 'fraud@bad.com'
    assert out['to'] == 'user@acme.com'
    assert out['subject'].startswith('Urgent')
    assert 'raw' in out and 'authentication_results' in out['raw']
