import time
import pytest
from src.modules.network_hunter import NetworkThreatHunter

class DummyConfig: pass

@pytest.fixture
def hunter():
    return NetworkThreatHunter(DummyConfig())

def _base_cert_event():
    now = time.time()
    return {
        'sni': 'example.org',
        'cert_subject': 'CN=wrong.example.org',
        'cert_issuer': 'Test CA',
        'cert_chain_valid': True,
        'cert_self_signed': False,
        'cert_not_before': now - 10,
        'cert_not_after': now + 3*86400,  # 3 days left
        'cert_sig_alg': 'sha256rsa',
        'cert_key_bits': 1024,  # weak
        'cert_revoked': True,
        'cert_san_dns': ['alt.example.org'],
    }

def test_ssl_soon_expiring_and_weak_key(hunter):
    evt = _base_cert_event()
    factors = []
    hunter._analyze_cert(evt, factors)
    assert 'ssl:soon_expiring' in factors
    assert 'ssl:weak_key_length' in factors

def test_ssl_revoked_and_sni_mismatch(hunter):
    evt = _base_cert_event()
    factors = []
    hunter._analyze_cert(evt, factors)
    assert 'ssl:revoked_cert' in factors
    # SNI mismatch due to subject CN mismatch and SAN set not matching SNI
    assert 'ssl:sni_mismatch' in factors
