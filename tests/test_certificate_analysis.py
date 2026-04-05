from __future__ import annotations
import time
from src.modules.certificate_analysis import analyze_cert


def test_self_signed_and_weak_sig():
    event = {
        'cert_self_signed': True,
        'cert_sig_alg': 'sha1WithRSAEncryption',
        'cert_not_before': time.time() - 3600,
        'cert_not_after': time.time() + (60*60*24*365),
        'cert_fp': 'deadbeef',
        'cert_issuer': 'Acme Test CA'
    }
    factors, delta = analyze_cert(event)
    assert 'ssl:self_signed_cert' in factors
    assert 'ssl:weak_sig_algo' in factors
    assert delta > 0


def test_expired_and_short_validity():
    now = time.time()
    event = {
        'cert_self_signed': False,
        'cert_sig_alg': 'sha256',
        'cert_not_before': now - (60*60*24*10),
        'cert_not_after': now - 1,  # expired
        'cert_fp': 'abcd',
        'cert_issuer': 'Minor CA'
    }
    factors, delta = analyze_cert(event)
    assert 'ssl:expired_cert' in factors
    # expired should contribute meaningful delta
    assert delta >= 0.05


def test_short_validity_flag():
    now = time.time()
    # Validity 7 days
    event = {
        'cert_self_signed': False,
        'cert_sig_alg': 'sha256',
        'cert_not_before': now - (60*60*24*1),
        'cert_not_after': now + (60*60*24*6),
        'cert_fp': '1234',
        'cert_issuer': 'Tiny CA'
    }
    factors, delta = analyze_cert(event)
    assert 'ssl:short_validity' in factors
    assert delta > 0
