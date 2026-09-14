import time
import pytest

from src.modules.network_hunter import NetworkThreatHunter

@pytest.mark.asyncio
async def test_minimal_cert_factors_self_signed_and_expired():
    hunter = NetworkThreatHunter({})
    now = time.time()
    past = now - 3600
    event = {
        'cert_self_signed': True,
        'cert_chain_valid': False,
        'cert_not_before': past - 86400,
        'cert_not_after': past - 10,  # expired
        'cert_sig_alg': 'sha1WithRSAEncryption',
        'cert_issuer': 'CN=Rare Test Issuer',
        'sni': 'example.com',
        'cert_subject': 'CN=SomethingElse'
    }
    # Directly invoke internal analysis pieces via public analyze_event
    result = await hunter.analyze_event(event)
    factors = set(result['factors'])
    # Expect the minimal certificate-derived factors
    assert 'ssl:self_signed_cert' in factors
    assert 'ssl:expired_cert' in factors
    assert 'ssl:weak_sig_algo' in factors
    assert 'ssl:rare_issuer' in factors or 'ssl:rare_issuer' in factors  # freq heuristic first occurrence
    # Short validity may or may not appear depending on window (here long past, so skip)

@pytest.mark.asyncio
async def test_short_validity_and_sni_mismatch():
    hunter = NetworkThreatHunter({})
    now = time.time()
    nb = now - 60  # issued 1 minute ago
    na = now + 600  # expires in 10 minutes (<30 days)
    event = {
        'cert_self_signed': False,
        'cert_chain_valid': True,
        'cert_not_before': nb,
        'cert_not_after': na,
        'cert_sig_alg': 'sha256WithRSAEncryption',
        'cert_issuer': 'CN=Another Issuer',
        'sni': 'alpha.example',
        'cert_subject': 'CN=beta.example'
    }
    result = await hunter.analyze_event(event)
    factors = set(result['factors'])
    assert 'ssl:short_validity' in factors
    assert 'ssl:sni_mismatch' in factors
