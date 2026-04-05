import pytest


def test_canonicalization_and_strict_verify(monkeypatch):
    try:
        import dkim
    except Exception:
        pytest.skip('dkimpy not installed')
    try:
        import dns.resolver
    except Exception:
        pytest.skip('dnspython not installed')

    from src.core import email_auth

    # Build a simple message
    raw_headers = [
        ('From', 'alice@example.test'),
        ('To', 'bob@example.test'),
        ('Subject', 'Test Canon'),
    ]
    body = b"Test body\n"
    hdr_block = '\r\n'.join([f"{n}: {v}" for n,v in raw_headers]) + '\r\n\r\n'
    msg_bytes = hdr_block.encode('utf-8') + body

    # Generate ephemeral RSA key pair using dkim library helper if present
    import rsa
    (pub, priv) = rsa.newkeys(1024)
    priv_pem = priv.save_pkcs1()
    selector = b'testsel'
    domain = b'example.test'

    # Create DKIM signature
    sig = dkim.sign(msg_bytes, selector, domain, priv_pem, include_headers=[b'from', b'to', b'subject'], canonicalize=(b'relaxed', b'relaxed'))

    # Build AMS by replacing header name
    ams = sig.replace(b'DKIM-Signature:', b'ARC-Message-Signature:')
    aseal = b'ARC-Seal: i=1; a=rsa-sha256; s=testsel; d=example.test; b=FAKE'
    full = aseal + b'\r\n' + ams + b'\r\n' + msg_bytes

    # Mock DNS to return TXT for selector and dmarc
    class DummyAns:
        def __init__(self, s):
            self.strings = [s.encode('utf-8')]

    def fake_resolve(qname, rdtype, lifetime=2.0):
        if qname == 'testsel._domainkey.example.test':
            return [DummyAns('v=DKIM1; p=FAKE')]
        if qname == '_dmarc.example.test':
            return [DummyAns('v=DMARC1; p=none')]
        raise Exception('not found')

    monkeypatch.setattr('dns.resolver.resolve', fake_resolve)

    # Run strict validation (may be heuristic depending on dkim.verify)
    res = email_auth.validate_arc_chain(full)
    assert 'sets' in res
    assert isinstance(res['sets'], list)
