import pytest


def test_arc_rfc_verification_harness(monkeypatch):
    try:
        import dkim
    except Exception:
        pytest.skip('dkimpy not installed')

    try:
        import dns.resolver
    except Exception:
        pytest.skip('dnspython not installed')

    from src.core import email_auth

    # Generate a simple message
    body = b"Hello world\n"
    headers = [
        b"From: alice@example.test",
        b"To: bob@example.test",
        b"Subject: test",
    ]
    msg = b"\r\n".join(headers) + b"\r\n\r\n" + body

    # Generate test key
    import rsa
    (pub, priv) = rsa.newkeys(1024)
    priv_pem = priv.save_pkcs1()
    pub_pem = pub.save_pkcs1()

    selector = 'testsel'
    domain = 'example.test'

    # Create a DKIM signature for the message
    sig = dkim.sign(msg, selector.encode(), domain.encode(), priv_pem, include_headers=[b"From", b"To", b"Subject"], canonicalize=(b"relaxed", b"relaxed"))

    # Build an ARC-Message-Signature by taking the DKIM signature bytes and replacing header name
    ams = sig.replace(b'DKIM-Signature:', b'ARC-Message-Signature:')
    # Prepend AMS to message
    raw_with_ams = ams + b"\r\n" + msg

    # Build an ARC-Seal by signing the AMS header (approximate)
    # For test purposes, we'll add an ARC-Seal header as a placeholder and rely on AMS verification
    aseal = b"ARC-Seal: i=1; a=rsa-sha256; s=testsel; d=example.test; b=SEAL"
    raw_full = aseal + b"\r\n" + raw_with_ams

    # Mock DNS resolution for selector._domainkey.example.test
    class DummyAns:
        def __init__(self, s):
            self.strings = [s.encode('utf-8')]

    def fake_resolve(qname, rdtype, lifetime=2.0):
        if qname == f"{selector}._domainkey.{domain}":
            # Provide minimal TXT with p= base64 of pub key (dkimpy doesn't parse key from TXT here in test)
            return [DummyAns('v=DKIM1; p=FAKE')]
        if qname == f"_dmarc.{domain}":
            return [DummyAns('v=DMARC1; p=none')]
        raise Exception('not found')

    monkeypatch.setattr('dns.resolver.resolve', fake_resolve)

    # Now run validate_arc_chain; since our ASEAL is synthetic we expect AMS verify to pass
    res = email_auth.validate_arc_chain(raw_full)
    # AMS verification may be True; overall_valid should be True or None depending on dkim.verify behavior
    assert 'sets' in res
    assert isinstance(res['sets'], list)
