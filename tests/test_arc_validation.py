def test_validate_arc_chain_groups_and_checks(monkeypatch):
    from src.core import email_auth

    # Construct a fake raw message with ARC headers for i=1 and i=2
    raw = (
        'ARC-Authentication-Results: i=1; auth=some\r\n'
        'ARC-Message-Signature: i=1; a=rsa-sha256; s=testsel; d=example.test; b=SIGN1\r\n'
        'ARC-Seal: i=1; b=SEAL1\r\n'
        'ARC-Authentication-Results: i=2; auth=some2\r\n'
        'ARC-Message-Signature: i=2; a=rsa-sha256; s=othersel; d=example.test; b=SIGN2\r\n'
        'ARC-Seal: i=2; b=SEAL2\r\n'
        'From: Alice <alice@example.test>\r\n'
        'Subject: test\r\n\r\n'
        'Body'
    ).encode('utf-8')

    # Mock DNS for selectors
    def fake_resolve(name, rdtype, lifetime=2.0):
        class A:
            def __init__(self, s):
                self.strings = [s.encode('utf-8')]
        if name.startswith('testsel._domainkey') or name.startswith('othersel._domainkey'):
            return [A('v=DKIM1; p=FAKEKEY')]
        raise Exception('not found')

    monkeypatch.setattr('dns.resolver.resolve', fake_resolve)

    # Stub dkim lib absent -> verify returns None heuristically
    monkeypatch.setattr('src.core.email_auth._dkim_lib', None)

    res = email_auth.validate_arc_chain(raw)
    assert res['arc_present'] is True
    assert isinstance(res['sets'], list)
    assert len(res['sets']) >= 2
    # Because _dkim_lib is None we expect overall_valid to be None
    assert res['overall_valid'] is None
