import types


def test_dmarc_alignment_with_mocked_dns(monkeypatch):
    from src.core import email_auth

    # Mock DNS TXT response for _dmarc.example.test
    class DummyAns:
        def __init__(self, s):
            self.strings = [s.encode('utf-8')]

    def fake_resolve(name, rdtype, lifetime=2.0):
        if name.startswith('_dmarc.'):
            return [DummyAns('v=DMARC1; p=reject; adkim=s; aspf=s')]
        raise Exception('not found')

    monkeypatch.setattr('dns.resolver.resolve', fake_resolve)

    # Stub DKIM verified flag
    dkim_verified = True
    res = email_auth.check_dmarc('example.test', 'Alice <alice@example.test>', dkim_verified=dkim_verified, spf_result=None)
    assert res.get('dmarc_policy') == 'reject'
    assert res.get('adkim') == 's'
    assert res.get('aspf') == 's'
    assert res.get('alignment') in ('dkim', 'spf')
    assert res.get('dmarc_status') == 'pass'
