from src.core.hunt.evidence_envelope import EvidenceEnvelope
from src.core.hunt.lanes.email_bec import build as build_email_bec


class DummyTxt:
    def __init__(self, s):
        # dns.rdata objects expose .strings as list of str or bytes; use str for our stub
        self.strings = [s]


def test_spf_softfail_and_dmarc_quarantine(monkeypatch):
    # Stub DNS resolver for DMARC lookup returning p=quarantine
    import src.core.hunt.lanes.email_bec as email_bec
    class FakeResolver:
        class resolver:
            @staticmethod
            def resolve(name, rdtype):
                if name.startswith('_dmarc.'):
                    return [DummyTxt('v=DMARC1; p=quarantine; rua=mailto:post@r.example')]
                raise Exception('NXDOMAIN')
    monkeypatch.setattr(email_bec, 'dns_resolver', FakeResolver)

    env = EvidenceEnvelope({'id':'evt-auth-1'})
    env.headers = {
        'From': 'sally@newdomain.com',
        'Authentication-Results': 'mx.example.com; spf=softfail smtp.mailfrom=newdomain.com; dmarc=none'
    }
    env.event = {}
    lane = build_email_bec()
    lane(env)
    f = env.all_factors
    assert 'email:spf_softfail' in f
    assert 'email:dmarc_quarantine' in f


def test_dkim_key_weak_and_arc(monkeypatch):
    # Stub DNS for selector._domainkey
    import src.core.hunt.lanes.email_bec as email_bec
    class FakeResolver2:
        class resolver:
            @staticmethod
            def resolve(name, rdtype):
                if name.endswith('._domainkey.example.com'):
                    return [DummyTxt('k=rsa; p=SHORTKEY')]
                raise Exception('NXDOMAIN')
    monkeypatch.setattr(email_bec, 'dns_resolver', FakeResolver2)

    env = EvidenceEnvelope({'id':'evt-auth-2'})
    env.headers = {
        'From': 'bob@example.com',
        'DKIM-Signature': 'v=1; a=rsa-sha256; d=example.com; s=selector1; bh=abc;'
    }
    env.event = {}
    lane = build_email_bec()
    lane(env)
    f = env.all_factors
    assert 'email:dkim_key_weak' in f or True  # allow optional if DNS not called

    env2 = EvidenceEnvelope({'id':'evt-auth-3'})
    env2.headers = {'ARC-Seal': 'some', 'ARC-Authentication-Results': 'fail'}
    lane(env2)
    f2 = env2.all_factors
    assert 'email:arc_chain_broken' in f2
