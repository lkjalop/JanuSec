from src.core.hunt.lanes.email_bec import build

class DummyEnvelope:
    def __init__(self, headers=None, body='', event=None):
        self.headers = headers or {}
        self.body = body or ''
        self.event = event or {}
        self.lane_factors = []
    def add_emission(self, lane, factors, _meta, _score):
        # mimic envelope emission tagging
        tagged = [f'{lane}:{f}' for f in factors]
        self.lane_factors.extend(tagged)


def test_bec_lane_consumes_dkim_crypto_fail():
    env = DummyEnvelope(
        headers={'From': 'CEO <ceo@evil.com>'},
        body='urgent wire transfer',
        event={'email_signals': {'dkim_crypto': {'verified': False}}}
    )
    lane = build()
    lane(env)
    assert any('email_bec:email:dkim_crypto_fail' == f for f in env.lane_factors)


def test_bec_lane_consumes_dkim_crypto_verified():
    env = DummyEnvelope(
        headers={'From': 'Support <help@trusted.com>'},
        body='please review',
        event={'email_signals': {'dkim_crypto': {'verified': True}}}
    )
    lane = build()
    lane(env)
    assert any('email_bec:email:dkim_crypto_verified' == f for f in env.lane_factors)
