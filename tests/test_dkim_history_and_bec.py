from src.core.hunt.lanes.email_bec import build
from src.core.enrichment.dkim_history import record_dkim_result, get_last_dkim


class DummyEnvelope:
    def __init__(self, headers=None, body='', event=None):
        self.headers = headers or {}
        self.body = body or ''
        self.event = event or {}
        self.lane_factors = []

    def add_emission(self, lane, factors, _meta, _score):
        tagged = [f'{lane}:{f}' for f in factors]
        self.lane_factors.extend(tagged)


def test_record_and_get_last_dkim(tmp_path):
    # Use env to point history file to tmp
    import os
    os.environ['DKIM_HISTORY_PATH'] = str(tmp_path / 'dh.json')
    # record a positive DKIM for alice (use current ts to avoid TTL expiry)
    import time
    record_dkim_result('alice@example.com', True, 'example.com', ts=time.time())
    last = get_last_dkim('alice@example.com')
    assert last and last.get('valid') is True


def test_bec_detects_dkim_flip(tmp_path):
    import os
    os.environ['DKIM_HISTORY_PATH'] = str(tmp_path / 'dh.json')
    # previously valid for attacker@evil.com (use current ts)
    import time
    record_dkim_result('attacker@evil.com', True, 'good.example', ts=time.time())

    env = DummyEnvelope(
        headers={'From': 'Attacker <attacker@evil.com>'},
        body='please wire funds',
        event={'email_signals': {'dkim_crypto': {'verified': False, 'signing_domain': 'evil.example'}}}
    )
    lane = build()
    lane(env)
    assert any('email_bec:email:dkim_flip' == f for f in env.lane_factors)
