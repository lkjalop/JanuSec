import os
import time
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


def test_bec_detects_domain_change_flip(tmp_path):
    os.environ['DKIM_HISTORY_PATH'] = str(tmp_path / 'dh.json')
    # previously valid for bob@corp.com with signing domain corp.com
    record_dkim_result('bob@corp.com', True, 'corp.com', ts=time.time())

    # New event shows DKIM verified False
    env = DummyEnvelope(
        headers={'From': 'Bob <bob@corp.com>'},
        body='please send payment',
        event={'email_signals': {'dkim_crypto': {'verified': False, 'signing_domain': 'evil.com'}}}
    )
    lane = build()
    lane(env)
    assert any('email_bec:email:dkim_flip' == f for f in env.lane_factors)


def test_bec_no_flip_same_domain(tmp_path):
    os.environ['DKIM_HISTORY_PATH'] = str(tmp_path / 'dh.json')
    record_dkim_result('ceo@company.com', True, 'company.com', ts=time.time())

    env = DummyEnvelope(
        headers={'From': 'CEO <ceo@company.com>'},
        body='confirm invoice',
        event={'email_signals': {'dkim_crypto': {'verified': False, 'signing_domain': 'company.com'}}}
    )
    lane = build()
    lane(env)
    # Since signing domain hasn't changed, stricter flip detection should NOT flag a flip
    assert not any('email_bec:email:dkim_flip' == f for f in env.lane_factors)


def test_dkim_history_ttl_expiry(tmp_path):
    os.environ['DKIM_HISTORY_PATH'] = str(tmp_path / 'dh.json')
    # record with old ts beyond TTL
    old_ts = time.time() - (60*60*24*40)  # 40 days ago
    record_dkim_result('old@legacy.com', True, 'legacy.com', ts=old_ts)
    # current event shows DKIM fails, but entry should have expired if TTL default 30 days
    env = DummyEnvelope(
        headers={'From': 'Old <old@legacy.com>'},
        body='legacy notice',
        event={'email_signals': {'dkim_crypto': {'verified': False}}}
    )
    lane = build()
    lane(env)
    # Since history expired, no flip factor should be present
    assert not any('email_bec:email:dkim_flip' == f for f in env.lane_factors)


def test_malformed_from_header(tmp_path):
    os.environ['DKIM_HISTORY_PATH'] = str(tmp_path / 'dh.json')
    # record prior valid
    record_dkim_result('user@host.com', True, 'host.com', ts=time.time())
    env = DummyEnvelope(
        headers={'From': 'MalformedFromHeaderNoAngleOrAddr'},
        body='check',
        event={'email_signals': {'dkim_crypto': {'verified': False}}}
    )
    lane = build()
    # Should not raise
    lane(env)
    # cannot determine address, so no flip tag
    assert not any('email_bec:email:dkim_flip' == f for f in env.lane_factors)
