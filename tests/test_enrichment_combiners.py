import time
from src.core.enrichment.email_combiners import combine_email_signals


def test_combine_basic_pass():
    auth = {'dkim': 'pass', 'spf': 'pass', 'dmarc': 'pass'}
    headers = {'From': 'alice@example.com', 'Subject': 'Test'}
    envelope = {'return_path': 'bounce@example.com'}
    reputations = {'ip': 1.0, 'domain_age': 1.0}
    out = combine_email_signals(auth=auth, headers=headers, envelope=envelope, reputations=reputations)
    assert out['ok_dkim'] is True
    assert out['ok_spf'] is True
    assert out['ok_dmarc'] is True
    assert 'multiplier' in out
    assert out['multiplier'] > 0


def test_header_mismatch_reduces_multiplier():
    auth = {'dkim': 'pass', 'spf': 'fail'}
    headers = {'From': 'alice@legit.com'}
    envelope = {'return_path': 'evil.com'}
    out = combine_email_signals(auth=auth, headers=headers, envelope=envelope, reputations={})
    assert out['header_mismatch'] is True
    assert out['multiplier'] < 1.0
