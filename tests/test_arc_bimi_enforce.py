import pytest

from src.integrations.email_arc_bimi import enforce_arc_bimi


def test_arc_bimi_enforce_none():
    headers = {
        'Authentication-Results': 'mx.google.com; dmarc=pass spf=pass dkim=pass arc=pass bimi=pass'
    }
    out = enforce_arc_bimi({k.lower():v for k,v in headers.items()})
    assert out['enforcement'] == 'none'


def test_arc_bimi_enforce_quarantine_on_dmarc_arc_fail():
    headers = {
        'Authentication-Results': 'example.net; dmarc=fail spf=pass dkim=pass arc=fail'
    }
    out = enforce_arc_bimi({k.lower():v for k,v in headers.items()})
    assert out['enforcement'] == 'quarantine'
    assert 'email:arc_fail_with_dmarc_fail' in out['factors']


def test_arc_bimi_enforce_quarantine_on_bimi_fail_weak_dmarc():
    headers = {
        'Authentication-Results': 'example.net; dmarc=none spf=pass dkim=pass bimi=fail'
    }
    out = enforce_arc_bimi({k.lower():v for k,v in headers.items()})
    assert out['enforcement'] == 'quarantine'
    assert 'email:bimi_fail_weak_dmarc' in out['factors']
