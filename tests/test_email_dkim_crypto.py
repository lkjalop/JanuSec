import pytest

from src.integrations.email_dkim_spf import verify_dkim


def test_verify_dkim_structure_no_message():
    res = verify_dkim(None)
    assert 'dkim' in res
    dk = res['dkim']
    assert 'verified' in dk and dk['verified'] is None
    assert dk.get('error') == 'no_message'


def test_verify_dkim_structure_with_dummy_message():
    # Minimal RFC822-like message with a DKIM-Signature header (not valid)
    raw = (b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1;\r\n"
           b"From: alice@example.com\r\n"
           b"To: bob@example.com\r\n"
           b"Subject: Test\r\n\r\nBody")
    res = verify_dkim(raw)
    assert 'dkim' in res
    dk = res['dkim']
    # We can't guarantee True without DNS keys; ensure keys exist and verified is bool
    assert 'verified' in dk
    assert isinstance(dk['verified'], (bool, type(None)))
    # Domain and selector may be parsed from header
    assert 'domain' in dk and 'selector' in dk
