import os
import sys
import pytest

# Ensure project root is on sys.path so `src` package is importable in tests
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Ensure tests/ is first on path so our dkim test stub is importable as `dkim`
TESTS_DIR = os.path.abspath(os.path.dirname(__file__))
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

import importlib.util

spec = importlib.util.spec_from_file_location(
    "email_authenticator",
    os.path.join(ROOT, "src", "core", "enrichment", "email_authenticator.py"),
)
email_auth = importlib.util.module_from_spec(spec)
spec.loader.exec_module(email_auth)

DKIMVerifier = email_auth.DKIMVerifier


class DummyAnswer:
    def __init__(self, s):
        # emulate dns.resolver answer object
        self.strings = [s.encode('utf-8')]


def test_no_dkim_header(monkeypatch):
    verifier = DKIMVerifier()
    msg = b"Subject: hi\r\n\r\nHello\r\n"
    res = verifier.verify_message_bytes(msg)
    assert res["valid"] is False
    assert res["selector"] is None
    assert "No DKIM-Signature" in res["failure_reason"]


def test_dkim_verify_success_with_dns(monkeypatch):
    verifier = DKIMVerifier()

    # prepare a fake message with DKIM-Signature header
    msg = b"DKIM-Signature: v=1; s=sel; d=example.com; b=abc;\r\nSubject: test\r\n\r\nbody\r\n"

    # Mock dkim.verify to return True
    monkeypatch.setattr(email_auth.dkim, 'verify', lambda m: True)

    # Mock dns resolver resolve to return a TXT containing p=...
    def fake_resolve(name, rdtype):
        assert name == 'sel._domainkey.example.com'
        return [DummyAnswer('v=DKIM1; k=rsa; p=MIIB')]

    monkeypatch.setattr(email_auth, 'resolve', fake_resolve)

    res = verifier.verify_message_bytes(msg)
    assert res["valid"] is True
    assert res["selector"] == 'sel'
    assert res["signing_domain"] == 'example.com'
    assert res["public_key_present"] is True
    assert res["public_key_b64"] == 'MIIB'


def test_dkim_verify_failure_and_missing_dns(monkeypatch):
    verifier = DKIMVerifier()
    msg = b"DKIM-Signature: v=1; s=sel2; d=bad.example; b=abc;\r\nSubject: test\r\n\r\nbody\r\n"

    # dkim.verify raises an exception
    def fake_verify(m):
        raise Exception('invalid signature')

    monkeypatch.setattr(email_auth.dkim, 'verify', fake_verify)

    # dns.resolve returns NXDOMAIN (simulate via raising)
    def fake_resolve_fail(name, rdtype):
        raise Exception('NXDOMAIN')

    monkeypatch.setattr(email_auth, 'resolve', fake_resolve_fail)

    res = verifier.verify_message_bytes(msg)
    assert res["valid"] is False
    assert res["public_key_present"] is False
    assert 'dkim.verify exception' in res['failure_reason'] or 'DNS' in res['failure_reason']
