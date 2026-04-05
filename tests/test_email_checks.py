import os
import json
from src.integrations.email_checks import redact_pii, dkim_check, spf_check, dmarc_evaluate, compute_sha256_hex


def test_redact_pii_emails_and_hashes():
    txt = "send to alice@example.com and include token abcdef1234567890abcdef1234567890"
    out = redact_pii(txt)
    assert "[REDACTED_EMAIL]" in out
    assert "[REDACTED_HASH]" in out


def test_dkim_spf_dmarc_simple():
    headers = {"From": "alice@example.com", "DKIM-Signature": "v=1; a=rsa-sha256;"}
    dkim = dkim_check(headers)
    assert dkim["passed"] is True

    spf = spf_check("alice@example.com", "bounce@example.com")
    assert spf["passed"] is True

    dmarc = dmarc_evaluate("example.com", dkim, spf)
    assert dmarc["passed"] is True


def test_compute_sha256_hex():
    h = compute_sha256_hex(b"hello")
    assert len(h) == 64
