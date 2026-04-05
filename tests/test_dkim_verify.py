import base64
import pytest

from src.integrations import email_dkim_spf as dkimmod


def sample_signed_message() -> bytes:
    # This is a placeholder RFC822-like message. It does NOT contain a real DKIM signature.
    # Operators can replace this with a real raw RFC822 message bytes for an end-to-end test.
    msg = (
        b"From: sender@example.com\r\n"
        b"To: recipient@example.com\r\n"
        b"Subject: Test DKIM\r\n"
        b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector; b=...;\r\n"
        b"\r\n"
        b"This is a test message body.\r\n"
    )
    return msg


def test_is_dkim_available_boolean():
    assert isinstance(dkimmod.is_dkim_available(), bool)


def test_verify_dkim_behaviour():
    msg = sample_signed_message()
    res = dkimmod.verify_dkim(msg)
    assert isinstance(res, dict)
    assert "dkim" in res
    d = res["dkim"]
    assert "verified" in d
    # If dkimpy is not installed, verify_dkim should return an informative error hint
    if not dkimmod.is_dkim_available():
        assert d.get("error") in ("dkimpy_not_installed", "no_message")
        assert "hint" in d or d.get("error") == "no_message"
