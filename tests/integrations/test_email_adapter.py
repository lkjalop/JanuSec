import pytest

from src.integrations.email_adapter import EmailAdapter
from src.integrations.email_dkim_spf import parse_dkim, parse_spf, redact_pii, attachment_hashes


def test_dkim_spf_parsing_and_redaction():
    dkim_hdr = "v=1; a=rsa-sha256; d=example.org; s=sel2;"
    spf_hdr = "Received-SPF: Fail (not authorized) client-ip=198.51.100.11"
    d = parse_dkim(dkim_hdr)
    s = parse_spf(spf_hdr)
    assert d["dkim"]["present"] is True
    assert d["dkim"]["domain"] == "example.org"
    assert d["dkim"]["selector"] == "sel2"
    assert s["spf"]["result"] == "fail"

    body = "Contact me at alice@example.com or +1 212-555-0199"
    red = redact_pii(body)
    assert "[REDACTED_EMAIL]" in red
    assert "[REDACTED_PHONE]" in red

    att = attachment_hashes([
        {"filename": "a.bin", "sha256": "abc"},
        {"filename": "b.bin", "md5": "def"},
    ])
    assert att["attachment_hashes"] == ["abc", "def"]


@pytest.mark.asyncio
async def test_email_adapter_fetch_and_ack():
    adapter = EmailAdapter("gmail", {})
    ok = await adapter.connect()
    assert ok
    events, cursor = await adapter.fetch_since()
    assert len(events) == 3
    assert cursor is not None
    acked = await adapter.ack(cursor)
    assert acked
    h = await adapter.health()
    assert h["connected"] is True
