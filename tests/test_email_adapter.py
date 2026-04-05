import json
import os
from src.integrations.email_adapter import EmailAdapter, OAuthConfig, redact_pii, DKIMVerifier, SPFChecker, DMARCPolicy


def load_fixture(name):
    path = os.path.join(os.path.dirname(__file__), "fixtures", "email", name)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_redact_pii():
    text = "contact me at alice@example.com or 4111 1111 1111 1111"
    r = redact_pii(text)
    assert "[REDACTED_EMAIL]" in r
    assert "[REDACTED_CC]" in r


def test_canonicalize_message_from_fixture():
    fx = load_fixture("sample_message.json")
    cfg = OAuthConfig(client_id="x", client_secret="y")
    adapter = EmailAdapter(cfg)
    c = adapter.canonicalize_message(fx)
    assert c["id"] == fx["id"]
    assert c["body_hash"] is not None


def test_dkim_spf_dmarc_fixture():
    fx = load_fixture("sample_message.json")
    headers = fx.get("headers", {})
    verifier = DKIMVerifier()
    spf = SPFChecker()
    dmarc = DMARCPolicy()
    dkim_ok = verifier.verify(headers, fx.get("body", ""))
    spf_res = spf.check(fx.get("source_ip", ""), fx.get("from_domain", "example.com"))
    pol = dmarc.evaluate(fx.get("from_domain", "example.com"), spf_res, dkim_ok)
    assert pol in ("none", "quarantine")
