import json
import os
from pathlib import Path

import pytest

from src.integrations.email_adapter import EmailAdapter


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "emails"


class DummyTransport:
    def __init__(self, msg):
        self.msg = msg

    def list_messages(self, since=None):
        return [self.msg]


def load_fixture(name):
    p = FIXTURE_DIR / name
    with open(p, "r", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.mark.parametrize(
    "fixture,expect",
    [
        ("dkim_pass_spf_pass.json", {"dkim_pass": True, "spf_pass": True, "dmarc_pass": True}),
        ("dkim_missing_spf_fail.json", {"dkim_pass": False, "spf_pass": False, "dmarc_pass": False}),
        ("dkim_pass_spf_mismatch.json", {"dkim_pass": True, "spf_pass": False, "dmarc_pass": True}),
        ("dkim_borderline.json", {"dkim_pass": True, "spf_pass": True, "dmarc_pass": True}),
    ],
)
def test_canonicalize_various(fixture, expect):
    msg = load_fixture(fixture)
    transport = DummyTransport(msg)
    adapter = EmailAdapter(transport)

    canon = adapter.canonicalize_message(msg)

    assert canon["id"] == msg["id"]
    assert "body_redacted" in canon
    assert "body_hash" in canon

    # dkim/spf/dmarc structure exists
    dkim = canon["dkim"]
    spf = canon["spf"]
    dmarc = canon["dmarc"]

    assert dkim.get("passed") is expect["dkim_pass"]

    # spf_check returns 'passed' and echoes fields when possible
    assert bool(spf.get("passed")) is expect["spf_pass"]

    # DMARC uses simple OR of DKIM/SPF in helper
    assert bool(dmarc.get("passed")) is expect["dmarc_pass"]

