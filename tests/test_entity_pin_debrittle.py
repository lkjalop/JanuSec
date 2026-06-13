"""Regression: entity-pin quality gate must not flag innocent tokens (de-brittle).

The gate forced narration fallbacks on plain all-caps English words (STYLIST, RULES,
MODE) and hex hash fragments (BADD91DA), because its regex matched any all-caps run and
it treated hashes as proper-noun entities. Guards should require positive evidence of a
problem, not pattern-match-and-reject.
"""
from __future__ import annotations
import os
os.environ.setdefault("PLATFORM_LITE_INIT", "1")
from src.core.tier1_prefill.verdict_engine import _validate_entity_pins


def _q(text, allowed=None):
    pf = {"incident_name": "", "headline_subtitle": text, "short_narrative": "", "top_actions": []}
    return _validate_entity_pins(pf, allowed or set())


def test_plain_allcaps_words_not_flagged():
    q = _q("STYLIST MODE RULES are enabled for the report")
    assert q["flagged_tokens"] == [] and q["passed"]


def test_hex_hash_fragment_not_flagged():
    q = _q("file hash BADD91DA matched threat intel")
    assert "BADD91DA" not in q["flagged_tokens"]


def test_real_unknown_access_key_still_flagged():
    q = _q("attacker used AKIA1234DEADBEEF to call the API", allowed=set())
    assert any("AKIA" in t for t in q["flagged_tokens"])


def test_hyphenated_host_still_checked():
    # WS-MARTIN-01 absent from allowed → flagged (real entity, correctly pinned)
    q = _q("process spawned on WS-MARTIN-01", allowed=set())
    assert any("MARTIN" in t.upper() for t in q["flagged_tokens"])


def test_known_entity_passes():
    q = _q("martin.chen accessed SVR01", allowed={"martin.chen", "svr01"})
    assert q["passed"]
