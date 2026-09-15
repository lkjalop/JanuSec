"""Structured-slot LLM narration (Step 2): the LLM only rephrases the deterministic
draft; any drift (new entity, new MITRE, wrong paragraph count) falls back to the
guaranteed deterministic brief."""
import json

import pytest

from src.core.grc.summary_narrator import narrate_summary

pytestmark = pytest.mark.acceptance


def _det():
    return {
        "occurred": {"actor": "martin.chen", "affected_hosts": ["ws-martin-01"],
                     "affected_identities": ["martin.chen"]},
        "do_next": [{"priority": "P1", "sla_hours": 24, "action": "Revoke the OAuth grant"}],
        "controls_affected": {"iso27001": ["A.5.15"]},
        "paragraphs": [
            "Between 13 Apr and 28 Apr, martin.chen was breached via OAuth and exfiltrated data from ws-martin-01.",
            "Do next [P1/24h]: Revoke the OAuth grant.",
            "Controls affected: ISO27001 A.5.15.",
        ],
    }


class _Client:
    def __init__(self, paras):
        self._paras = paras
    def generate(self, *a, **k):
        return {"text": json.dumps({"paragraphs": self._paras})}


def test_valid_rewrite_uses_llm():
    good = _Client([
        "From 13 to 28 April, the account martin.chen was compromised through OAuth and data was stolen from ws-martin-01.",
        "Immediate action [P1/24h]: revoke the OAuth grant.",
        "The breach bypassed ISO27001 A.5.15.",
    ])
    r = narrate_summary(_det(), client=good)
    assert r["narration_source"] == "llm"
    assert "martin.chen" in r["paragraphs"][0]
    assert len(r["paragraphs"]) == 3


def test_hallucinated_entity_falls_back():
    bad = _Client([
        "martin.chen breached ws-martin-01 and pivoted to svr-evil-99.",  # svr-evil-99 not in draft
        "Do next [P1/24h]: Revoke the OAuth grant.",
        "Controls affected: ISO27001 A.5.15.",
    ])
    r = narrate_summary(_det(), client=bad)
    assert r["narration_source"] == "deterministic"
    assert "svr-evil-99" not in " ".join(r["paragraphs"])


def test_fabricated_mitre_falls_back():
    m = _Client([
        "martin.chen was breached via OAuth (T9999) from ws-martin-01.",  # ungrounded T-code
        "Do next [P1/24h]: Revoke the OAuth grant.",
        "Controls affected: ISO27001 A.5.15.",
    ])
    r = narrate_summary(_det(), client=m)
    assert r["narration_source"] == "deterministic"


def test_wrong_paragraph_count_falls_back():
    two = _Client(["only two paragraphs here about martin.chen", "second one"])
    r = narrate_summary(_det(), client=two)
    assert r["narration_source"] == "deterministic"


def test_missing_actor_falls_back():
    noactor = _Client(["A breach occurred via OAuth.", "Do next [P1/24h]: revoke.", "ISO27001 A.5.15."])
    r = narrate_summary(_det(), client=noactor)
    assert r["narration_source"] == "deterministic"


def test_disabled_flag_uses_deterministic(monkeypatch):
    monkeypatch.setenv("JANUSEC_GRC_LLM_SUMMARY", "0")
    good = _Client(["rewritten martin.chen prose", "do next", "controls"])
    r = narrate_summary(_det(), client=good)
    assert r["narration_source"] == "deterministic"
    assert r["paragraphs"] == _det()["paragraphs"]
