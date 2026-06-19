"""Narrator reliability: the CEO-grade narrative must not silently fall back.

Locks the three robustness fixes:
  1. T2 narrator defaults to a non-reasoning, clean-JSON model (qwen2.5:14b) so the
     top-cluster narrative parses instead of falling back.
  2. Reasoning-model <think>...</think> preambles (with braces) are stripped before
     JSON extraction.
  3. A response truncated by the token budget is salvaged (best-effort JSON repair)
     rather than discarded to the deterministic fallback.
"""
from __future__ import annotations

import pytest

from src.core.ingest import cluster_narrator as cn

pytestmark = pytest.mark.acceptance  # part of the golden acceptance harness


def test_t2_model_defaults_to_clean_json_model():
    # Must be set (so the top cluster gets the quality tier) and NOT a reasoning model.
    assert cn._T2_MODEL, "T2 narrator model must default to a concrete model"
    assert not any(tok in cn._T2_MODEL for tok in ("qwen3", "deepseek-r1")), (
        f"T2 model {cn._T2_MODEL} is a reasoning model — emits <think>, breaks JSON")


def test_strip_think_preamble_with_braces():
    # Reasoning preamble containing braces must not corrupt JSON extraction.
    raw = '<think>output should be {a json object} now</think>\n' \
          '{"verdict":"SUSPECTED_BREACH","confidence":0.7,"attack_narrative":"x"}'
    out = cn._parse_llm_output(raw, "c1")
    assert out["verdict"] == "SUSPECTED_BREACH"
    assert out["confidence"] == 0.7


def test_repair_truncated_json_salvages_partial_narrative():
    trunc = ('{"verdict": "VALIDATED_BREACH", "confidence": 0.95, '
             '"attack_narrative": "martin.chen OAuth consent then exfil to lookalike')
    repaired = cn._repair_truncated_json(trunc)
    assert repaired is not None
    assert repaired["verdict"] == "VALIDATED_BREACH"
    assert "martin.chen" in repaired["attack_narrative"]


def test_truncated_response_does_not_fall_back():
    # Full parse path: a truncated response should be salvaged, NOT downgraded to the
    # REQUIRES_INVESTIGATION/0.5 deterministic fallback.
    trunc = ('{"verdict": "VALIDATED_BREACH", "confidence": 0.92, '
             '"kill_chain_stages": ["exploitation","lateral_movement"], '
             '"attack_narrative": "oauth consent grant to lookalike then')
    out = cn._parse_llm_output(trunc, "c2")
    assert out["verdict"] == "VALIDATED_BREACH"
    assert out["confidence"] == 0.92


def test_clean_json_still_parses():
    clean = '{"verdict":"VALIDATED_BREACH","confidence":0.9,"attack_narrative":"ok",' \
            '"kill_chain_stages":["exploitation"]}'
    out = cn._parse_llm_output(clean, "c3")
    assert out["verdict"] == "VALIDATED_BREACH" and out["confidence"] == 0.9


def test_unrecoverable_text_still_falls_back_cleanly():
    out = cn._parse_llm_output("not json at all, just prose", "c4")
    # Falls back without raising; deterministic fallback shape.
    assert "verdict" in out
