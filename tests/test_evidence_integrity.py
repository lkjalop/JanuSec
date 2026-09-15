"""Evidence-integrity verifier + adversarial re-verification loop.

Uses the real VESPER hallucination case (svr-db-01 / vesper.local, which the
qwen2.5:14b narrator benchmark actually produced) plus the admin.corp
substring-escape case that the old grounding check let through.
"""
import pytest

from src.core.ingest.evidence_integrity import (
    check_evidence_integrity,
    regenerate_until_grounded,
    _is_grounded,
    _evidence_token_set,
)

pytestmark = pytest.mark.acceptance


def _evidence():
    return [
        {"user": "martin.chen", "src_ip": "10.20.1.5", "hostname": "ws-martin-01", "event_name": "oauth_consent"},
        {"user": "martin.chen", "src_ip": "10.20.1.5", "hostname": "dc01.vesper.local", "event_name": "kerberoasting"},
        {"user": "martin.chen", "dst_ip": "10.20.9.9", "event_name": "wmi_exec", "bytes": 4200},
    ]


def test_grounded_entities_pass():
    toks = _evidence_token_set(_evidence())
    assert _is_grounded("10.20.1.5", toks)          # exact IP token
    assert _is_grounded("martin.chen", toks)        # exact username token
    assert _is_grounded("ws-martin-01", toks)       # exact dashed host
    assert _is_grounded("vesper.local", toks)       # delimited segment of dc01.vesper.local


def test_substring_escape_is_closed():
    # Old check grounded admin.corp whenever 'admin' appeared. It must now be flagged.
    toks = _evidence_token_set([{"user": "admin", "note": "admin logged in"}])
    assert not _is_grounded("admin.corp", toks)


def test_vesper_hallucinations_are_flagged():
    narrative = {
        "attack_narrative": (
            "martin.chen ran kerberoasting from ws-martin-01, then moved laterally to "
            "svr-db-01 and svr-file-01 and exfiltrated to vesper.local [1] [2] [3]."
        ),
        "_llm_evidence_refs": [1, 2, 3],
    }
    rep = check_evidence_integrity(narrative, _evidence(), cluster={"shared_users": ["martin.chen"]})
    assert not rep.ok
    # svr-db-01 / svr-file-01 are absent from evidence; martin.chen / ws-martin-01 are not flagged.
    assert "svr-db-01" in rep.ungrounded_entities
    assert "svr-file-01" in rep.ungrounded_entities
    assert "martin.chen" not in rep.ungrounded_entities
    assert "ws-martin-01" not in rep.ungrounded_entities


def test_citation_shortfall_flagged():
    narrative = {"attack_narrative": "martin.chen ran kerberoasting from ws-martin-01.", "_llm_evidence_refs": [1]}
    rep = check_evidence_integrity(narrative, _evidence(), min_citations=3)
    assert not rep.ok
    assert rep.citation_count == 1
    assert any("citation" in i for i in rep.issues)


def test_swallowed_claim_detected():
    # Cluster asserts a shared user with no supporting evidence row -> lost evidence.
    narrative = {"attack_narrative": "activity by martin.chen [1] [2] [3].", "_llm_evidence_refs": [1, 2, 3]}
    rep = check_evidence_integrity(narrative, _evidence(), cluster={"shared_users": ["ghost.user"]})
    assert "ghost.user" in rep.swallowed_claims
    assert not rep.ok


def test_clean_narrative_passes():
    narrative = {
        "attack_narrative": "martin.chen ran kerberoasting from ws-martin-01 to dc01.vesper.local [1] [2] [3].",
        "_llm_evidence_refs": [1, 2, 3],
    }
    rep = check_evidence_integrity(narrative, _evidence(), cluster={"shared_users": ["martin.chen"]})
    assert rep.ok
    assert rep.score == 1.0


def test_regenerate_loop_recovers_then_passes():
    bad = {
        "attack_narrative": "martin.chen pivoted to svr-db-01 and svr-file-01 [1] [2] [3].",
        "_llm_evidence_refs": [1, 2, 3],
    }

    def regenerate(feedback, prev):
        # The regeneration removes the hallucinated hosts (as a real LLM would, given
        # the feedback). Assert the feedback actually names the violations.
        assert "svr-db-01" in feedback and "svr-file-01" in feedback
        return {
            "attack_narrative": "martin.chen ran kerberoasting from ws-martin-01 [1] [2] [3].",
            "_llm_evidence_refs": [1, 2, 3],
        }

    narrative, report, meta = regenerate_until_grounded(
        bad, _evidence(), {"shared_users": ["martin.chen"]}, regenerate_fn=regenerate, max_retries=1
    )
    assert meta["regenerated"] is True
    assert report.ok
    assert not narrative.get("_integrity_degraded")
    assert narrative["_evidence_integrity"]["ok"] is True


def test_regenerate_loop_falls_back_and_flags_when_unfixable():
    bad = {"attack_narrative": "pivot to svr-db-01 [1] [2] [3].", "_llm_evidence_refs": [1, 2, 3]}

    def regenerate(feedback, prev):
        return {"attack_narrative": "still mentions svr-db-01 [1] [2] [3].", "_llm_evidence_refs": [1, 2, 3]}

    def fallback(prev, report):
        return {"attack_narrative": "Deterministic summary of martin.chen activity [1] [2] [3].",
                "_llm_evidence_refs": [1, 2, 3]}

    narrative, report, meta = regenerate_until_grounded(
        bad, _evidence(), {"shared_users": ["martin.chen"]},
        regenerate_fn=regenerate, fallback_fn=fallback, max_retries=1,
    )
    assert meta["regenerated"] is True
    assert meta["fell_back"] is True
    # Fallback is grounded, so it ships clean; but if it weren't, _integrity_degraded flags it.
    assert "svr-db-01" not in narrative["attack_narrative"]
