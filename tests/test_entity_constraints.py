"""Entity-constrained generation (Phase 3.11): allow-list block + output scrub.

The scrub is the structural guarantee — no matter what the model emits, the shipped
prose contains only grounded entities or neutral redactions.
"""
import pytest

from src.core.ingest.entity_constraints import (
    build_entity_allowlist,
    format_allowlist_block,
    scrub_ungrounded_entities,
)

pytestmark = pytest.mark.acceptance


def _evidence():
    return [
        {"user": "martin.chen", "src_ip": "10.20.1.5", "hostname": "srv-db-01"},
        {"user": "martin.chen", "hostname": "dc01.vesper.local", "dst_ip": "10.20.9.9"},
    ]


def test_allowlist_extraction_and_block():
    al = build_entity_allowlist(_evidence())
    assert "martin.chen" in al.users
    assert "10.20.1.5" in al.ips
    assert "srv-db-01" in al.hosts
    block = format_allowlist_block(al)
    assert "ENTITY ALLOW-LIST" in block
    assert "martin.chen" in block and "srv-db-01" in block


def test_grounded_entities_survive_scrub():
    text = "martin.chen on srv-db-01 (10.20.1.5) reached dc01.vesper.local."
    scrubbed, red = scrub_ungrounded_entities(text, _evidence())
    assert scrubbed == text          # nothing changed
    assert red == []


def test_typo_nearmiss_is_substituted():
    # Model wrote svr-db-01; evidence has srv-db-01 -> substitute, don't redact.
    text = "The attacker pivoted to svr-db-01."
    scrubbed, red = scrub_ungrounded_entities(text, _evidence())
    assert "srv-db-01" in scrubbed
    assert "svr-db-01" not in scrubbed
    assert red and red[0]["action"] == "substituted"


def test_pure_hallucination_is_redacted():
    text = "Data was exfiltrated to evil-exfil-99 and attacker.example."
    scrubbed, red = scrub_ungrounded_entities(text, _evidence())
    assert "evil-exfil-99" not in scrubbed
    assert "attacker.example" not in scrubbed
    # Redacted to neutral phrases, so the shipped prose has no fabricated entity.
    assert "an internal host" in scrubbed or "an external domain" in scrubbed
    assert all(r["action"] == "redacted" for r in red)


def test_mitre_ids_are_not_touched():
    text = "Kerberoasting (T1558.003) then WMI (T1047)."
    scrubbed, red = scrub_ungrounded_entities(text, _evidence())
    assert "T1558.003" in scrubbed and "T1047" in scrubbed
    assert red == []


def test_scrub_is_idempotent():
    text = "pivot to evil-exfil-99."
    once, _ = scrub_ungrounded_entities(text, _evidence())
    twice, red2 = scrub_ungrounded_entities(once, _evidence())
    assert once == twice
    assert red2 == []  # neutral phrases contain no entity-shaped tokens


def test_empty_and_noentity_text():
    assert scrub_ungrounded_entities("", _evidence()) == ("", [])
    t = "The user logged in and ran a command."
    assert scrub_ungrounded_entities(t, _evidence()) == (t, [])
