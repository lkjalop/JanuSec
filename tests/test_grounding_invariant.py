"""#4 Grounding invariant (CI-enforceable, dataset-independent).

The flagship claim is 'grounded — no fabricated entities or MITRE codes ship'. This
proves it structurally on adversarial synthetic input (no VESPER/Meridian/Santos, so
it also guards against dataset overfitting): whatever an LLM emits, after the scrub +
MITRE correction the shipped text contains ZERO entity or technique not in evidence.
"""
import pytest

from src.core.ingest.entity_constraints import scrub_ungrounded_entities, correct_mitre_ids

pytestmark = pytest.mark.acceptance

# Small, varied evidence set — the only "truth" the narrative may reference.
_EVIDENCE = [
    {"user": "alice.tan", "src_ip": "10.1.2.3", "hostname": "wkstn-alice-04", "event_name": "login"},
    {"user": "svc_deploy", "dst_ip": "10.1.9.9", "hostname": "srv-ci-02", "domain": "corp.internal"},
]
_ALLOWED_MITRE = {"T1078", "T1021.006"}

# Adversarial narratives a drifting model might emit — each seeds fabrications.
_ADVERSARIAL = [
    "alice.tan on wkstn-alice-04 pivoted to evil-host-99 and beacon-c2.xyz (T9999).",
    "Exfil from srv-ci-02 to 203.0.113.240 via attacker.example using T1566 and T4444.",
    "svc_deploy escalated on ghost-server-42.internal; see badhost.evil and 8.8.8.8.",
    "Nothing suspicious — routine access by alice.tan on wkstn-alice-04.",   # clean control
]

_FABRICATED_TOKENS = ["evil-host-99", "beacon-c2.xyz", "attacker.example", "203.0.113.240",
                      "ghost-server-42.internal", "badhost.evil", "8.8.8.8"]
_FABRICATED_MITRE = ["T9999", "T4444", "T1566"]


@pytest.mark.parametrize("text", _ADVERSARIAL)
def test_no_fabricated_entity_survives_the_scrub(text):
    scrubbed, _ = scrub_ungrounded_entities(text, _EVIDENCE)
    for tok in _FABRICATED_TOKENS:
        assert tok not in scrubbed, f"fabricated entity {tok!r} survived scrub"


@pytest.mark.parametrize("text", _ADVERSARIAL)
def test_no_fabricated_mitre_survives_correction(text):
    corrected, _ = correct_mitre_ids(text, _ALLOWED_MITRE)
    for code in _FABRICATED_MITRE:
        assert code not in corrected, f"fabricated MITRE {code!r} survived correction"


def test_grounded_entities_are_preserved():
    # Real evidence entities must NOT be scrubbed.
    text = "alice.tan on wkstn-alice-04 (10.1.2.3) and svc_deploy on srv-ci-02."
    scrubbed, redactions = scrub_ungrounded_entities(text, _EVIDENCE)
    assert redactions == []
    for real in ("alice.tan", "wkstn-alice-04", "10.1.2.3", "svc_deploy", "srv-ci-02"):
        assert real in scrubbed


def test_end_to_end_shipped_text_has_zero_ungrounded():
    # The full guarantee: after scrub + MITRE correction, re-scanning finds nothing ungrounded.
    for text in _ADVERSARIAL:
        s, _ = scrub_ungrounded_entities(text, _EVIDENCE)
        s, _ = correct_mitre_ids(s, _ALLOWED_MITRE)
        residual, _ = scrub_ungrounded_entities(s, _EVIDENCE)   # second pass must be a no-op
        assert residual == s, "shipped text still contained an ungrounded entity"
