"""Describe-only trust fixes: verdict/confidence consistency + MITRE correction.

These are the two defects the live VESPER run exposed that undermine a
compromise-assessment buyer's trust: a VALIDATED_BREACH shown at 0.55 confidence,
and wrong MITRE technique IDs (T1547/T1075) shipped when the platform knows the
correct ones (T1528/T1047).
"""
import pytest

from src.core.verdicts import confidence_floor
from src.core.ingest.entity_constraints import correct_mitre_ids

pytestmark = pytest.mark.acceptance


def test_confidence_floor_matches_verdict_strength():
    assert confidence_floor("VALIDATED_BREACH") == 0.75
    assert confidence_floor("CONFIRMED_INTRUSION") == 0.75
    assert confidence_floor("INCIDENT") == 0.75
    assert confidence_floor("LIKELY_BREACH") == 0.55
    assert confidence_floor("SUSPECTED_BREACH") == 0.50
    assert confidence_floor("BENIGN_EXPECTED") == 0.0
    assert confidence_floor("validated_breach") == 0.75  # case-insensitive


def test_validated_breach_confidence_is_floored_in_narrative():
    # A VALIDATED_BREACH cluster whose (LLM) confidence came out 0.55 must not display
    # a confidence that contradicts the verdict.
    from src.core.ingest.cluster_narrator import _apply_narrative_to_cluster
    cluster = {"cluster_id": "c1", "final_verdict": "VALIDATED_BREACH", "confidence": 0.55}
    narrative = {"verdict": "VALIDATED_BREACH", "confidence": 0.55, "kill_chain_stage": "exfiltration"}
    _apply_narrative_to_cluster(cluster, narrative, upgrade_only=True)
    assert cluster["confidence"] >= 0.75
    assert cluster.get("_confidence_floored") is True
    assert cluster.get("_confidence_pre_floor") == 0.55


def test_high_confidence_breach_not_altered():
    from src.core.ingest.cluster_narrator import _apply_narrative_to_cluster
    cluster = {"cluster_id": "c2", "final_verdict": "VALIDATED_BREACH", "confidence": 0.92}
    narrative = {"verdict": "VALIDATED_BREACH", "confidence": 0.92, "kill_chain_stage": "impact"}
    _apply_narrative_to_cluster(cluster, narrative, upgrade_only=True)
    assert abs(cluster["confidence"] - 0.92) < 1e-9
    assert not cluster.get("_confidence_floored")


def test_wrong_mitre_ids_removed_correct_kept():
    allowed = {"T1528", "T1047", "T1558.003"}
    txt = "oauth_device_code (T1547), wmi_dcom_lateral (T1075), kerberoasting (T1558.003)"
    out, removed = correct_mitre_ids(txt, allowed)
    assert "T1547" not in out and "T1075" not in out
    assert "T1558.003" in out
    assert {r["code"] for r in removed} == {"T1547", "T1075"}


def test_base_technique_tolerated():
    # Prose citing the base technique is kept when a sub-technique is allowed.
    out, removed = correct_mitre_ids("Kerberoasting (T1558) then WMI (T1047).", {"T1558.003", "T1047"})
    assert "T1558" in out and "T1047" in out
    assert removed == []


def test_mitre_correction_noop_without_allowed_set():
    assert correct_mitre_ids("attacker used (T9999)", set()) == ("attacker used (T9999)", [])


def test_evidence_refs_translate_prompt_positions_to_absolute_indices():
    from src.core.ingest.cluster_narrator import _translate_evidence_refs
    # evidence in prompt order; the LLM cites 1-based positions into this list.
    ev = [{"row_index": 8}, {"row_index": 26}, {"row_index": 47}, {"row_index": 48}, {"row_index": 52}]
    assert _translate_evidence_refs([1, 3, 5], ev) == [8, 47, 52]  # positions -> real event indices
    assert _translate_evidence_refs([99, 2], ev) == [26]           # out-of-range dropped
    assert _translate_evidence_refs([], ev) == []
    assert _translate_evidence_refs(None, ev) == []
    # citations must be a subset of the provenance (the fed rows)
    provenance = {r["row_index"] for r in ev}
    assert set(_translate_evidence_refs([1, 3, 5], ev)) <= provenance
