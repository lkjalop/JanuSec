from src.api.case_intelligence_endpoints import _correction_improves, _corrective_query, _deterministic_narration


def test_corrective_query_changes_focus_and_includes_case_entities():
    output = {"entry_point": "OAuth", "evidence_ids_by_field": {}}
    metrics = {"attribution_quality": 0.25, "evidence_recall": 0.1}
    view = {"entity_roles": [{"role": "actor", "entity": "alice@example.com"}]}
    query = _corrective_query(output, metrics, view)
    assert "denied, failed, blocked" in query
    assert "actor versus victim/target" in query
    assert "alice@example.com" in query


def test_correction_is_selected_only_for_better_grounding():
    weak = {"unsupported_claim_rate": 0.5, "attribution_quality": 0.5, "evidence_recall": 0.1}
    better = {"unsupported_claim_rate": 0.0, "attribution_quality": 1.0, "evidence_recall": 0.2}
    fluent_but_worse = {"unsupported_claim_rate": 0.75, "attribution_quality": 0.25, "evidence_recall": 0.8}
    assert _correction_improves(weak, better)
    assert not _correction_improves(weak, fluent_but_worse)


def test_deterministic_narration_cites_server_owned_evidence():
    output = _deterministic_narration({
        "posture": {"breach_status": "confirmed", "evidence_confidence": 0.9},
        "breach_summary": {"headline": "Confirmed", "what_happened": "Observed activity.", "supporting_evidence_ids": ["ev-1"]},
        "attack_story": {"milestones": [{"phase": "initial_access", "summary": "OAuth grant", "evidence_ids": ["ev-2"]}]},
        "coverage_gaps": ["CMDB missing"], "immediate_decisions": [],
    })
    assert output["generated_by"] == "deterministic_case_projection"
    assert output["evidence_ids_by_field"]["what_happened"] == ["ev-1"]
    assert output["evidence_ids_by_field"]["entry_point"] == ["ev-2"]
