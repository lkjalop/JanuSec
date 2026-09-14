from src.core.model_evaluation import evaluate_model_output


def _view():
    return {
        "posture": {"breach_status": "confirmed"},
        "evidence": {"rows": [{"id": "e1"}, {"id": "e2"}]},
        "claims": [],
    }


def test_grounded_model_output_receives_attribution_and_calibration_metrics():
    output = {
        "what_happened": "Observed execution.",
        "entry_point": "OAuth consent.",
        "evidence_ids_by_field": {"what_happened": ["e1"], "entry_point": ["e2"], "alternative_hypotheses": ["e1"]},
        "overall_confidence": 0.8,
        "alternative_hypotheses": ["authorized testing"],
    }
    result = evaluate_model_output(output, _view(), latency_ms=1200)
    assert result["action"] == "accept"
    assert result["attribution_quality"] == 1.0
    assert result["calibration_brier"] == 0.04
    assert result["time_to_defensible_conclusion_ms"] == 1200


def test_uncited_or_unknown_evidence_is_not_defensible():
    output = {"what_happened": "Claim", "evidence_ids_by_field": {"what_happened": ["invented"]}}
    result = evaluate_model_output(output, _view())
    assert result["action"] == "refine"
    assert result["unsupported_claim_rate"] == 1.0
    assert "unknown_evidence_ids:invented" in result["gaps"]


def test_milestone_and_graph_evidence_are_eligible_model_citations():
    view = _view()
    view["attack_story"] = {"milestones": [{"evidence_ids": ["e3"]}]}
    view["graph"] = {"edges": [{"evidence_ids": ["e4"]}]}
    output = {
        "what_happened": "Observed sequence.",
        "entry_point": "Candidate entry.",
        "evidence_ids_by_field": {"what_happened": ["e3"], "entry_point": ["e4"]},
    }
    result = evaluate_model_output(output, view)
    assert result["action"] == "accept"
    assert result["attribution_quality"] == 1.0


def test_explicit_provisional_fields_are_abstentions_not_unsupported_claims():
    output = {
        "what_happened": "Observed execution.",
        "entry_point": "provisional",
        "persistence": "Insufficient evidence",
        "evidence_ids_by_field": {"what_happened": ["e1"]},
    }
    result = evaluate_model_output(output, _view())
    assert result["action"] == "accept"
    assert result["attribution_quality"] == 1.0
    assert result["unsupported_claim_rate"] == 0.0


def test_total_abstention_is_not_an_unsupported_claim_or_an_accepted_conclusion():
    result = evaluate_model_output({"what_happened": "Insufficient evidence"}, _view())
    assert result["action"] == "abstain"
    assert result["unsupported_claim_rate"] == 0
    assert result["factual_field_count"] == 0
    assert result["time_to_defensible_conclusion_ms"] is None
