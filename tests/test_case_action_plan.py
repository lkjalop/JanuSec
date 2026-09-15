from src.core.grc.action_plan import build_case_action_plan
from src.api.models.case_evidence import CaseActionPlan


def test_action_plan_prioritizes_response_and_keeps_control_mapping_informative():
    plan = build_case_action_plan(
        case_id="case-1",
        containment=[{
            "action": "Revoke the affected session", "priority": "critical",
            "owner_role": "identity_owner", "evidence_ids": ["ev-1"],
        }],
        immediate_decisions=[{
            "decision": "Determine whether regulated data was accessed",
            "rationale": "Data classification is not attached", "evidence_ids": ["ev-2"],
        }],
        control_impacts=[{
            "id": "iso:A.5.15", "framework": "iso_27001", "control_id": "A.5.15",
            "title": "Access control", "assertion_status": "possible_control_weakness",
            "basis": "Successful access was observed", "supporting_evidence_ids": ["ev-1"],
        }],
        grc_assignments=[], infrastructure_truth={},
    )
    assert plan["schema_version"] == "janusec.case-action-plan/v1"
    assert plan["actions"][0]["horizon"] == "now"
    assert plan["actions"][0]["recommendation_status"] == "required_response"
    control = next(item for item in plan["actions"] if item["action_type"] == "control_correction")
    assert control["mapping_status"] == "informative_until_grc_review"
    assert "formal nonconformity requires authorized review" in control["control_consequence"]
    assert {item["id"] for item in plan["decisions_required"]} == {
        "decision-authorization-scope", "decision-reachability-scope", "decision-business-impact",
        "decision-data-classification", "decision-regulatory-applicability",
    }
    collection_tasks = [item for item in plan["actions"] if item["action_type"] == "evidence_collection"]
    assert len(collection_tasks) == 5
    assert all(item["recommendation_status"] == "required_information_collection" for item in collection_tasks)
    assert all("read-only" in " ".join(item["preconditions"]).lower() for item in collection_tasks)
    CaseActionPlan.model_validate(plan)


def test_action_plan_does_not_promote_uncited_containment_to_required_response():
    plan = build_case_action_plan(
        case_id="case-2", containment=[{"action": "Isolate the host"}],
        immediate_decisions=[], control_impacts=[], grc_assignments=[],
        infrastructure_truth={
            "iam": {"status": "verified"}, "topology": {"status": "verified"},
            "cmdb": {"status": "verified"}, "data_classification": {"status": "verified"},
            "regulatory_applicability": {"status": "verified"},
        },
    )
    assert plan["actions"][0]["recommendation_status"] == "suggested_investigation"
    assert plan["decisions_required"] == []
