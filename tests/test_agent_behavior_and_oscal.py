from copy import deepcopy
import base64
import json
import pytest
from src.core.agent_behavior import build_reviewed_baseline, evaluate_agent_event
from src.core.evidence_contract.records import canonical_hash


def _event():
    return {"tenant_id": "t", "agent_id": "a", "tool_calls": 3, "unique_tools": 2,
            "write_calls": 0, "external_destinations": 0}


def test_agent_evaluation_does_not_train_on_anomalous_input():
    descriptor = {"name": "search", "description": "Read case evidence", "inputSchema": {"type": "object"}}
    baseline = build_reviewed_baseline(tenant_id="t", agent_id="a", samples=[_event() for _ in range(20)],
                                      descriptors={"search": descriptor}, review_receipt="review-fixture-1")
    original = deepcopy(baseline)
    assert evaluate_agent_event(_event(), baseline, descriptors={"search": descriptor})["status"] == "within_reviewed_baseline"
    hostile = {**_event(), "tool_calls": 100, "write_calls": 25}
    changed = {**descriptor, "inputSchema": {"type": "object", "properties": {"secret": {"type": "string"}}}}
    result = evaluate_agent_event(hostile, baseline, descriptors={"search": changed})
    assert {s["factor"] for s in result["signals"]} >= {"agent:tool_calls_spike", "agent:write_calls_spike", "agent:tool_descriptor_drift"}
    assert baseline == original
    assert result["assertion_status"] == "candidate"
    assert evaluate_agent_event(_event(), None, descriptors={})["status"] == "baseline_unavailable"
    with pytest.raises(ValueError, match="tenant_or_agent"):
        evaluate_agent_event({**_event(), "tenant_id": "other"}, baseline, descriptors={})
    with pytest.raises(ValueError, match="cold_start"):
        build_reviewed_baseline(tenant_id="t", agent_id="a", samples=[_event()], descriptors={}, review_receipt="review")


def _profile():
    from src.core.mappings.catalog_validation import catalog_index
    return {"tenant_id": "t", "framework": "nist_800_53", "catalog_version": catalog_index()["metadata"]["version"],
            "control_ids": ["AC-2"], "assessment_plan_href": "https://customer.example/plan.json"}


def test_oscal_uses_customer_scope_and_embeds_verifiable_evidence():
    from src.reporting.oscal_export import export_case_evidence, validate_oscal
    view = {"case": {"id": "a", "tenant_id": "t"}, "evidence": {"rows": [{"id": "e1"}]},
            "control_impacts": [{"id": "c", "framework": "nist_800_53", "control_id": "AC-2"}]}
    document = export_case_evidence(view, _profile(), tenant_id="t")
    validate_oscal(document)
    ar = document["assessment-results"]
    assert "findings" not in ar["results"][0]
    assert "include-controls" not in ar["results"][0]["reviewed-controls"]["control-selections"][0]
    resource = ar["back-matter"]["resources"][0]
    embedded = json.loads(base64.b64decode(resource["base64"]["value"]))
    assert embedded == view
    assert resource["props"][0]["value"] == canonical_hash(embedded)
    with pytest.raises(ValueError, match="customer_scope"):
        export_case_evidence(view, {**_profile(), "tenant_id": "other"}, tenant_id="t")
    with pytest.raises(ValueError, match="active_control_scope"):
        export_case_evidence(view, {**_profile(), "control_ids": ["AC-9999"]}, tenant_id="t")


def test_oscal_rejects_unpinned_catalog_version():
    from src.reporting.oscal_export import export_case_evidence
    with pytest.raises(ValueError, match="version_not_supported"):
        export_case_evidence({"case": {"id": "a", "tenant_id": "t"}}, {**_profile(), "catalog_version": "unknown"}, tenant_id="t")
