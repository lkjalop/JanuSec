import pytest

from src.core.grc.evidence_bridge import (
    export_finding, veeam_verification_evidence, verify_workflow_chain, workflow_event,
)


def test_telemetry_starts_as_possible_weakness_and_closure_requires_evidence():
    event = workflow_event(
        tenant_id="t1", assessment_id="a1", case_id="c1", finding_id="control-1",
        event_type="review_opened", actor="analyst-a",
        data={"supporting_evidence_ids": ["e1"]},
    )
    assert event["classification"] == "possible_control_weakness"
    assert event["framework_mapping_versions"]["iso_27001"] == "ISO/IEC 27001:2022"
    with pytest.raises(ValueError, match="closure_requires_verification_evidence"):
        workflow_event(
            tenant_id="t1", assessment_id="a1", case_id="c1", finding_id="control-1",
            event_type="closed", actor="analyst-a", data={"status": "closed"},
        )


def test_grc_export_is_idempotent_payload_not_external_mutation():
    event = workflow_event(
        tenant_id="t1", assessment_id="a1", case_id="c1", finding_id="control-1",
        event_type="assigned", actor="analyst-a",
        data={"status": "assigned", "control_owner": "identity-team"},
    )
    payload = export_finding(event, "vanta")
    assert payload["idempotency_key"] == event["content_hash"]
    assert payload["dispatched"] is False


def test_veeam_receipt_requires_explicit_successful_recovery_tests():
    verified = veeam_verification_evidence({
        "source_version": "13", "collected_at": "2026-08-21T00:00:00Z",
        "immutability": {"enabled": True},
        "recovery_tests": [{"workload": "finance-db", "result": "passed"}],
    })
    assert verified["verification_status"] == "verified"
    assert verified["provider_native"]["source_version"] == "13"


@pytest.mark.asyncio
async def test_grc_workflow_repository_is_append_only(tmp_path, monkeypatch):
    from src.db.database import close_pool
    from src.repositories.grc_workflow_repo import append_event, list_events

    await close_pool()
    monkeypatch.setenv("DB_FALLBACK_PATH", str(tmp_path / "grc.sqlite"))
    event = workflow_event(
        tenant_id="t1", assessment_id="a1", case_id="c1", finding_id="control-1",
        event_type="review_opened", actor="analyst-a", data={},
    )
    assert (await append_event(event))["appended"] is True
    assert (await append_event(event))["appended"] is False
    assert await list_events("t1", "a1", "c1") == [event]
    assert await list_events("t2", "a1", "c1") == []
    await close_pool()


def test_formal_nonconformity_requires_explicit_human_signoff():
    with pytest.raises(ValueError, match="nonconformity_requires_analyst_signoff"):
        workflow_event(
            tenant_id="t1", assessment_id="a1", case_id="c1", finding_id="control-1",
            event_type="classified", actor="auditor-a",
            data={"classification": "formal_nonconformity"},
        )


def test_workflow_chain_detects_tampering_and_wrong_predecessor():
    first = workflow_event(
        tenant_id="t1", assessment_id="a1", case_id="c1", finding_id="control-1",
        event_type="review_opened", actor="analyst-a", data={},
    )
    second = workflow_event(
        tenant_id="t1", assessment_id="a1", case_id="c1", finding_id="control-1",
        event_type="assigned", actor="owner-a", previous_hash=first["content_hash"],
        data={"status": "assigned"},
    )
    assert verify_workflow_chain([first, second]) == (True, "verified")
    tampered = {**second, "actor": "someone-else"}
    assert verify_workflow_chain([first, tampered])[0] is False


def test_action_workflow_enforces_transition_and_before_after_receipts():
    assigned = workflow_event(
        tenant_id="t1", assessment_id="a1", case_id="c1", finding_id="action-1",
        event_type="assign", actor="commander", data={"status": "assigned"},
    )
    approved = workflow_event(
        tenant_id="t1", assessment_id="a1", case_id="c1", finding_id="action-1",
        event_type="approve", actor="approver", data={"status": "approved"},
        previous_hash=assigned["content_hash"], previous_event=assigned,
    )
    with pytest.raises(ValueError, match="invalid_grc_transition"):
        workflow_event(
            tenant_id="t1", assessment_id="a1", case_id="c1", finding_id="action-1",
            event_type="verify", actor="reviewer", data={"status": "verified", "after_evidence_ids": ["after"]},
            previous_hash=approved["content_hash"], previous_event=approved,
        )
    implementing = workflow_event(
        tenant_id="t1", assessment_id="a1", case_id="c1", finding_id="action-1",
        event_type="implementing", actor="owner", data={"status": "implementing"},
        previous_hash=approved["content_hash"], previous_event=approved,
    )
    with pytest.raises(ValueError, match="implementation_requires_before_and_after"):
        workflow_event(
            tenant_id="t1", assessment_id="a1", case_id="c1", finding_id="action-1",
            event_type="implemented", actor="owner", data={"status": "implemented"},
            previous_hash=implementing["content_hash"], previous_event=implementing,
        )
    implemented = workflow_event(
        tenant_id="t1", assessment_id="a1", case_id="c1", finding_id="action-1",
        event_type="implemented", actor="owner",
        data={"status": "implemented", "before_evidence_ids": ["before"], "after_evidence_ids": ["after"]},
        previous_hash=implementing["content_hash"], previous_event=implementing,
    )
    assert implemented["before_evidence_ids"] == ["before"]
