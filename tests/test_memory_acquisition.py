from __future__ import annotations

import time
from unittest.mock import patch

from src.artifact.memory_acquisition import MemoryAcquisitionGuide


def test_courier_plan_ttl_and_listing(tmp_path):
    guide = MemoryAcquisitionGuide(manifest_path=tmp_path / "manifest.json", plan_ttl_seconds=1)
    plan = guide.issue_plan(host="host-a", os_family="windows", case_id="case1", tenant_id="tenant", courier_profile="default")
    # Force plan to appear expired
    with guide._lock:  # type: ignore[attr-defined]
        guide._plans[plan.attestation_id].issued_at -= 120  # type: ignore[attr-defined]
        guide._plans[plan.attestation_id].expires_at = guide._plans[plan.attestation_id].issued_at + 1  # type: ignore[attr-defined]
    plans = guide.list_plans(limit=1)
    assert plans[0]["sla_breach"], "plan should show SLA breach when TTL exceeded"
    guide.record_event(plan.attestation_id, event="revoke")
    plans = guide.list_plans(limit=1)
    assert plans[0]["revoked"], "revocation should be recorded"


def test_courier_alerts_fan_out(tmp_path):
    with patch.dict(
        "os.environ",
        {"COURIER_ALERT_WEBHOOK": "https://courier.example/hooks", "SOAR_ALERT_WEBHOOK": "https://soar.example/hooks"},
    ):
        guide = MemoryAcquisitionGuide(manifest_path=tmp_path / "manifest.json", plan_ttl_seconds=1)
        plan = guide.issue_plan(host="host-a", os_family="windows", case_id="case1", tenant_id="tenant", courier_profile="default")
        with guide._lock:  # type: ignore[attr-defined]
            guide._plans[plan.attestation_id].issued_at -= 7200  # type: ignore[attr-defined]
            guide._plans[plan.attestation_id].expires_at = guide._plans[plan.attestation_id].issued_at + 1  # type: ignore[attr-defined]
        with patch("src.artifact.memory_acquisition.post_webhook") as mocked_hook:
            guide.record_event(plan.attestation_id, event="heartbeat")
            assert mocked_hook.call_count == 2, "alerts should fan out to courier + SOAR targets"
