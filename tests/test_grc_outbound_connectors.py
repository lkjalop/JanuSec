import pytest

from src.core.grc.outbound_connectors import GRCConnectorConfig, dispatch_approved_finding


def test_dispatch_requires_explicit_approval_and_preserves_idempotency():
    config = GRCConnectorConfig("servicenow", "https://example.test/api/now/table/incident", "secret")
    export = {"target":"servicenow", "idempotency_key":"hash-1", "finding":{"title":"Finding"}}
    with pytest.raises(PermissionError):
        dispatch_approved_finding(
            export_payload=export, config=config, approved_by="approver", approval_receipt_hash="approval-1",
            explicit_approval=False, sender=lambda *_: (201, {"result":{"sys_id":"abc"}}),
        )
    captured = {}
    def sender(_config, body, headers):
        captured.update({"body": body, "headers": headers})
        return 201, {"result":{"sys_id":"abc"}}
    receipt = dispatch_approved_finding(
        export_payload=export, config=config, approved_by="approver", approval_receipt_hash="approval-1",
        explicit_approval=True, sender=sender,
    )
    assert receipt["status"] == "dispatched"
    assert receipt["external_id"] == "abc"
    assert captured["headers"]["Idempotency-Key"] == "hash-1"
    assert b"secret" not in captured["body"]


@pytest.mark.asyncio
async def test_dispatch_receipts_are_tenant_scoped_and_idempotent(tmp_path, monkeypatch):
    from src.db.database import close_pool
    from src.repositories.grc_dispatch_repo import (
        append_receipt, get_receipt_by_idempotency, list_receipts,
    )

    await close_pool()
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("DB_FALLBACK_PATH", str(tmp_path / "dispatch.sqlite"))
    receipt = {
        "content_hash": "receipt-hash", "target": "servicenow",
        "idempotency_key": "finding-hash", "status": "dispatched",
    }
    assert await append_receipt(
        tenant_id="t1", assessment_id="a1", case_id="c1", receipt=receipt,
    ) is True
    assert await append_receipt(
        tenant_id="t1", assessment_id="a1", case_id="c1", receipt=receipt,
    ) is False
    assert await get_receipt_by_idempotency(
        tenant_id="t1", assessment_id="a1", case_id="c1",
        target="servicenow", idempotency_key="finding-hash",
    ) == receipt
    assert await list_receipts(tenant_id="t1", assessment_id="a1", case_id="c1") == [receipt]
    assert await list_receipts(tenant_id="t2", assessment_id="a1", case_id="c1") == []
    await close_pool()
