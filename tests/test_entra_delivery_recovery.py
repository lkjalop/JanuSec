import json
from types import SimpleNamespace
import pytest
from src.connectors.azure.base import AzureConnectorConfig, checkpoint_path
from src.connectors.azure.entra_id import EntraIDConnector


def _row(id, second):
    return {"id": id, "createdDateTime": f"2026-01-01T00:00:{second:02}Z", "status": {"errorCode": 0}}


def test_paginated_collection_receipts_and_restart_cursor(tmp_path):
    cfg = AzureConnectorConfig(tenant_id="provider-a", checkpoint_dir=str(tmp_path), customer_tenant_id="customer-a")
    requests = []
    link = "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=opaque"
    def fetch(kind, args):
        requests.append(args)
        return {"value": [_row("older", 1)]} if "next_link" in args else {"value": [_row("newest", 9)], "@odata.nextLink": link}
    conn = EntraIDConnector(cfg, request_json=fetch)
    conn.defer_checkpoint = True
    rows = list(conn.fetch_signins())
    assert len(rows) == 2
    assert conn.ck == {}
    assert requests[1] == {"next_link": link}
    assert all(json.loads(open(row["raw_receipt_path"], encoding="utf-8").read())["provider_native"]["id"] == row["id"] for row in rows)
    conn.acknowledge_delivery()
    restarted = EntraIDConnector(cfg, request_json=fetch)
    assert restarted.ck["signins_last_ts"].endswith("09Z")
    list(restarted.fetch_signins())
    assert requests[2]["since_ts"].endswith("09Z")
    other = AzureConnectorConfig(tenant_id="provider-a", checkpoint_dir=str(tmp_path), customer_tenant_id="customer-b")
    assert checkpoint_path("entra_id", cfg) != checkpoint_path("entra_id", other)
    assert EntraIDConnector(other, request_json=fetch).ck == {}


def test_partial_page_failure_does_not_advance_cursor(tmp_path):
    cfg = AzureConnectorConfig(tenant_id="a", checkpoint_dir=str(tmp_path))
    def fetch(kind, args):
        if "next_link" in args:
            raise RuntimeError("provider unavailable")
        return {"value": [_row("a", 1)], "@odata.nextLink": "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=2"}
    conn = EntraIDConnector(cfg, request_json=fetch)
    with pytest.raises(RuntimeError, match="unavailable"):
        list(conn.fetch_signins())
    conn.acknowledge_delivery()
    assert EntraIDConnector(cfg, request_json=fetch).ck == {}


def test_cross_origin_next_link_rejected(tmp_path):
    cfg = AzureConnectorConfig(tenant_id="a", checkpoint_dir=str(tmp_path))
    conn = EntraIDConnector(cfg, request_json=lambda *_: {"value": [], "@odata.nextLink": "https://attacker.example/steal"})
    with pytest.raises(ValueError, match="untrusted_graph"):
        list(conn.fetch_signins())


def test_iso_checkpoint_is_used_as_graph_filter(tmp_path, monkeypatch):
    conn = EntraIDConnector(AzureConnectorConfig(tenant_id="a", checkpoint_dir=str(tmp_path)))
    calls = []
    monkeypatch.setattr(conn, "_graph_get", lambda path, params: calls.append(params) or {"value": []})
    conn._signins_from_graph("2026-01-01T00:00:09Z")
    assert calls[0]["$filter"] == "createdDateTime ge 2026-01-01T00:00:09Z"


def test_delivered_rows_survive_runtime_restart_and_deduplicate(tmp_path, monkeypatch):
    monkeypatch.setenv("JANUSEC_CONNECTOR_RECEIPTS_DB", str(tmp_path / "delivery.sqlite"))
    from src.api.routes.connectors import _append_events, _dedupe_events, _runtime_events_to_assessment_rows
    runtime = SimpleNamespace(tenants={})
    event = {"id": "one", "tenant_id": "tenant-a", "connector_id": "azure:entra_signin", "ts": "2026-01-01T00:00:00Z"}
    fresh, _ = _dedupe_events(runtime, "tenant-a", "azure", "entra_signin", [event])
    _append_events(runtime, "tenant-a", "entra_signin", fresh)
    restarted = SimpleNamespace(tenants={})
    assert _dedupe_events(restarted, "tenant-a", "azure", "entra_signin", [event]) == ([], 1)
    rows = _runtime_events_to_assessment_rows(restarted, tenant="tenant-a", provider_filter={"azure"}, connector_filter={"entra_signin"}, limit_per_lane=100, include_email=False)
    assert len(rows) == 1 and rows[0]["id"] == "one"
    other = _runtime_events_to_assessment_rows(restarted, tenant="tenant-b", provider_filter=set(), connector_filter=set(), limit_per_lane=100, include_email=False)
    assert other == []
