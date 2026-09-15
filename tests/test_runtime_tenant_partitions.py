from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api import custody
from src.api.graph_sessions import _tenant_runtime_view
from src.api.runtime_state import (
    ServerRuntime,
    get_file_batch_analysis,
    get_tenant_runtime,
)
from src.api.tenant_middleware import TenantMiddleware


def test_tenant_runtime_partitions_are_real_and_isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("TENANT_PERSIST_DIR", str(tmp_path / "tenants"))
    runtime = ServerRuntime()

    tenant_a = get_tenant_runtime(runtime, "tenant-a")
    tenant_b = get_tenant_runtime(runtime, "tenant-b")
    tenant_a["ewma_history"]["same-pair"] = (7.0, 1.0)
    get_file_batch_analysis(runtime, "tenant-a")["batch-1"] = {
        "tenant_id": "tenant-a"
    }

    assert tenant_a is get_tenant_runtime(runtime, "tenant-a")
    assert tenant_a is not tenant_b
    assert "same-pair" not in tenant_b["ewma_history"]
    assert "batch-1" not in get_file_batch_analysis(runtime, "tenant-b")
    assert "batch-1" not in get_file_batch_analysis(runtime)


@pytest.mark.parametrize("tenant_id", ["../tenant-b", "CON", "tenant."])
def test_tenant_runtime_rejects_path_like_identifier(tenant_id):
    with pytest.raises(ValueError, match="invalid_tenant_id"):
        get_tenant_runtime(ServerRuntime(), tenant_id)


def test_detector_runtime_view_excludes_global_and_other_tenant_events():
    runtime = ServerRuntime()
    runtime.nx_rate_tracker["global-producer"].extend([True] * 8)
    get_tenant_runtime(runtime, "tenant-a")["nx_rate_tracker"]["a"].extend([True] * 8)
    runtime.sanitized_events.extend(
        (
            {"tenant_id": "tenant-a", "event_id": "a"},
            {"tenant_id": "tenant-b", "event_id": "b"},
            {"event_id": "legacy-unscoped"},
        )
    )

    view = _tenant_runtime_view(runtime, "tenant-b", allow_legacy_demo_data=False)

    assert dict(view.nx_rate_tracker) == {}
    assert [event["event_id"] for event in view.sanitized_events] == ["b"]


def test_file_batch_cache_enforces_tenant_ownership(monkeypatch):
    runtime = ServerRuntime()
    app = FastAPI()
    app.add_middleware(TenantMiddleware)
    app.include_router(custody.router)
    monkeypatch.setattr(custody, "get_server_runtime_state", lambda _app: runtime)
    monkeypatch.setattr(custody, "_append_custody", AsyncMock())
    client = TestClient(app)

    created = client.post(
        "/files/batch",
        json={"batch_id": "batch-shared-name", "files": [{"sha256": "hash-a"}]},
        headers={"X-Tenant-ID": "tenant-a"},
    )
    assert created.status_code == 200, created.text
    assert created.json()["tenant_id"] == "tenant-a"

    owned = client.get(
        "/files/batch/analysis/batch-shared-name",
        headers={"X-Tenant-ID": "tenant-a"},
    )
    cross_tenant = client.get(
        "/files/batch/analysis/batch-shared-name",
        headers={"X-Tenant-ID": "tenant-b"},
    )

    assert owned.status_code == 200
    assert owned.json()["tenant_id"] == "tenant-a"
    assert cross_tenant.status_code == 404


@pytest.mark.asyncio
async def test_custody_log_is_partitioned_by_tenant_outside_tests(monkeypatch, tmp_path):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    runtime = ServerRuntime()
    runtime.file_custody_path = tmp_path / "custody" / "custody.jsonl"
    item = custody.FileItem(sha256="a" * 64)

    await custody._append_custody(runtime, "tenant-a", "batch-1", item, ["observed"])

    assert (tmp_path / "custody" / "tenant-a" / "custody.jsonl").exists()
    assert not runtime.file_custody_path.exists()
