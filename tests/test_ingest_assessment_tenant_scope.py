from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException
from fastapi.testclient import TestClient

from src.api.ingest_endpoints import router
from src.api.tenant_middleware import TenantMiddleware
from src.core.ingest import store
from src.security.auth import AuthContext, require_api_key


def _client() -> TestClient:
    app = FastAPI()
    app.add_middleware(TenantMiddleware)

    async def _header_auth(x_api_key: str | None = Header(None)) -> AuthContext:
        tenants = {"key-a": "tenant-a", "key-b": "tenant-b"}
        tenant_id = tenants.get(x_api_key or "")
        if tenant_id is None:
            raise HTTPException(status_code=401, detail="unauthorized")
        return AuthContext(f"api-key:{tenant_id}", ["*"], tenant_id=tenant_id)

    app.dependency_overrides[require_api_key] = _header_auth
    app.include_router(router)
    return TestClient(app)


def _headers(tenant: str, key: str) -> dict[str, str]:
    return {"X-Tenant-ID": tenant, "x-api-key": key}


def _job() -> dict:
    return {
        "assessment_id": "assessment-a",
        "org": "tenant-a",
        "status": "running",
        "stage": "normalize",
        "stage_label": "Normalize",
        "percent": 40,
        "row_count": 12,
        "cluster_count": 1,
        "error": None,
    }


def test_owner_can_poll_assessment(monkeypatch):
    monkeypatch.setattr(store, "get_job", lambda assessment_id: _job())

    response = _client().get(
        "/api/v1/assessments/assessment-a/progress/poll",
        headers=_headers("tenant-a", "key-a"),
    )

    assert response.status_code == 200
    assert response.json()["assessment_id"] == "assessment-a"


def test_foreign_tenant_cannot_read_or_cancel_assessment(monkeypatch):
    updates: list[tuple] = []
    monkeypatch.setattr(store, "get_job", lambda assessment_id: _job())
    monkeypatch.setattr(
        store, "update_job", lambda *args, **kwargs: updates.append((args, kwargs))
    )
    monkeypatch.setattr(
        store,
        "count_evidence_rows",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("foreign evidence query reached storage")
        ),
    )

    client = _client()
    headers = _headers("tenant-b", "key-b")
    requests = [
        client.get(
            "/api/v1/assessments/assessment-a/progress", headers=headers
        ),
        client.get(
            "/api/v1/assessments/assessment-a/progress/poll", headers=headers
        ),
        client.get(
            "/api/v1/assessments/assessment-a/evidence", headers=headers
        ),
        client.post(
            "/api/v1/assessments/assessment-a/cancel", headers=headers
        ),
    ]

    assert [response.status_code for response in requests] == [404, 404, 404, 404]
    assert all(
        response.json()["detail"] == "Assessment not found"
        for response in requests
    )
    assert updates == []


def test_auth_tenant_binding_rejects_conflicting_header(monkeypatch):
    monkeypatch.setattr(store, "get_job", lambda assessment_id: _job())

    response = _client().get(
        "/api/v1/assessments/assessment-a/progress/poll",
        headers=_headers("tenant-b", "key-a"),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "tenant_mismatch"


def test_assessment_list_is_filtered_and_bounded(monkeypatch):
    captured: dict = {}

    class _Connection:
        def execute(self, query: str, params: list[object]):
            captured["query"] = query
            captured["params"] = params
            return self

        def fetchall(self):
            return [
                (
                    "assessment-a",
                    "tenant-a",
                    "ready",
                    "complete",
                    100,
                    12,
                    1,
                    "2026-08-18T00:00:00Z",
                )
            ]

    monkeypatch.setattr(store, "_db", lambda: _Connection())

    response = _client().get(
        "/api/v1/assessments/?limit=999",
        headers=_headers("tenant-a", "key-a"),
    )

    assert response.status_code == 200
    assert response.json()["jobs"][0]["org"] == "tenant-a"
    assert "WHERE org = ?" in captured["query"]
    assert captured["params"] == ["tenant-a", 200]


def test_progress_endpoint_does_not_accept_api_key_in_url(monkeypatch):
    monkeypatch.setattr(store, "get_job", lambda assessment_id: _job())

    response = _client().get(
        "/api/v1/assessments/assessment-a/progress?token=key-a",
        headers={"X-Tenant-ID": "tenant-a"},
    )

    assert response.status_code == 401

