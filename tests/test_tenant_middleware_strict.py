from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.api.tenant_middleware import TenantMiddleware


def _client() -> TestClient:
    app = FastAPI()
    app.add_middleware(TenantMiddleware)

    @app.get("/api/v1/scoped")
    async def _scoped(request: Request):
        return {"tenant_id": request.state.tenant_id}

    @app.get("/health")
    async def _health(request: Request):
        return {"tenant_id": request.state.tenant_id}

    return TestClient(app)


def test_middleware_rejects_unsafe_tenant_identifier():
    response = _client().get(
        "/api/v1/scoped", headers={"X-Tenant-ID": "../tenant-b"}
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "invalid_tenant_id"}


def test_middleware_propagates_validated_tenant_identifier():
    response = _client().get(
        "/api/v1/scoped", headers={"X-Tenant-ID": "tenant-a"}
    )

    assert response.status_code == 200
    assert response.json() == {"tenant_id": "tenant-a"}
    assert response.headers["X-Tenant-ID"] == "tenant-a"


def test_middleware_fails_closed_for_invalid_default_tenant(monkeypatch):
    monkeypatch.setenv("DEFAULT_TENANT", "../default")

    response = _client().get("/health")

    assert response.status_code == 500
    assert response.json() == {"detail": "invalid_default_tenant"}
