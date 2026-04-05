from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from src.api.server import app
from src.core.detectors import api_security

client = TestClient(app)


def _configure_spec(monkeypatch) -> None:
    spec_path = Path("tests/data/min_openapi.json")
    monkeypatch.setattr(api_security, "API_SPEC_PATH", spec_path)
    api_security.refresh_api_inventory_cache()


def test_inventory_endpoint_returns_metadata(monkeypatch):
    _configure_spec(monkeypatch)
    response = client.get("/api/v1/api_security/inventory")
    assert response.status_code == 200
    payload = response.json()
    assert payload["spec_version"] == "1.0.0"
    assert payload["route_count"] >= 2


def test_inventory_assert_flags_missing(monkeypatch):
    _configure_spec(monkeypatch)
    response = client.post("/api/v1/api_security/inventory/assert", json={"observed_routes": ["/shadow/new"]})
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "/shadow/new" in detail["missing_routes"]


def test_inventory_reload(monkeypatch):
    _configure_spec(monkeypatch)
    response = client.post("/api/v1/api_security/inventory/reload")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "reloaded"
