from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.core.detectors import api_security
from src.core.detectors.api_security import analyze_api_event, is_api_event

VECTORS = Path("tests/data/api_security_auth_harness.json")


@pytest.fixture(autouse=True)
def configure_inventory(monkeypatch):
    spec_path = Path("tests/data/min_openapi.json")
    monkeypatch.setattr(api_security, "API_SPEC_PATH", spec_path)
    monkeypatch.setattr(api_security, "BUSINESS_FLOW_PATH", Path("config/api_business_flows.json"))
    api_security._business_flow_fixtures.cache_clear()
    api_security.refresh_api_inventory_cache()


@pytest.mark.parametrize("vector", json.loads(VECTORS.read_text(encoding="utf-8")))
def test_api_security_auth_harness_vectors(vector):
    event = vector["event"]
    expected = set(vector.get("expected", {}).get("factors_contains") or [])
    if not is_api_event(event):
        pytest.skip("vector not applicable to API detector")
    analysis = analyze_api_event(event)
    for factor in expected:
        assert factor in analysis.factors, f"missing {factor} for {vector['name']}"


def test_inventory_snapshot_reports_missing_routes(monkeypatch):
    spec_path = Path("tests/data/min_openapi.json")
    monkeypatch.setattr(api_security, "API_SPEC_PATH", spec_path)
    api_security.refresh_api_inventory_cache()
    snapshot = api_security.get_inventory_snapshot(["/api/v1/users/123", "/shadow/new"])
    assert snapshot["spec_version"] == "1.0.0"
    assert "/shadow/new" in snapshot["missing_routes"]
