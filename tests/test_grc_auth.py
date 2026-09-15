"""#1 Auth: GRC / evidence endpoints require an API key in production, bypass in
lite/dev/test/demo so the acceptance suite and local demos still work."""
import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.grc_endpoints import router
from src.api.deep_analyze.persistence import REPORT_STORE
from src.core.grc.nonconformity import build_audit_pack

pytestmark = pytest.mark.acceptance

_BYPASS_ENVS = ("PLATFORM_LITE_INIT", "FAST_TEST_MODE", "JANUSEC_DEV_MODE",
                "TEST_HELPERS_ENABLED", "PYTEST_CURRENT_TEST")


def _seed():
    REPORT_STORE["auth-x"] = {"org": "default", "audit_pack": build_audit_pack([
        {"cluster_id": "c", "final_verdict": "VALIDATED_BREACH", "severity": "critical",
         "shared_users": ["u"], "factor_tags": ["kerberoasting"]}])}


def _client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_lite_mode_does_not_bypass_authentication():
    _seed()
    assert _client().get("/api/v1/assessments/auth-x/audit-pack").status_code == 401


def test_enforced_in_production_mode(monkeypatch):
    _seed()
    for k in _BYPASS_ENVS:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("API_KEYS_JSON", '[{"key":"secret-key-123","scopes":["grc:read"],"tenant_id":"default"}]')
    c = _client()
    assert c.get("/api/v1/assessments/auth-x/audit-pack").status_code == 401
    assert c.get("/api/v1/assessments/auth-x/audit-pack", headers={"X-API-Key": "nope"}).status_code == 401
    assert c.get("/api/v1/assessments/auth-x/audit-pack", headers={"X-API-Key": "secret-key-123"}).status_code == 200
    # governance posture endpoint is gated too
    assert c.get("/api/v1/ai-governance").status_code == 401
    assert c.get("/api/v1/ai-governance", headers={"X-API-Key": "secret-key-123"}).status_code == 200
