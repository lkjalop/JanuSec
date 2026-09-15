from __future__ import annotations

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from src.api.tenant_helpers import (
    resolve_tenant_id,
    resolve_tenant_with_default,
    validate_tenant_id,
)


def _request(tenant: str | None = None, *, state_tenant: str | None = None) -> Request:
    headers = []
    if tenant is not None:
        headers.append((b"x-tenant-id", tenant.encode("utf-8")))
    request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/api/v1/example",
            "raw_path": b"/api/v1/example",
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 1234),
            "server": ("testserver", 80),
        }
    )
    if state_tenant is not None:
        request.state.tenant_id = state_tenant
    return request


def test_transport_tenant_is_authoritative_even_in_test_mode(monkeypatch):
    monkeypatch.setenv("TEST_HELPERS_ENABLED", "1")
    monkeypatch.setenv("PLATFORM_LITE_INIT", "1")
    request = _request("tenant-a", state_tenant="tenant-a")

    with pytest.raises(HTTPException) as exc:
        resolve_tenant_id(request, "tenant-b")

    assert exc.value.status_code == 403
    assert exc.value.detail == "tenant_mismatch"


def test_non_production_override_requires_explicit_gate(monkeypatch):
    monkeypatch.setenv("JANUSEC_RUNTIME_PROFILE", "test")
    monkeypatch.setenv("ALLOW_TENANT_OVERRIDE", "1")

    assert resolve_tenant_id(_request("tenant-a"), "tenant-b") == "tenant-b"


def test_override_gate_is_ignored_in_production(monkeypatch):
    monkeypatch.setenv("JANUSEC_RUNTIME_PROFILE", "production")
    monkeypatch.setenv("ALLOW_TENANT_OVERRIDE", "1")

    with pytest.raises(HTTPException) as exc:
        resolve_tenant_id(_request("tenant-a"), "tenant-b")

    assert exc.value.status_code == 403


def test_tenant_bound_auth_cannot_be_overridden_by_transport_or_payload(monkeypatch):
    monkeypatch.setenv("JANUSEC_RUNTIME_PROFILE", "test")
    monkeypatch.setenv("ALLOW_TENANT_OVERRIDE", "1")
    auth = type("Auth", (), {"tenant_id": "tenant-a"})()

    with pytest.raises(HTTPException) as exc:
        resolve_tenant_id(_request("tenant-b"), "tenant-b", auth=auth)

    assert exc.value.status_code == 403
    assert exc.value.detail == "tenant_mismatch"


def test_tenant_bound_auth_supplies_authoritative_scope():
    auth = type("Auth", (), {"tenant_id": "tenant-a"})()

    assert resolve_tenant_id(_request(), auth=auth) == "tenant-a"


@pytest.mark.parametrize(
    "tenant",
    ["../escape", "a/b", "a\\b", " tenant with spaces ", "x" * 65, "CON", "tenant."],
)
def test_invalid_tenant_identifiers_are_rejected(tenant):
    with pytest.raises(HTTPException) as exc:
        validate_tenant_id(tenant, required=True)

    assert exc.value.status_code == 400
    assert exc.value.detail == "invalid_tenant_id"


def test_default_policy_is_not_swallowed(monkeypatch):
    monkeypatch.setenv("ALLOW_DEFAULT_TENANT", "0")

    with pytest.raises(HTTPException) as exc:
        resolve_tenant_with_default(_request())

    assert exc.value.status_code == 400
    assert exc.value.detail == "tenant_id_required"


def test_default_policy_returns_validated_fallback(monkeypatch):
    monkeypatch.setenv("ALLOW_DEFAULT_TENANT", "1")

    assert resolve_tenant_with_default(_request(), "safe-default") == "safe-default"


def test_production_does_not_implicitly_enable_default_tenant(monkeypatch):
    monkeypatch.delenv("ALLOW_DEFAULT_TENANT", raising=False)
    monkeypatch.setenv("JANUSEC_RUNTIME_PROFILE", "production")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    with pytest.raises(HTTPException) as exc:
        resolve_tenant_with_default(_request())

    assert exc.value.status_code == 400
    assert exc.value.detail == "tenant_id_required"
