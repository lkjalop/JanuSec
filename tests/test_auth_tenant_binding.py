from __future__ import annotations

import pytest
from fastapi import HTTPException

from src.security.auth import auth_dependency

pytest.importorskip("jwt")
import jwt  # noqa: E402


def _token(secret: str, payload: dict) -> str:
    return jwt.encode(payload, secret, algorithm="HS256")


@pytest.mark.asyncio
async def test_jwt_requires_tenant_claim(monkeypatch):
    secret = "tenant-binding-test-secret-at-least-32-bytes"
    monkeypatch.setenv("JWT_SECRET", secret)
    monkeypatch.delenv("JWT_AUDIENCE", raising=False)
    monkeypatch.delenv("JWT_ISSUER", raising=False)
    token = _token(secret, {"sub": "analyst", "scopes": ["factors.search"]})

    with pytest.raises(HTTPException) as exc_info:
        await auth_dependency(None, f"Bearer {token}", [])

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "tenant_claim_required"


@pytest.mark.asyncio
async def test_jwt_tenant_claim_is_bound_to_auth_context(monkeypatch):
    secret = "tenant-binding-test-secret-at-least-32-bytes"
    monkeypatch.setenv("JWT_SECRET", secret)
    monkeypatch.delenv("JWT_AUDIENCE", raising=False)
    monkeypatch.delenv("JWT_ISSUER", raising=False)
    token = _token(
        secret,
        {
            "sub": "analyst",
            "tenant_id": "tenant-a",
            "scopes": ["factors.search"],
        },
    )

    context = await auth_dependency(None, f"Bearer {token}", [])

    assert context.tenant_id == "tenant-a"
    assert context.credential_type == "jwt"
    assert context.is_platform_admin is False


@pytest.mark.asyncio
async def test_jwt_rejects_unsafe_tenant_claim(monkeypatch):
    secret = "tenant-binding-test-secret-at-least-32-bytes"
    monkeypatch.setenv("JWT_SECRET", secret)
    monkeypatch.delenv("JWT_AUDIENCE", raising=False)
    monkeypatch.delenv("JWT_ISSUER", raising=False)
    token = _token(
        secret,
        {
            "sub": "analyst",
            "tenant_id": "../tenant-b",
            "scopes": ["factors.search"],
        },
    )

    with pytest.raises(HTTPException) as exc_info:
        await auth_dependency(None, f"Bearer {token}", [])

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "invalid_tenant_claim"


@pytest.mark.asyncio
async def test_explicit_platform_admin_jwt_may_be_tenantless(monkeypatch):
    secret = "tenant-binding-test-secret-at-least-32-bytes"
    monkeypatch.setenv("JWT_SECRET", secret)
    monkeypatch.delenv("JWT_AUDIENCE", raising=False)
    monkeypatch.delenv("JWT_ISSUER", raising=False)
    token = _token(secret, {"sub": "platform-operator", "role": "platform_admin"})

    context = await auth_dependency(None, f"Bearer {token}", [])

    assert context.tenant_id is None
    assert context.scopes == ["*"]
    assert context.is_platform_admin is True
