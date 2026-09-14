from __future__ import annotations

import json
import secrets

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api import graph_sessions
from src.api.tenant_middleware import TenantMiddleware


def _client(monkeypatch, tmp_path) -> tuple[TestClient, dict[str, str]]:
    monkeypatch.setenv("SESSION_PERSIST_DIR", str(tmp_path / "sessions"))
    monkeypatch.setenv("GRAPH_SESSION_SNAPSHOT_DIR", str(tmp_path / "snapshots"))
    monkeypatch.setenv("JANUSEC_RUNTIME_PROFILE", "production")
    monkeypatch.delenv("SYNTHETIC_EVIDENCE_ENABLED", raising=False)
    monkeypatch.setenv("TEST_HELPERS_ENABLED", "0")
    keys = {tenant: secrets.token_urlsafe(48) for tenant in ('tenant-a', 'tenant-b')}
    monkeypatch.setenv('API_KEYS_JSON', json.dumps([
        {'key': key, 'tenant_id': tenant, 'scopes': ['*']} for tenant, key in keys.items()
    ]))
    graph_sessions._SESSIONS.clear()
    graph_sessions._DISCOVERIES.clear()

    async def _persist(session_id, summary, payload, tenant_id):
        return {
            "session_id": session_id,
            "tenant_id": tenant_id,
            "status": "ready",
            "summary": summary,
            "paths": [],
            "graph_snapshot_ref": None,
        }

    async def _load(_session_id, _tenant_id):
        return None

    monkeypatch.setattr(graph_sessions, "_persist_graph_session_record", _persist)
    monkeypatch.setattr(graph_sessions, "_load_graph_session_record", _load)

    app = FastAPI()
    app.add_middleware(TenantMiddleware)
    app.include_router(graph_sessions.router)
    return TestClient(app), keys


def test_cached_graph_session_is_invisible_across_tenants(monkeypatch, tmp_path):
    client, keys = _client(monkeypatch, tmp_path)
    tenant_a = {"X-Tenant-ID": "tenant-a", 'X-API-Key': keys['tenant-a']}
    tenant_b = {"X-Tenant-ID": "tenant-b", 'X-API-Key': keys['tenant-b']}

    built = client.post(
        "/api/v1/graph/session/build",
        json={"session_ids": ["missing-source-a", "missing-source-b"]},
        headers=tenant_a,
    )
    assert built.status_code == 200, built.text
    session_id = built.json()["session_id"]
    assert built.json()["tenant_id"] == "tenant-a"

    assert client.get(f"/api/v1/graph/session/{session_id}", headers=tenant_a).status_code == 200
    for suffix, method in (
        ("", "get"),
        ("/paths", "get"),
        ("/timeline", "get"),
        ("/explain", "get"),
        ("/narrative", "get"),
        ("/discoveries", "get"),
        ("/replay", "post"),
    ):
        response = getattr(client, method)(
            f"/api/v1/graph/session/{session_id}{suffix}", headers=tenant_b
        )
        assert response.status_code == 404, (suffix, response.text)

    listed_a = client.get("/api/v1/graph/session/list", headers=tenant_a).json()
    listed_b = client.get("/api/v1/graph/session/list", headers=tenant_b).json()
    assert [item["session_id"] for item in listed_a["sessions"]] == [session_id]
    assert listed_b["sessions"] == []

    cleanup_b = client.post(
        f"/api/v1/graph/session/cleanup?session_id={session_id}", headers=tenant_b
    )
    assert cleanup_b.status_code == 200
    assert cleanup_b.json()["removed"] == 0
    assert client.get(f"/api/v1/graph/session/{session_id}", headers=tenant_a).status_code == 200


def test_production_profile_ignores_synthetic_evidence_switch(monkeypatch):
    monkeypatch.setenv("JANUSEC_RUNTIME_PROFILE", "production")
    monkeypatch.setenv("SYNTHETIC_EVIDENCE_ENABLED", "1")
    monkeypatch.setenv("TEST_HELPERS_ENABLED", "1")

    assert graph_sessions._allow_synthetic_evidence() is False
