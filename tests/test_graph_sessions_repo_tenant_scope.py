from __future__ import annotations

import pytest

from src.repositories import graph_sessions_repo


class _ConnectionContext:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


@pytest.mark.asyncio
async def test_graph_session_read_uses_exact_tenant_match(monkeypatch):
    calls: list[tuple[str, tuple[object, ...]]] = []

    class _Connection:
        async def fetchrow(self, sql, *args):
            calls.append((sql, args))
            return None

    async def _acquire():
        return _ConnectionContext(_Connection())

    async def _schema():
        return None

    monkeypatch.setattr(graph_sessions_repo, "_acquire_conn", _acquire)
    monkeypatch.setattr(graph_sessions_repo, "ensure_schema", _schema)

    assert await graph_sessions_repo.get_graph_session("session-1", "tenant-a") is None
    assert calls == [
        (
            "SELECT * FROM graph_sessions WHERE session_id=$1 AND tenant_id=$2",
            ("session-1", "tenant-a"),
        )
    ]


@pytest.mark.asyncio
async def test_graph_session_read_rejects_unscoped_lookup():
    with pytest.raises(ValueError, match="tenant_id_required"):
        await graph_sessions_repo.get_graph_session("session-1", None)


@pytest.mark.asyncio
async def test_graph_session_write_rejects_tenantless_record():
    with pytest.raises(ValueError, match="tenant_id_required"):
        await graph_sessions_repo.upsert_graph_session({"session_id": "session-1"})
