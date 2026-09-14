from __future__ import annotations

import pytest

from src.repositories import evidence_ledger_repo


class _Context:
    def __init__(self, connection):
        self.connection = connection

    async def __aenter__(self):
        return self.connection

    async def __aexit__(self, exc_type, exc, tb):
        return False


@pytest.mark.asyncio
async def test_list_case_is_always_tenant_and_case_scoped(monkeypatch) -> None:
    calls = []

    class Connection:
        async def fetch(self, query, *args):
            calls.append((query, args))
            return []

    async def connection():
        return _Context(Connection())

    async def schema():
        return None

    monkeypatch.setattr(evidence_ledger_repo, "_connection", connection)
    monkeypatch.setattr(evidence_ledger_repo, "ensure_schema", schema)

    assert await evidence_ledger_repo.list_case("tenant-a", "case-1") == []
    assert "tenant_id=$1 AND case_id=$2" in calls[0][0]
    assert calls[0][1][:2] == ("tenant-a", "case-1")


@pytest.mark.asyncio
async def test_list_case_rejects_unscoped_read() -> None:
    with pytest.raises(ValueError, match="tenant_and_case_required"):
        await evidence_ledger_repo.list_case("", "case-1")
