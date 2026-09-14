from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, Dict, Optional, Tuple

import pytest

from src.collectors.iam_ad_worker import ActiveDirectoryCollector


class _MemoryStore:
    def __init__(self) -> None:
        self.saved: Dict[Tuple[str, str], Optional[str]] = {}

    def load_cursor(self, tenant: str, provider: str, key: str) -> Optional[str]:
        return self.saved.get((provider, key))

    def save_cursor(self, tenant: str, provider: str, key: str, value: str) -> None:
        self.saved[(provider, key)] = value


class _StubHTTP:
    def __init__(self) -> None:
        self.calls: list[Dict[str, Any]] = []

    async def post(self, url: str, headers: Dict[str, str], json: Dict[str, Any]) -> Any:  # noqa: A003 - param name
        self.calls.append({"url": url, "headers": headers, "json": json})

        class _Resp:
            @staticmethod
            def raise_for_status() -> None:
                return None

        return _Resp()


class _DirSyncExtend:
    def __init__(self) -> None:
        self.calls: list[Tuple[tuple[Any, ...], Dict[str, Any]]] = []

    def microsoft_dir_sync(self, *args: Any, **kwargs: Any) -> None:
        self.calls.append((args, kwargs))


class _Entry:
    def __init__(self) -> None:
        self.whenChanged = SimpleNamespace(value="2026-01-01T00:00:00Z")
        self.userPrincipalName = "user@example.com"
        self.memberOf = ["CN=Admins", "CN=Ops"]

    def entry_to_json(self) -> str:
        return json.dumps({"dn": "CN=user,DC=example,DC=com"})


class _Conn:
    def __init__(self) -> None:
        self.entries = [_Entry()]
        self.extend = _DirSyncExtend()
        self.result = {"controls": {"dirSync": {"value": {"cookie": "cookie-next"}}}}
        self.unbound = False

    def unbind(self) -> None:
        self.unbound = True


@pytest.mark.asyncio
async def test_poll_changes_tracks_cookie(monkeypatch, tmp_path):
    store = _MemoryStore()
    monkeypatch.setenv("AD_IAM_RUN_LOG", str(tmp_path / "ad-run.log"))
    collector = ActiveDirectoryCollector(
        "tenant",
        connection_factory=_Conn,
        tenant_store=store,
    )
    events = await collector.poll_changes()
    assert len(events) == 1
    assert store.saved[("ad", "dirsync_cookie")] == "cookie-next"


@pytest.mark.asyncio
async def test_forward_to_ingest_uses_http_client(monkeypatch, tmp_path):
    store = _MemoryStore()
    http = _StubHTTP()
    monkeypatch.setenv("AD_IAM_RUN_LOG", str(tmp_path / "forward.log"))
    collector = ActiveDirectoryCollector(
        "tenant",
        connection_factory=_Conn,
        tenant_store=store,
        http_client=http,
    )
    events = [{"timestamp": "2026-01-01T00:00:00Z"}]
    count = await collector.forward_to_ingest(events)
    assert count == 1
    assert collector._last_forward_count == 1  # noqa: SLF001 - white-box assertion
