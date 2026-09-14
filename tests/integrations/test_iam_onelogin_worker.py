from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import pytest

from src.collectors.iam_onelogin_worker import OneLoginCollector


class _MemoryStore:
    def __init__(self) -> None:
        self.saved: Dict[Tuple[str, str], Optional[str]] = {}

    def load_cursor(self, tenant: str, provider: str, key: str) -> Optional[str]:
        return self.saved.get((provider, key))

    def save_cursor(self, tenant: str, provider: str, key: str, value: str) -> None:
        self.saved[(provider, key)] = value


class _Resp:
    def __init__(self, payload: Dict[str, Any]) -> None:
        self._payload = payload

    def json(self) -> Dict[str, Any]:
        return self._payload

    def raise_for_status(self) -> None:
        return None


class _StubHTTP:
    def __init__(self) -> None:
        self.post_responses: List[_Resp] = []
        self.get_responses: List[_Resp] = []

    async def post(self, url: str, **kwargs: Any) -> _Resp:
        return self.post_responses.pop(0)

    async def get(self, url: str, **kwargs: Any) -> _Resp:
        return self.get_responses.pop(0)


@pytest.mark.asyncio
async def test_onelogin_poll(monkeypatch, tmp_path):
    store = _MemoryStore()
    http = _StubHTTP()
    http.post_responses.append(_Resp({"access_token": "tok"}))
    http.get_responses.append(
        _Resp({"data": [{"id": 100, "created_at": "2026-01-01T00:00:00Z", "event_type_name": "login", "actor_user_name": "svc"}]})
    )
    monkeypatch.setenv("ONELOGIN_IAM_RUN_LOG", str(tmp_path / "onelogin.log"))
    collector = OneLoginCollector(
        "tenant",
        client_id="id",
        client_secret="secret",
        http_client=http,
        tenant_store=store,
    )
    events = await collector.poll_events()
    assert len(events) == 1
    assert store.saved[("onelogin", "event_cursor")] == "100"


@pytest.mark.asyncio
async def test_onelogin_forward(monkeypatch, tmp_path):
    store = _MemoryStore()
    http = _StubHTTP()
    http.post_responses.append(_Resp({}))
    monkeypatch.setenv("ONELOGIN_IAM_RUN_LOG", str(tmp_path / "forward.log"))
    collector = OneLoginCollector(
        "tenant",
        client_id="id",
        client_secret="secret",
        http_client=http,
        tenant_store=store,
    )
    count = await collector.forward_to_ingest([{"timestamp": "ts"}])
    assert count == 1
    assert collector._last_forward_count == 1  # noqa: SLF001
