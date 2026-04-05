from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import pytest

from src.collectors.iam_duo_worker import DuoCollector


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
        self.get_responses: List[_Resp] = []
        self.post_responses: List[_Resp] = []

    async def get(self, url: str, **kwargs: Any) -> _Resp:
        return self.get_responses.pop(0)

    async def post(self, url: str, **kwargs: Any) -> _Resp:
        return self.post_responses.pop(0)


@pytest.mark.asyncio
async def test_duo_poll(monkeypatch, tmp_path):
    store = _MemoryStore()
    http = _StubHTTP()
    http.get_responses.append(_Resp({"authlogs": [{"timestamp": 1700000000, "username": "user", "result": "allow"}]}))
    monkeypatch.setenv("DUO_IAM_RUN_LOG", str(tmp_path / "duo.log"))
    collector = DuoCollector(
        "tenant",
        integration_key="ikey",
        secret_key="skey",
        http_client=http,
        tenant_store=store,
    )
    events = await collector.poll_events()
    assert len(events) == 1
    assert store.saved[("duo", "since_ts")] == "1700000000"


@pytest.mark.asyncio
async def test_duo_forward(monkeypatch, tmp_path):
    store = _MemoryStore()
    http = _StubHTTP()
    http.post_responses.append(_Resp({}))
    monkeypatch.setenv("DUO_IAM_RUN_LOG", str(tmp_path / "forward.log"))
    collector = DuoCollector(
        "tenant",
        integration_key="ikey",
        secret_key="skey",
        http_client=http,
        tenant_store=store,
    )
    count = await collector.forward_to_ingest([{"timestamp": 1234}])
    assert count == 1
    assert collector._last_forward_count == 1  # noqa: SLF001
