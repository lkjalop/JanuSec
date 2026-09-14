from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import pytest

from src.collectors.iam_ping_worker import PingIdentityCollector


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
async def test_ping_worker_persists_since(monkeypatch, tmp_path):
    store = _MemoryStore()
    http = _StubHTTP()
    http.post_responses.append(_Resp({"access_token": "tok"}))
    http.get_responses.append(
        _Resp(
            {
                "_embedded": {
                    "events": [
                        {"occurredAt": "2026-01-01T00:00:00Z", "actor": {"name": "svc"}, "target": {"id": "user"}, "action": "login"}
                    ]
                }
            }
        )
    )
    monkeypatch.setenv("PING_IAM_RUN_LOG", str(tmp_path / "ping.log"))
    collector = PingIdentityCollector(
        "tenant",
        env_id="env",
        client_id="id",
        client_secret="secret",
        http_client=http,
        tenant_store=store,
    )
    events = await collector.poll_events()
    assert len(events) == 1
    assert store.saved[("ping", "since_ts")] == "2026-01-01T00:00:00Z"


@pytest.mark.asyncio
async def test_ping_forward(monkeypatch, tmp_path):
    store = _MemoryStore()
    http = _StubHTTP()
    http.post_responses.append(_Resp({}))
    monkeypatch.setenv("PING_IAM_RUN_LOG", str(tmp_path / "forward.log"))
    collector = PingIdentityCollector(
        "tenant",
        env_id="env",
        client_id="id",
        client_secret="secret",
        http_client=http,
        tenant_store=store,
    )
    count = await collector.forward_to_ingest([{"timestamp": "now"}])
    assert count == 1
    assert collector._last_forward_count == 1  # noqa: SLF001
