from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import pytest

from src.collectors.iam_sailpoint_worker import SailPointCollector


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
        self.post_calls: List[Dict[str, Any]] = []
        self.get_calls: List[Dict[str, Any]] = []

    async def post(self, url: str, **kwargs: Any) -> _Resp:
        self.post_calls.append({"url": url, **kwargs})
        return self.post_responses.pop(0)

    async def get(self, url: str, **kwargs: Any) -> _Resp:
        self.get_calls.append({"url": url, **kwargs})
        return self.get_responses.pop(0)


@pytest.mark.asyncio
async def test_poll_events_updates_cursor(monkeypatch, tmp_path):
    store = _MemoryStore()
    http = _StubHTTP()
    http.post_responses.append(_Resp({"access_token": "tok"}))
    http.get_responses.append(
        _Resp(
            {
                "data": [
                    {"created": "2026-01-01T00:00:00Z", "type": "provision", "actor": {"name": "svc"}, "target": {"name": "user"}}
                ],
                "nextCursor": "cursor-2",
            }
        )
    )
    monkeypatch.setenv("SAILPOINT_IAM_RUN_LOG", str(tmp_path / "sailpoint.log"))
    collector = SailPointCollector(
        "tenant",
        base_url="https://example",
        client_id="id",
        client_secret="secret",
        http_client=http,
        tenant_store=store,
    )
    events = await collector.poll_events()
    assert len(events) == 1
    assert store.saved[("sailpoint", "event_cursor")] == "cursor-2"


@pytest.mark.asyncio
async def test_forward_to_ingest(monkeypatch, tmp_path):
    store = _MemoryStore()
    http = _StubHTTP()
    http.post_responses.append(_Resp({}))  # forward response
    monkeypatch.setenv("SAILPOINT_IAM_RUN_LOG", str(tmp_path / "forward.log"))
    collector = SailPointCollector(
        "tenant",
        base_url="https://example",
        client_id="id",
        client_secret="secret",
        http_client=http,
        tenant_store=store,
    )
    count = await collector.forward_to_ingest([{"timestamp": "2026-01-01T00:00:00Z"}])
    assert count == 1
    assert collector._last_forward_count == 1  # noqa: SLF001 - white-box
