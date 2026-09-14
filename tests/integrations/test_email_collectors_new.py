from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import pytest

from src.collectors.email.abnormal_collector import AbnormalCollector
from src.collectors.email.mimecast_collector import MimecastCollector
from src.collectors.email.defender_collector import DefenderCollector
from src.connectors.email.microsoft_graph_defender import GraphConfig
from src.schemas.email import NormalizedEmailEvent


class StubStore:
    def __init__(self) -> None:
        self.saved: Dict[Tuple[str, str], Optional[str]] = {}

    def load_cursor(self, tenant: str, provider: str, key: str) -> Optional[str]:
        return self.saved.get((provider, key))

    def save_cursor(self, tenant: str, provider: str, key: str, value: str) -> None:
        self.saved[(provider, key)] = value


class StubConnector:
    def __init__(self, events: list[NormalizedEmailEvent]):
        self.events = events
        self.calls: list[Dict[str, Any]] = []

    async def fetch_detections(self, tenant_id: str, *, since: Optional[datetime] = None, limit: int = 50):
        self.calls.append({"tenant": tenant_id, "since": since, "limit": limit})
        return self.events

    async def fetch_alerts(self, tenant_id: str, *, since: Optional[datetime] = None, limit: int = 100, severity: Optional[str] = None):
        self.calls.append({"tenant": tenant_id, "since": since, "limit": limit, "severity": severity})
        return self.events

    async def fetch_security_alerts(self, tenant_id: str, *, top: int = 100, filter_query: Optional[str] = None):
        self.calls.append({"tenant": tenant_id, "top": top, "filter_query": filter_query})
        return self.events


class FakeResp:
    def __init__(self, status_code: int = 200):
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeAsyncClient:
    def __init__(self, responses: list[FakeResp]):
        self._responses = responses
        self.calls: list[Tuple[str, Dict[str, Any]]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url: str, headers: Dict[str, Any], json: Dict[str, Any]):
        self.calls.append((url, json))
        if not self._responses:
            return FakeResp(200)
        return self._responses.pop(0)


def _event(event_id: str) -> NormalizedEmailEvent:
    return NormalizedEmailEvent(
        event_id=event_id,
        event_type="email",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        source_platform="test",
        sender="attacker@example.com",
        recipient="victim@example.com",
        subject="Test",
    )


@pytest.mark.asyncio
async def test_mimecast_collector_uses_connector(monkeypatch):
    events = [_event("mime-1"), _event("mime-2")]
    store = StubStore()
    collector = MimecastCollector(
        "tenant-mime",
        connector=StubConnector(events),
        tenant_store=store,
    )
    polled = await collector.poll_detections()
    assert len(polled) == 2
    assert store.saved[("mimecast", "sinceTime")] is not None

    responses = [FakeResp(200), FakeResp(200)]
    fake_client = FakeAsyncClient(responses)
    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", lambda timeout=30: fake_client)
    sent = await collector.forward_to_ingest(polled)
    assert sent == 2
    assert any("/api/v1/email/ingest/batch" in call[0] for call in fake_client.calls)


@pytest.mark.asyncio
async def test_abnormal_collector_tracks_cursor(monkeypatch):
    events = [_event("abn-1")]
    store = StubStore()
    collector = AbnormalCollector(
        "tenant-abn",
        connector=StubConnector(events),
        tenant_store=store,
    )
    polled = await collector.poll_alerts()
    assert len(polled) == 1
    assert store.saved[("abnormal", "createdAfter")] is not None

    responses = [FakeResp(200)]
    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", lambda timeout=30: FakeAsyncClient(list(responses)))
    sent = await collector.forward_to_ingest(polled)
    assert sent == 1


@pytest.mark.asyncio
async def test_defender_collector_forward(monkeypatch):
    events = [_event("def-1")]
    collector = DefenderCollector(
        "tenant-def",
        graph_config=GraphConfig(tenant_id="tid", client_id="cid", client_secret="secret"),
        connector=StubConnector(events),
    )
    polled = await collector.poll_alerts()
    assert len(polled) == 1

    responses = [FakeResp(200)]
    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", lambda timeout=30: FakeAsyncClient(list(responses)))
    sent = await collector.forward_to_ingest(polled)
    assert sent == 1
@pytest.fixture(autouse=True)
def disable_token_store_db(monkeypatch):
    monkeypatch.setenv("TOKEN_STORE_DB", "0")
