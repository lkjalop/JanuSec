from __future__ import annotations

import asyncio
from typing import Any, Dict

import pytest

from src.collectors.iam_ad_worker import ActiveDirectoryCollector
from src.collectors.iam_ping_worker import PingIdentityCollector
from src.collectors.iam_sailpoint_worker import SailPointCollector


@pytest.mark.asyncio
async def test_ad_collector_graceful_when_ldap_missing(monkeypatch):
    collector = ActiveDirectoryCollector("tenant-test", server_url=None, user=None, password=None, base_dn=None)
    events = await collector.poll_changes()
    assert events == []


@pytest.mark.asyncio
async def test_sailpoint_collector_noop_without_httpx(monkeypatch):
    monkeypatch.setattr("src.collectors.iam_sailpoint_worker.httpx", None)
    collector = SailPointCollector("tenant-test", base_url=None, client_id=None, client_secret=None)
    events = await collector.poll_events()
    assert events == []


@pytest.mark.asyncio
async def test_pingidentity_collector_normalizes_events(monkeypatch):
    calls: Dict[str, Any] = {}

    class DummyResponse:
        def __init__(self, payload: Dict[str, Any]):
            self._payload = payload

        def json(self):
            return self._payload

        def raise_for_status(self):
            return None

    class DummyAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, *args, **kwargs):
            calls["post"] = kwargs
            return DummyResponse({"access_token": "token"})

        async def get(self, *args, **kwargs):
            calls["get"] = kwargs
            return DummyResponse(
                {
                    "_embedded": {
                        "events": [
                            {
                                "occurredAt": "2026-01-01T00:00:00Z",
                                "action": "ASSIGN_ROLE",
                                "severity": "medium",
                                "actor": {"name": "admin"},
                                "target": {"id": "user-1"},
                            }
                        ]
                    }
                }
            )

    dummy_module = type("DummyHttpx", (), {"AsyncClient": DummyAsyncClient})
    monkeypatch.setattr("src.collectors.iam_ping_worker.httpx", dummy_module)

    collector = PingIdentityCollector("tenant-test", base_url="https://example", env_id="env", client_id="cid", client_secret="secret")
    events = await collector.poll_events()
    assert len(events) == 1
    assert events[0]["action"] == "ASSIGN_ROLE"
