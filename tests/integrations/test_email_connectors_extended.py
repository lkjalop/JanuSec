from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

import pytest

from src.connectors.email.abnormal import AbnormalConfig, AbnormalConnector
from src.connectors.email.mimecast import MimecastConfig, MimecastConnector
from src.connectors.email.microsoft_graph_defender import DefenderConnector, GraphConfig
from src.integrations.auth.token_store import TokenStore


class StubResponse:
    def __init__(self, status_code: int = 200, json_data: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, Any]] = None):
        self.status_code = status_code
        self._json = json_data or {}
        self.headers = headers or {}
        self.text = json.dumps(self._json)

    def json(self) -> Dict[str, Any]:
        return self._json


class StubHttpClient:
    def __init__(self, responses: List[Any]):
        self.responses = responses
        self.calls: List[Dict[str, Any]] = []

    async def request(self, method: str, url: str, **kwargs) -> StubResponse:
        self.calls.append({"method": method, "url": url, "kwargs": kwargs})
        if not self.responses:
            raise AssertionError("No stub responses left")
        resp = self.responses.pop(0)
        if callable(resp):
            resp = resp(method, url, kwargs)
        return resp


@pytest.fixture(autouse=True)
def disable_token_store_db(monkeypatch):
    monkeypatch.setenv("TOKEN_STORE_DB", "0")


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    async def _noop(_: float):
        return None

    monkeypatch.setattr("src.connectors.email.common.asyncio.sleep", _noop)


@pytest.mark.asyncio
async def test_mimecast_connector_fetches_and_stores_token():
    token_store = TokenStore()
    responses = [
        StubResponse(json_data={"access_token": "mime-token", "expires_in": 120}),
        StubResponse(
            json_data={
                "data": [
                    {
                        "id": "evt-1",
                        "timestamp": "2026-01-01T00:00:00Z",
                        "sender": "attacker@example.com",
                        "recipient": "victim@example.com",
                        "subject": "Suspicious mail",
                        "urls": [{"url": "http://evil"}],
                        "attachments": [],
                    }
                ]
            }
        ),
    ]
    client = StubHttpClient(responses)
    connector = MimecastConnector(
        MimecastConfig(client_id="cid", client_secret="secret"),
        token_store,
        http_client=client,
    )
    events = await connector.fetch_detections("tenant-a")
    assert len(events) == 1
    await connector.close()

    cached = await token_store.get_token("tenant-a", "email:mimecast")
    assert cached is not None
    assert cached["access_token"] == "mime-token"
    assert events[0].sender_domain == "example.com"


@pytest.mark.asyncio
async def test_abnormal_connector_handles_rate_limit_and_pagination():
    token_store = TokenStore()
    responses = [
        StubResponse(json_data={"access_token": "abn-token", "expires_in": 60}),
        StubResponse(status_code=429, json_data={"error": "rate"}, headers={"Retry-After": "0"}),
        StubResponse(
            json_data={
                "alerts": [
                    {
                        "id": "alert-1",
                        "severity": "high",
                        "status": "open",
                        "email": {
                            "messageId": "msg-1",
                            "receivedAt": "2026-01-02T00:00:00Z",
                            "sender": "fraud@evil.io",
                            "recipient": "ciso@example.com",
                            "subject": "Payment update",
                        },
                    }
                ]
            }
        ),
    ]
    client = StubHttpClient(responses)
    connector = AbnormalConnector(
        AbnormalConfig(client_id="cid", client_secret="sec"),
        token_store,
        http_client=client,
    )
    events = await connector.fetch_alerts("tenant-b", limit=1)
    assert len(events) == 1
    assert events[0].triage_status == "open"
    await connector.close()


@pytest.mark.asyncio
async def test_defender_connector_normalizes_alert(monkeypatch):
    token_store = TokenStore()
    responses = [
        StubResponse(json_data={"access_token": "graph-token", "expires_in": 300}),
        StubResponse(
            json_data={
                "value": [
                    {
                        "id": "def-1",
                        "category": "phishing",
                        "createdDateTime": "2026-01-03T00:00:00Z",
                        "threatDisplayName": "Credential theft",
                        "status": "active",
                        "severity": "medium",
                        "entities": [
                            {
                                "@odata.type": "#microsoft.graph.security.emailEntity",
                                "sender": "bad@fraud.io",
                                "recipient": "soc@example.com",
                                "subject": "Urgent action",
                                "networkMessageId": "msg-123",
                                "urls": [{"url": "https://fraud.io/login"}],
                            }
                        ],
                    }
                ]
            }
        ),
    ]
    client = StubHttpClient(responses)
    cfg = GraphConfig(tenant_id="contoso", client_id="cid", client_secret="sec")
    connector = DefenderConnector(cfg, token_store, http_client=client)
    events = await connector.fetch_security_alerts("tenant-c")
    assert len(events) == 1
    evt = events[0]
    assert evt.sender_domain == "fraud.io"
    assert evt.message_id == "msg-123"
    await connector.close()
