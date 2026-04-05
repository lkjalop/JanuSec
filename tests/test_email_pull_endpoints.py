import os
import time
from datetime import datetime, timedelta

from fastapi.testclient import TestClient

from src.api.app import app


def _headers():
    return {"x-api-key": "devkey123", "X-Tenant-Id": "tenant-test"}


def test_email_delivery_pull_filters_recipients(monkeypatch):
    class _StubO365:
        def fetch_events(self, since_ts: float):
            return [
                {
                    "toRecipients": [{"emailAddress": {"address": "alice@example.com"}}],
                    "from": {"emailAddress": {"address": "evil@example.net"}},
                    "receivedDateTime": "2026-01-01T00:00:00Z",
                    "id": "msg-1",
                },
                {
                    "toRecipients": [{"emailAddress": {"address": "bob@example.com"}}],
                    "from": {"emailAddress": {"address": "other@example.net"}},
                    "receivedDateTime": "2026-01-01T00:01:00Z",
                    "id": "msg-2",
                },
            ]

    class _StubGmail:
        def fetch_events(self, since_ts: float):
            return [
                {"to": ["charlie@example.com"], "from": "noreply@example.net", "internalDate": int(time.time() * 1000)},
            ]

    monkeypatch.setattr("src.collectors.email_o365_adapter.O365EmailCollector", _StubO365)
    monkeypatch.setattr("src.collectors.email_gmail_adapter.GmailEmailCollector", _StubGmail)

    client = TestClient(app)
    start = datetime.utcnow() - timedelta(hours=1)
    end = datetime.utcnow()
    payload = {"recipients": ["alice@example.com"], "start": start.isoformat(), "end": end.isoformat()}
    resp = client.post("/api/v1/email/delivery/pull", json=payload, headers=_headers())
    assert resp.status_code == 200
    body = resp.json()
    assert body["source"] == "email_delivery_logs"
    events = body.get("events", [])
    assert isinstance(events, list)
    assert len(events) == 1
    assert events[0]["recipient"] == "alice@example.com"
    assert "message_id" in events[0]


def test_email_click_pull_filters_users_and_time(monkeypatch):
    now = time.time()
    rows = [
        {"user": "sam@example.com", "url": "https://evil", "timestamp": now - 120, "meta": {"device_id": "dev-1"}},
        {"user": "other@example.com", "url": "https://ok", "timestamp": now - 60, "meta": {"device_id": "dev-2"}},
        {"user": "sam@example.com", "url": "https://late", "timestamp": now - 7200, "meta": {"device_id": "dev-3"}},
    ]

    monkeypatch.setattr("src.connectors.email.click_store.fetch_recent_clicks", lambda limit=500: rows)

    client = TestClient(app)
    payload = {"users": ["sam@example.com"], "start": now - 600, "end": now + 1}
    resp = client.post("/api/v1/email/click/pull", json=payload, headers=_headers())
    assert resp.status_code == 200
    body = resp.json()
    events = body.get("events", [])
    assert isinstance(events, list)
    assert len(events) == 1
    assert events[0]["user"] == "sam@example.com"
    assert events[0]["url"] == "https://evil"


def test_email_quarantine_pull_filters_recipients(monkeypatch):
    os.environ["ABNORMAL_CLIENT_ID"] = "test-id"
    os.environ["ABNORMAL_CLIENT_SECRET"] = "test-secret"

    class _StubAbnormal:
        def __init__(self, cfg, token_store):
            self.cfg = cfg
            self.token_store = token_store

        async def fetch_alerts(self, tenant_id, since=None, limit=200, severity=None):
            return [
                {"recipient": "alice@example.com", "message_id": "q-1", "verdict": "quarantine", "timestamp": time.time()},
                {"recipient": "bob@example.com", "message_id": "q-2", "verdict": "quarantine", "timestamp": time.time()},
            ]

        async def close(self):
            return None

    monkeypatch.setattr("src.connectors.email.abnormal.AbnormalConnector", _StubAbnormal)

    client = TestClient(app)
    payload = {"recipients": ["alice@example.com"], "start": time.time() - 3600}
    resp = client.post("/api/v1/email/quarantine/pull", json=payload, headers=_headers())
    assert resp.status_code == 200
    body = resp.json()
    events = body.get("events", [])
    assert isinstance(events, list)
    assert len(events) == 1
    assert events[0]["recipient"] == "alice@example.com"
    assert events[0]["action"] == "quarantined"
