"""Phase 2.9 — connector webhooks must ACTUALLY ingest, not just count.

Regression cover for the bug where /api/v1/webhooks/{crowdstrike,sentinel,splunk}
verified the HMAC, incremented events_ingested_total, and returned OK WITHOUT
parsing or storing the body — so no webhook event was ever ingested.
"""
import hashlib
import hmac
import json
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.routers.connectors_webhooks import _parse_webhook_rows, router


def _sign(body: bytes, secret: str) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_parse_handles_object_array_envelope_and_ndjson():
    assert _parse_webhook_rows(b'{"a":1}') == [{"a": 1}]
    assert _parse_webhook_rows(b'[{"a":1},{"b":2}]') == [{"a": 1}, {"b": 2}]
    assert _parse_webhook_rows(b'{"resources":[{"x":1}]}') == [{"x": 1}]
    assert _parse_webhook_rows(b'{"a":1}\n{"b":2}') == [{"a": 1}, {"b": 2}]
    assert _parse_webhook_rows(b"") == []


def test_bad_signature_rejected_and_not_ingested(client, monkeypatch):
    monkeypatch.setenv("CROWDSTRIKE_WEBHOOK_SECRET", "s3cret")
    body = json.dumps({"event_simpleName": "ProcessRollup2"}).encode()
    r = client.post(
        "/api/v1/webhooks/crowdstrike",
        content=body,
        headers={"x-signature": "deadbeef", "x-timestamp": str(int(time.time()))},
    )
    assert r.status_code == 401


def test_verified_crowdstrike_event_is_ingested(client, monkeypatch):
    monkeypatch.setenv("CROWDSTRIKE_WEBHOOK_SECRET", "s3cret")
    body = json.dumps(
        {"resources": [{"device_id": "abc", "event_simpleName": "ProcessRollup2", "user": "martin.chen"}]}
    ).encode()
    ts = str(int(time.time()))
    r = client.post(
        "/api/v1/webhooks/crowdstrike",
        content=body,
        headers={"x-signature": _sign(body, "s3cret"), "x-timestamp": ts},
    )
    assert r.status_code == 200
    payload = r.json()
    assert payload["status"] == "ok"
    # The core regression assertion: the event was actually accepted into ingest,
    # not silently dropped after signature verification.
    assert payload["accepted"] >= 1

    # And it is observable in the streaming session the webhook routes to.
    from src.pipeline.streaming_ingest import get_session

    session = get_session("webhook-crowdstrike")
    assert session is not None
    snap = session.snapshot()
    assert snap["total_ingested"] >= 1
