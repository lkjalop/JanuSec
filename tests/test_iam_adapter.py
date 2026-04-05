import asyncio

from src.integrations.iam_adapter import IAMAdapter


def test_canonical_event_mapping():
    adapter = IAMAdapter(provider="okta", config={})
    raw = {
        "actor": "alice",
        "action": "LoginSuccess",
        "resource": "okta.portal",
        "result": "success",
        "ip": "192.0.2.5",
        "user_agent": "curl/7.68.0",
        "ts": 1700000000,
    }

    ce = adapter.canonical_event(raw)
    assert ce["actor"] == "alice"
    assert ce["action"] == "LoginSuccess"
    assert ce["resource"] == "okta.portal"
    assert ce["ip"] == "192.0.2.5"


def test_fetch_since_and_ack():
    adapter = IAMAdapter(provider="azure", config={})

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    events, cursor = loop.run_until_complete(adapter.fetch_since())
    assert isinstance(events, list)
    assert cursor is not None

    ok = loop.run_until_complete(adapter.ack(cursor))
    assert ok is True
import json
import os
from src.integrations.iam_adapter import IAMAdapter


def load_fixture(name):
    path = os.path.join(os.path.dirname(__file__), "fixtures", "iam", name)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_map_cloudtrail_fixture():
    fx = load_fixture("cloudtrail_event.json")
    adapter = IAMAdapter()
    mapped = adapter.map_cloudtrail_to_canonical(fx)
    assert mapped["id"] == fx["eventID"]
    assert "action" in mapped


def test_map_okta_fixture():
    fx = load_fixture("okta_event.json")
    adapter = IAMAdapter()
    mapped = adapter.map_okta_event(fx)
    assert mapped["id"] == fx.get("eventId")


def test_map_azure_fixture():
    fx = load_fixture("azure_signin.json")
    adapter = IAMAdapter()
    mapped = adapter.map_azure_signin(fx)
    assert mapped["principal"] == fx.get("userPrincipalName")
