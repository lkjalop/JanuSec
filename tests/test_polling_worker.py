import time
import os
import json
import pytest

from src.integrations.polling_worker import MailPollingWorker, CircuitOpenError
from src.integrations.tenant_store import TenantStore


class DummyConnector:
    def __init__(self):
        self.refreshed = False

    def refresh_token(self, refresh_token):
        self.refreshed = True
        return {'access_token': 'new', 'refresh_token': refresh_token, 'expires_in': 3600}

    def poll_delta(self, access_token, delta_link=None):
        # Emulate success returning an empty value set
        return {'value': [], '@odata.deltaLink': 'new-delta'}

    def parse_messages_to_events(self, payload):
        return []


def test_token_refresh_path(monkeypatch, tmp_path):
    monkeypatch.setenv('POLLING_STATE_DIR', str(tmp_path / 'polling_state'))
    ts = TenantStore()
    tid = 't-refresh'
    # expired token
    now = int(time.time())
    ts.save_tokens(tid, {'access_token': 'old', 'refresh_token': 'r', 'expires_at': now - 10, 'client_id': 'x', 'client_secret': 'y'})

    # Inject DummyConnector into worker by monkeypatching MSGraphConnector constructor
    worker = MailPollingWorker(tid, 'msgraph')
    worker.conn = DummyConnector()
    count = worker.poll_once()
    assert count == 0
    # tokens should be refreshed on disk
    toks = ts.load_tokens(tid)
    assert toks is not None
    assert toks.get('access_token') == 'new' or toks.get('access_token') == 'new'


def test_401_revocation_opens_circuit(monkeypatch, tmp_path):
    monkeypatch.setenv('POLLING_STATE_DIR', str(tmp_path / 'polling_state'))
    tid = 't-401'
    ts = TenantStore()
    ts.save_tokens(tid, {'access_token': 'ok', 'refresh_token': 'r', 'expires_at': int(time.time()) + 3600, 'client_id': 'x', 'client_secret': 'y'})

    # create a connector that raises HTTPError with response.status_code=401
    class BadConnector:
        def refresh_token(self, r):
            raise Exception('no')

        def poll_delta(self, access_token, delta_link=None):
            from requests import Response
            from requests import HTTPError
            resp = Response()
            resp.status_code = 401
            raise HTTPError(response=resp)

    worker = MailPollingWorker(tid, 'msgraph')
    worker.conn = BadConnector()
    with pytest.raises(RuntimeError):
        worker.poll_once()
import time
from types import SimpleNamespace

import pytest
from requests import HTTPError, Response

from integrations.polling_state import PollingStateStore
from integrations.polling_worker import MailPollingWorker
from integrations.tenant_store import TenantStore


class DummyPipelineResponse(SimpleNamespace):
    def __init__(self, status_code=200, headers=None):
        super().__init__(status_code=status_code, headers=headers or {})


def _patch_pipeline(monkeypatch):
    monkeypatch.setattr(
        "integrations.polling_worker.requests.post",
        lambda *args, **kwargs: DummyPipelineResponse(status_code=200),
    )


def _save_tokens(monkeypatch, tenant_id="tenant-test"):
    monkeypatch.setenv("SECRET_BACKEND", "memory")
    store = TenantStore()
    store.save_tokens(
        tenant_id,
        {
            "access_token": "token",
            "refresh_token": "refresh",
            "expires_at": int(time.time()) + 3600,
        },
    )
    return store


class DummyMSGraphConnector:
    def __init__(self, client_id, client_secret, redirect_uri, scope="offline_access Mail.Read"):
        pass

    def poll_delta(self, access_token, delta_link=None, top=50):
        DummyMSGraphConnector.last_delta = delta_link
        return {"value": [{"id": "1"}], "@odata.deltaLink": "https://next-delta"}

    def parse_messages_to_events(self, payload):
        return [{"id": row["id"]} for row in payload.get("value", [])]

    def refresh_token(self, refresh_token):
        return {"access_token": "new", "refresh_token": refresh_token, "expires_in": 3600}


class DummyGmailConnector:
    def __init__(self, client_id, client_secret, redirect_uri, scope=None):
        pass

    def list_messages(self, access_token, q=None, page_token=None, max_results=100):
        return {"messages": [{"id": "abc"}]}

    def get_message(self, access_token, message_id):
        return {"id": message_id, "historyId": "123", "raw": ""}

    def parse_raw_message(self, payload):
        return {"headers": {"Message-Id": payload["id"]}, "parts": [], "historyId": payload.get("historyId")}

    def list_history(self, access_token, start_history_id, page_token=None, max_results=100):
        return {"history": [{"id": "456", "messagesAdded": [{"message": {"id": "xyz"}}]}], "historyId": "456"}


def test_polling_worker_msgraph_persists_delta(tmp_path, monkeypatch):
    monkeypatch.setenv("POLLING_STATE_DIR", str(tmp_path / "state"))
    store = _save_tokens(monkeypatch)
    _patch_pipeline(monkeypatch)
    monkeypatch.setattr("integrations.polling_worker.MSGraphConnector", DummyMSGraphConnector)

    worker = MailPollingWorker("tenant-test", "msgraph", pipeline_endpoint="http://collector")
    processed = worker.poll_once()
    assert processed == 1

    state = PollingStateStore(str(tmp_path / "state")).load_state("tenant-test", "msgraph")
    assert state["delta_link"] == "https://next-delta"
    store.delete_tokens("tenant-test")


def test_polling_worker_detects_revocation(tmp_path, monkeypatch):
    monkeypatch.setenv("POLLING_STATE_DIR", str(tmp_path / "state"))
    store = _save_tokens(monkeypatch)
    _patch_pipeline(monkeypatch)

    class RevokedConnector(DummyMSGraphConnector):
        def poll_delta(self, access_token, delta_link=None, top=50):
            resp = Response()
            resp.status_code = 401
            raise HTTPError(response=resp)

    monkeypatch.setattr("integrations.polling_worker.MSGraphConnector", RevokedConnector)

    worker = MailPollingWorker("tenant-test", "msgraph", pipeline_endpoint="http://collector")
    with pytest.raises(RuntimeError):
        worker.poll_once()
    assert store.load_tokens("tenant-test") is None


def test_polling_worker_gmail_history_state(tmp_path, monkeypatch):
    monkeypatch.setenv("POLLING_STATE_DIR", str(tmp_path / "state"))
    store = _save_tokens(monkeypatch)
    _patch_pipeline(monkeypatch)
    monkeypatch.setattr("integrations.polling_worker.GmailConnector", DummyGmailConnector)

    worker = MailPollingWorker("tenant-test", "gmail", pipeline_endpoint="http://collector")
    processed = worker.poll_once()
    assert processed == 1

    state = PollingStateStore(str(tmp_path / "state")).load_state("tenant-test", "gmail")
    assert state["history_id"] in {"123", "456"}
    store.delete_tokens("tenant-test")
