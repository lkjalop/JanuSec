import time
import os
import json
import requests
import pytest

from src.integrations.polling_worker import MailPollingWorker
from src.integrations.tenant_store import TenantStore


def make_http_error(status=429, headers=None):
    resp = requests.Response()
    resp.status_code = status
    resp._content = b''
    resp.headers = headers or {}
    return requests.exceptions.HTTPError(response=resp)


def test_retry_respects_retry_after(monkeypatch, tmp_path):
    monkeypatch.setenv('POLLING_STATE_DIR', str(tmp_path / 'polling_state'))
    monkeypatch.setenv('SECRET_BACKEND', 'memory')
    monkeypatch.setenv('CONNECTOR_STATUS_ENDPOINT', '')
    monkeypatch.setenv('POLLING_MAX_ATTEMPTS', '3')
    monkeypatch.setenv('POLLING_BACKOFF_BASE', '0.01')

    tid = 't-retry'
    ts = TenantStore()
    ts.save_tokens(tid, {'access_token': 'good', 'refresh_token': 'r', 'expires_at': int(time.time()) + 3600, 'client_id': 'x', 'client_secret': 'y'})

    class FlakyConnector:
        def __init__(self):
            self.calls = 0

        def poll_delta(self, access_token, delta_link=None):
            self.calls += 1
            if self.calls == 1:
                # raise 429 with Retry-After header
                raise make_http_error(429, {'Retry-After': '0'})
            return {'value': [], '@odata.deltaLink': 'd-new'}

        def parse_messages_to_events(self, payload):
            return []

    worker = MailPollingWorker(tid, 'msgraph')
    # ensure the worker uses the same in-memory tenant store we populated
    worker.store = ts
    worker.conn = FlakyConnector()
    # Should succeed after retry
    count = worker.poll_once()
    assert count == 0
    assert worker.conn.calls >= 2


def test_circuit_opens_after_repeated_errors(monkeypatch, tmp_path):
    monkeypatch.setenv('POLLING_STATE_DIR', str(tmp_path / 'polling_state'))
    monkeypatch.setenv('SECRET_BACKEND', 'memory')
    monkeypatch.setenv('CONNECTOR_STATUS_ENDPOINT', '')
    monkeypatch.setenv('POLLING_MAX_ATTEMPTS', '1')
    monkeypatch.setenv('POLLING_BACKOFF_BASE', '0.001')

    tid = 't-circuit'
    ts = TenantStore()
    ts.save_tokens(tid, {'access_token': 'ok', 'refresh_token': 'r', 'expires_at': int(time.time()) + 3600, 'client_id': 'x', 'client_secret': 'y'})

    class AlwaysErr:
        def poll_delta(self, access_token, delta_link=None):
            raise make_http_error(500)

        def parse_messages_to_events(self, payload):
            return []

    worker = MailPollingWorker(tid, 'msgraph')
    worker.store = ts
    # Lower thresholds for test speed
    worker.circuit_fail_threshold = 2
    worker.circuit_window_seconds = 5
    worker.circuit_open_seconds = 10
    worker.conn = AlwaysErr()

    # First failure
    with pytest.raises(Exception):
        worker.poll_once()
    # Second failure should open circuit
    with pytest.raises(Exception):
        worker.poll_once()
    assert getattr(worker, '_circuit_open_until', 0) > time.time()


def test_401_revocation_deletes_tokens(monkeypatch, tmp_path):
    monkeypatch.setenv('POLLING_STATE_DIR', str(tmp_path / 'polling_state'))
    monkeypatch.setenv('SECRET_BACKEND', 'memory')
    monkeypatch.setenv('CONNECTOR_STATUS_ENDPOINT', '')

    tid = 't-401-del'
    ts = TenantStore()
    ts.save_tokens(tid, {'access_token': 'ok', 'refresh_token': 'r', 'expires_at': int(time.time()) + 3600, 'client_id': 'x', 'client_secret': 'y'})

    class AuthError:
        def poll_delta(self, access_token, delta_link=None):
            raise make_http_error(401)

        def parse_messages_to_events(self, payload):
            return []

    worker = MailPollingWorker(tid, 'msgraph')
    worker.store = ts
    worker.conn = AuthError()
    with pytest.raises(RuntimeError):
        worker.poll_once()
    # tokens should be deleted
    assert ts.load_tokens(tid) is None
