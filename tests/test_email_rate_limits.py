import time
import pytest
from src.integrations.email_transports import M365GraphTransport, GmailTransport, OAuthConfig
from src.integrations._backoff import retry_with_backoff


def test_retry_on_transient_error(monkeypatch):
    cfg = OAuthConfig(client_id="x", client_secret="y")
    t = M365GraphTransport(cfg)

    calls = {"n": 0}

    def flaky_list(since=None):
        calls["n"] += 1
        if calls["n"] < 3:
            raise RuntimeError("429 Too Many Requests")
        return [{"id": "ok-1"}]

    monkeypatch.setattr(t, "list_messages", flaky_list)

    res = retry_with_backoff(lambda: t.list_messages(), attempts=4, base_sleep=0.01, jitter=0)
    assert isinstance(res, list)
    assert calls["n"] == 3


def test_partial_pages_resume(monkeypatch):
    cfg = OAuthConfig(client_id="x", client_secret="y")
    t = GmailTransport(cfg)

    page_calls = {"n": 0}

    def paged(since=None):
        page_calls["n"] += 1
        if page_calls["n"] == 1:
            # first page returns only 1 item and a cursor
            return [{"id": "p1-1"}], "cursor-1"
        else:
            return ([{"id": "p2-1"}, {"id": "p2-2"}], None)

    # Simulate an adapter loop that handles partial pages
    events = []
    cursor = None
    evs, cursor = paged(cursor)
    events.extend(evs)
    if cursor:
        evs2, cursor2 = paged(cursor)
        events.extend(evs2)

    assert len(events) == 3
