import time
import pytest
from src.integrations._backoff import retry_with_backoff


class DummyResp:
    def __init__(self, headers):
        self.headers = headers


class RetryAfterExc(Exception):
    def __init__(self, msg, retry_after=None, response=None):
        super().__init__(msg)
        if retry_after is not None:
            self.retry_after = retry_after
        self.response = response


def test_retry_after_attribute(monkeypatch):
    calls = {"n": 0, "slept": []}

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RetryAfterExc("429", retry_after=0.03)
        return "ok"

    def fake_sleep(s):
        calls["slept"].append(s)

    monkeypatch.setattr("time.sleep", fake_sleep)
    res = retry_with_backoff(flaky, attempts=3, base_sleep=0.01, jitter=0)
    assert res == "ok"
    assert calls["slept"][0] == pytest.approx(0.03, rel=1e-6)


def test_retry_after_header_seconds(monkeypatch):
    calls = {"n": 0, "slept": []}

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            resp = DummyResp({"Retry-After": "2"})
            raise RetryAfterExc("429", response=resp)
        return "ok"

    def fake_sleep(s):
        calls["slept"].append(s)

    monkeypatch.setattr("time.sleep", fake_sleep)
    res = retry_with_backoff(flaky, attempts=3, base_sleep=0.01, jitter=0)
    assert res == "ok"
    assert calls["slept"][0] == pytest.approx(2.0, rel=1e-6)


def test_retry_after_header_httpdate(monkeypatch):
    calls = {"n": 0, "slept": []}

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            # set Retry-After to a date 1 second in the future
            from datetime import datetime, timezone

            future = (datetime.now(timezone.utc).timestamp() + 1)
            httpdate = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime(future))
            resp = DummyResp({"Retry-After": httpdate})
            raise RetryAfterExc("429", response=resp)
        return "ok"

    def fake_sleep(s):
        calls["slept"].append(s)

    monkeypatch.setattr("time.sleep", fake_sleep)
    res = retry_with_backoff(flaky, attempts=3, base_sleep=0.01, jitter=0)
    assert res == "ok"
    # Allow small timing fuzz (parsing and scheduling may differ across envs)
    assert calls["slept"][0] >= 0.05
