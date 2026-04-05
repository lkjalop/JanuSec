import time
from datetime import datetime, timedelta, timezone
import pytest

from src.integrations._backoff import retry_with_backoff
from src.integrations.http_exceptions import HTTPRetryError


class AttrRetryTransport:
    def __init__(self, retry_after):
        self.attempts = 0
        self.retry_after = retry_after

    def __call__(self):
        self.attempts += 1
        raise HTTPRetryError("rate limit", retry_after=self.retry_after, status_code=429)


class HeaderSecondsTransport:
    def __init__(self, seconds):
        self.seconds = seconds
        self.attempts = 0

    def __call__(self):
        self.attempts += 1
        # simulate a response-like object with headers
        resp = type("R", (), {"headers": {"Retry-After": str(self.seconds)}})()
        raise HTTPRetryError("rate limit", response=resp, status_code=429)


class HeaderDateTransport:
    def __init__(self, seconds_from_now):
        self.seconds_from_now = seconds_from_now
        self.attempts = 0

    def __call__(self):
        self.attempts += 1
        future = (datetime.now(timezone.utc) + timedelta(seconds=self.seconds_from_now))
        http_date = future.strftime("%a, %d %b %Y %H:%M:%S GMT")
        resp = type("R", (), {"headers": {"Retry-After": http_date}})()
        raise HTTPRetryError("rate limit", response=resp, status_code=429)


def test_attr_retry_sleep(monkeypatch):
    transport = AttrRetryTransport(0.03)
    sleeps = []

    def fake_sleep(s):
        sleeps.append(s)

    monkeypatch.setattr("time.sleep", fake_sleep)

    with pytest.raises(HTTPRetryError):
        retry_with_backoff(transport, attempts=2, base_sleep=0.01, jitter=0)

    # attribute-specified retry_after should be honored exactly on first sleep
    assert len(sleeps) >= 1
    assert abs(sleeps[0] - 0.03) < 1e-6


def test_header_seconds_retry_sleep(monkeypatch):
    transport = HeaderSecondsTransport(1)
    sleeps = []

    def fake_sleep(s):
        sleeps.append(s)

    monkeypatch.setattr("time.sleep", fake_sleep)

    with pytest.raises(HTTPRetryError):
        retry_with_backoff(transport, attempts=2, base_sleep=0.01, jitter=0)

    # header seconds should be parsed and used (and may be larger than safety minimum)
    assert sleeps[0] >= 0.05
    assert abs(sleeps[0] - 1) < 1e-6


def test_header_date_retry_sleep_applies_minimum(monkeypatch):
    # Use a very small future delta to ensure header-derived minimum kicks in
    transport = HeaderDateTransport(seconds_from_now=0.01)
    sleeps = []

    def fake_sleep(s):
        sleeps.append(s)

    monkeypatch.setattr("time.sleep", fake_sleep)

    with pytest.raises(HTTPRetryError):
        retry_with_backoff(transport, attempts=2, base_sleep=0.01, jitter=0)

    # header-derived tiny deltas should be elevated to the safety minimum (~>=0.05)
    assert len(sleeps) >= 1
    assert sleeps[0] >= 0.05
