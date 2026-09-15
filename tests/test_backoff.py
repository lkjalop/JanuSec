import pytest

import time
import random

from src.integrations._backoff import retry_with_backoff


def test_retry_success(monkeypatch):
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise ValueError("temporary")
        return "ok"

    # avoid real sleeping and randomness in tests
    monkeypatch.setattr("time.sleep", lambda s: None)
    monkeypatch.setattr("random.uniform", lambda a, b: 0)

    result = retry_with_backoff(flaky, attempts=5, base_sleep=0.001)
    assert result == "ok"
    assert calls["n"] == 3


def test_retry_fail(monkeypatch):
    def always_fail():
        raise RuntimeError("fail")

    monkeypatch.setattr("time.sleep", lambda s: None)
    monkeypatch.setattr("random.uniform", lambda a, b: 0)

    with pytest.raises(RuntimeError):
        retry_with_backoff(always_fail, attempts=3, base_sleep=0.001)
