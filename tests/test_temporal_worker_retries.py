import time
import pytest
from unittest.mock import MagicMock

import src.workers.temporal_worker as worker


def test_retry_db_success_after_retries(monkeypatch):
    calls = {'n':0}
    def flaky():
        calls['n'] += 1
        if calls['n'] < 2:
            raise Exception('transient')
        return 'ok'
    res = worker._retry_db(flaky, retries=3, backoff=0.01)
    assert res == 'ok'
    assert calls['n'] == 2


def test_retry_db_fails_all(monkeypatch):
    def always_fail():
        raise Exception('boom')
    with pytest.raises(Exception):
        worker._retry_db(always_fail, retries=2, backoff=0.001)

@pytest.mark.asyncio
async def test_process_task_handles_db_failure(monkeypatch):
    # Simulate parse_rule returning non-temporal to avoid executor calls
    class MockComp:
        pass
    monkeypatch.setattr('src.rules.dsl_parser.parse_rule', lambda r: MockComp())
    # Make _get_conn raise to exercise retry path and exception handling
    def bad_conn():
        raise Exception('db down')
    monkeypatch.setattr('src.workers.temporal_worker._get_conn', bad_conn)
    row = (1,'t','f','e','a','{}')
    res = await worker._process_task_row(row)
    # Should return False on parse/DB errors
    assert res is False
