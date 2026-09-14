import os
import time
import pytest
from src.dedup.store import dedup_check_set  # type: ignore


def test_dedup_inmemory_fallback():
    k = f'test-{int(time.time()*1000)}'
    assert dedup_check_set(k, ttl=1) is True
    assert dedup_check_set(k, ttl=1) is False
    time.sleep(1.1)
    assert dedup_check_set(k, ttl=1) is True
