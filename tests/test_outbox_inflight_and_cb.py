import asyncio
import json
import time
import os
import pytest

from src.outbox import async_consumer as ac


def test_inflight_tracker_ttl():
    t = ac.InFlightTracker(ttl_seconds=1)
    t.add('a')
    assert t.contains('a')
    time.sleep(1.2)
    assert not t.contains('a')


@pytest.mark.asyncio
async def test_circuit_breaker_opens(tmp_path, monkeypatch):
    # set small CB_WINDOW and threshold for test
    monkeypatch.setenv('OUTBOX_CB_WINDOW', '3')
    monkeypatch.setenv('OUTBOX_CB_FAIL_RATIO', '0.5')
    monkeypatch.setenv('OUTBOX_CB_COOLDOWN_SEC', '1')
    # update module-level values
    ac.CB_WINDOW = 3
    ac.CB_FAIL_RATIO = 0.5
    ac.CB_COOLDOWN = 1

    statefile = tmp_path / 'state.json'
    ac.OUTBOX_STATE = str(statefile)

    # simulate failures
    ac._save_state({'offset':0,'circuit_open_until':0,'recent_failures':[]})
    ac._register_failure()
    ac._register_failure()
    # after two failures with window=3 and ratio=0.5, ratio=2/3 ~= 0.666 >= 0.5 so circuit opens
    s = ac._load_state()
    assert s.get('circuit_open_until', 0) > 0
    # ensure circuit_open_until is in the future
    assert s.get('circuit_open_until', 0) >= int(time.time())