from __future__ import annotations

import asyncio
import datetime
import json
import threading
from pathlib import Path

import pytest

from src.api import deep_analyze_endpoints as dae


def test_bounded_dict_is_dict_and_evicts_fifo():
    store = dae._BoundedDict(maxsize=3)
    assert isinstance(store, dict)

    store['a'] = 1
    store['b'] = 2
    store['c'] = 3
    store['d'] = 4

    assert list(store.keys()) == ['b', 'c', 'd']
    assert 'a' not in store


def test_bounded_dict_update_existing_key_does_not_evict():
    store = dae._BoundedDict(maxsize=2)
    store['a'] = 1
    store['b'] = 2
    store['a'] = 10

    assert list(store.items()) == [('a', 10), ('b', 2)]


def test_bounded_dict_items_are_snapshot_safe():
    store = dae._BoundedDict(maxsize=10)
    store['a'] = 1
    snapshot = store.items()
    store['b'] = 2

    assert isinstance(snapshot, list)
    assert snapshot == [('a', 1)]


def test_bounded_dict_concurrent_writes():
    store = dae._BoundedDict(maxsize=1000)

    def writer(offset: int) -> None:
        for i in range(100):
            store[f'k{offset + i}'] = i

    threads = [threading.Thread(target=writer, args=(n * 100,)) for n in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(store) == 500
    assert store['k0'] == 0
    assert store['k499'] == 99


@pytest.mark.asyncio
async def test_track_task_keeps_task_until_done():
    async def work():
        await asyncio.sleep(0.01)
        return 'done'

    task = dae._track_task(asyncio.create_task(work()))
    assert task in dae._BACKGROUND_TASKS
    assert await task == 'done'
    await asyncio.sleep(0)
    assert task not in dae._BACKGROUND_TASKS


def test_track_task_handles_none():
    assert dae._track_task(None) is None


def test_atomic_json_and_text_helpers(tmp_path: Path):
    json_path = tmp_path / 'data.json'
    text_path = tmp_path / 'note.txt'
    now = datetime.datetime(2026, 1, 1, 12, 0, 0)

    dae._atomic_write_json_sync(str(json_path), {'when': now}, default=str)
    dae._atomic_write_text_sync(str(text_path), 'ready')

    assert json.loads(dae._read_text_sync(str(json_path))) == {'when': '2026-01-01 12:00:00'}
    assert dae._read_text_sync(str(text_path)) == 'ready'
    assert not Path(str(json_path) + '.tmp').exists()


def test_utcnow_is_naive_utc_timestamp():
    before = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    value = dae._utcnow()
    after = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

    assert value.tzinfo is None
    assert before <= value <= after
    assert '+00:00' not in (value.isoformat() + 'Z')


def test_report_store_compatibility():
    assert isinstance(dae.REPORT_STORE, dae._BoundedDict)
    assert isinstance(dae.REPORT_STORE, dict)

    from src.api.deep_analyze_endpoints import REPORT_STORE

    assert REPORT_STORE is dae.REPORT_STORE
