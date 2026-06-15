"""REPORT_STORE memory-safety + atomic persistence.

The Phase A refactor extracted persistence.py and (accidentally) dropped the
bound on REPORT_STORE, turning it into a plain unbounded dict — a latent OOM in
long-running servers. This suite pins the restored contract:

  - REPORT_STORE is a thread-safe FIFO-bounded dict (_BoundedDict).
  - eviction flushes persisted entries to disk so reads can still recover them.
  - the live atomic JSON writer leaves no .tmp behind.

The previous version of this file also tested _track_task / _utcnow /
_atomic_write_*_sync helpers that the refactor removed (0 callers in src/); those
assertions were testing dead code and have been dropped. Atomic-write coverage
now targets the live helper, src.api.persist_utils.atomic_write_json.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

from src.api.deep_analyze import persistence as P
from src.api import deep_analyze_endpoints as dae
from src.api.persist_utils import atomic_write_json


def test_bounded_dict_is_dict_and_evicts_fifo():
    store = P._BoundedDict(maxsize=3)
    assert isinstance(store, dict)

    store['a'] = 1
    store['b'] = 2
    store['c'] = 3
    store['d'] = 4  # over cap -> evict oldest ('a')

    assert list(store.keys()) == ['b', 'c', 'd']
    assert 'a' not in store


def test_bounded_dict_update_existing_key_does_not_evict():
    store = P._BoundedDict(maxsize=2)
    store['a'] = 1
    store['b'] = 2
    store['a'] = 10  # update existing -> keeps position, no eviction

    assert list(store.items()) == [('a', 10), ('b', 2)]


def test_bounded_dict_items_are_snapshot_safe():
    store = P._BoundedDict(maxsize=10)
    store['a'] = 1
    snapshot = store.items()
    store['b'] = 2

    assert isinstance(snapshot, list)
    assert snapshot == [('a', 1)]


def test_bounded_dict_concurrent_writes():
    store = P._BoundedDict(maxsize=1000)

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


def test_eviction_flushes_persisted_entry_to_disk(tmp_path: Path):
    # An evicted entry that carries a persisted_path must be written to disk so a
    # later read can recover it (the disk fallback in _get_assessment_cached).
    store = P._BoundedDict(maxsize=1)
    disk_path = tmp_path / 'a.json'
    store['a'] = {'id': 'a', 'persisted_path': str(disk_path), 'v': 1}
    assert not disk_path.exists()  # still in memory, not yet flushed
    store['b'] = {'id': 'b'}       # evicts 'a' -> flush to disk
    assert 'a' not in store
    assert json.loads(disk_path.read_text(encoding='utf-8'))['v'] == 1


def test_report_store_is_bounded_and_reexported():
    assert isinstance(P.REPORT_STORE, P._BoundedDict)
    assert isinstance(P.REPORT_STORE, dict)
    # deep_analyze_endpoints re-exports the same object for back-compat callers.
    assert dae.REPORT_STORE is P.REPORT_STORE
    assert dae._BoundedDict is P._BoundedDict


def test_atomic_write_json_leaves_no_tmp(tmp_path: Path):
    json_path = tmp_path / 'data.json'
    atomic_write_json(str(json_path), {'when': 'now'})
    assert json.loads(json_path.read_text(encoding='utf-8')) == {'when': 'now'}
    assert not Path(str(json_path) + '.tmp').exists()
