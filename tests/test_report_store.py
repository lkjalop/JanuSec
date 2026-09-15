from __future__ import annotations
import os
import json
import tempfile
import shutil
import pytest

from src.core.storage.report_store import InMemoryAdapter, FileAdapter, ReportStoreProxy, migrate_from_inmemory


def test_inmemory_adapter_basic():
    mem = InMemoryAdapter()
    mem.save('a1', {'x': 1})
    assert mem.get('a1')['x'] == 1
    assert 'a1' in list(mem.list_keys())
    mem.delete('a1')
    assert mem.get('a1') is None


def test_file_adapter_roundtrip(tmp_path):
    base = str(tmp_path)
    fa = FileAdapter(base_dir=base)
    payload = {'assessment_id': 'test1', 'value': 123}
    fa.save('test1', payload)
    loaded = fa.get('test1')
    assert isinstance(loaded, dict)
    assert loaded.get('value') == 123
    keys = list(fa.list_keys())
    assert 'test1' in keys
    fa.delete('test1')
    assert fa.get('test1') is None


def test_migrate_from_inmemory_to_file(tmp_path):
    base = str(tmp_path)
    fa = FileAdapter(base_dir=base)
    source = {'a': {'assessment_id':'a', 'v':1}, 'b': {'assessment_id':'b','v':2}}
    # use explicit proxy target
    proxy = ReportStoreProxy(adapter=fa)
    migrated = migrate_from_inmemory(source, target=proxy)
    assert migrated == 2
    assert proxy.get('a')['v'] == 1
    assert proxy.get('b')['v'] == 2

@pytest.mark.skipif(os.getenv('REDIS_URL') is None, reason='Redis not configured')
def test_redis_adapter_smoke():
    from src.core.storage.report_store import RedisAdapter
    r = RedisAdapter()
    r.save('r1', {'v': 5})
    assert r.get('r1')['v'] == 5
    r.delete('r1')
    assert r.get('r1') is None

@pytest.mark.skipif(os.getenv('DATABASE_URL') is None, reason='Postgres not configured')
def test_postgres_adapter_smoke():
    from src.core.storage.report_store import PostgresAdapter
    p = PostgresAdapter()
    p.save('p1', {'v': 9})
    assert p.get('p1')['v'] == 9
    p.delete('p1')
    assert p.get('p1') is None
