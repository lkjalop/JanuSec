import os
import pytest

from src.core.storage.report_store import PostgresAdapter


@pytest.mark.skipif(not os.getenv('DATABASE_URL'), reason='DATABASE_URL not configured')
def test_postgres_adapter_basic_crud():
    dsn = os.getenv('DATABASE_URL')
    adapter = PostgresAdapter(dsn)
    aid = 'test-postgres-adapter-1'
    payload = {'hello': 'world'}
    adapter.delete(aid)
    assert adapter.get(aid) is None
    adapter.save(aid, payload)
    got = adapter.get(aid)
    assert got is not None and got.get('hello') == 'world'
    adapter.delete(aid)
    assert adapter.get(aid) is None
