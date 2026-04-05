from src.jobs.retention_sweeper import sweep_once
import pytest

class FakeCursor:
    def __init__(self, rows):
        self._rows = rows
    def fetchall(self):
        return self._rows
    def fetchone(self):
        return self._rows[0] if self._rows else (0,)
    def execute(self, *args, **kwargs):
        pass
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        return False

class FakeConn:
    def __init__(self, rows):
        self._rows = rows
    def cursor(self):
        return FakeCursor(self._rows)
    def close(self):
        pass
    def commit(self):
        pass

def test_sweep_once_dryrun(monkeypatch):
    # Simulate one tenant entry with 5 deletable events
    def fake_load():
        return {'tenantA': {'retention_days': 1}}
    monkeypatch.setattr('src.jobs.retention_sweeper._load_retention_configs', fake_load)
    # Patch DB connection
    monkeypatch.setattr('src.jobs.retention_sweeper._get_conn', lambda: FakeConn([(5,)]))
    res = sweep_once(dry_run=True)
    assert isinstance(res, dict)
    assert 'tenantA' in res
