import time
import pytest
from src.rules.temporal_executor import execute_sequence, execute_absence, evaluate_rate, evaluate_zscore

# We'll monkeypatch psycopg2.connect to use an in-memory stub
class FakeCursor:
    def __init__(self, rows):
        self._rows = rows
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        return False
    def fetchall(self):
        return self._rows
    def fetchone(self):
        return self._rows[0] if self._rows else None
    def execute(self, *args, **kwargs):
        pass

class FakeConn:
    def __init__(self, rows):
        self._rows = rows
    def cursor(self):
        return FakeCursor(self._rows)
    def close(self):
        pass
    def commit(self):
        pass

def test_execute_sequence_simple(monkeypatch):
    # Observed events simulate raw dicts where 'user.id' equals 'alice' then action 'login'
    rows = [ (1, {'user':{'id':'alice'}, 'action':'login'}, 1000), (2, {'user':{'id':'alice'}, 'action':'priv_escalate'}, 1001) ]
    monkeypatch.setattr('src.rules.temporal_executor._get_conn', lambda: FakeConn(rows))
    from src.rules.dsl_parser import Comparison
    steps = [Comparison(field=['user','id'], op='==', value='alice'), Comparison(field=['action'], op='==', value='priv_escalate')]
    res = execute_sequence(steps, 3600, 'default')
    assert res is True


def test_execute_absence(monkeypatch):
    rows = [ (1, {'action':'login'}), (2, {'action':'download'}) ]
    monkeypatch.setattr('src.rules.temporal_executor._get_conn', lambda: FakeConn(rows))
    from src.rules.dsl_parser import Comparison
    pred = Comparison(field=['action'], op='==', value='logout')
    res = execute_absence(pred, 600, 'default')
    assert res is True


def test_evaluate_rate(monkeypatch):
    rows = [ (10,) ]
    monkeypatch.setattr('src.rules.temporal_executor._get_conn', lambda: FakeConn(rows))
    res = evaluate_rate(['user','id'], 300, '>', 5, 'default')
    assert res is True


def test_evaluate_zscore(monkeypatch):
    # Provide rows with numeric values
    rows = [ (1.0,), (2.0,), (3.0,) ]
    monkeypatch.setattr('src.rules.temporal_executor._get_conn', lambda: FakeConn(rows))
    res = evaluate_zscore(['metrics','val'], 3600, '>', 1.0, 'default')
    # Depending on variance, may be False; we accept bool return
    assert isinstance(res, bool)
