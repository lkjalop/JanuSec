import asyncio
import json
import pytest

from unittest.mock import patch, MagicMock

import src.workers.temporal_worker as worker


class DummyCursor:
    def __init__(self, rows=None):
        self._rows = rows or []
        self.closed = False
    def execute(self, *a, **k):
        pass
    def fetchone(self):
        return self._rows[0] if self._rows else None
    def fetchall(self):
        return self._rows
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        pass

class DummyConn:
    def __init__(self, cursor):
        self._cursor = cursor
    def cursor(self):
        return self._cursor
    def commit(self):
        pass
    def close(self):
        pass


@pytest.mark.asyncio
async def test_process_task_row_creates_incident(monkeypatch, tmp_path):
    # Prepare a temporal_tasks row: id, tenant_id, factor_id, event_id, rule_expr, ast
    row = (123, 'tenant-a', 'factor-x', 'evt-1', 'SEQ[...]', '{}')

    # Mock parse_rule to return a Sequence AST instance
    import src.rules.dsl_parser as dsl_mod
    # create a minimal Comparison and Sequence for the AST
    comp = dsl_mod.Comparison(['user'], '==', 'alice')
    seq = dsl_mod.Sequence([comp], 5, 'm')
    monkeypatch.setattr(dsl_mod, 'parse_rule', lambda r: seq)

    # Mock executor to return True
    async def fake_execute_sequence(steps, window, tenant_id):
        return True

    import src.rules.temporal_executor as te_mod
    monkeypatch.setattr(te_mod, 'async_execute_sequence', fake_execute_sequence)

    # Mock _fetch_event_raw to return canonical fields
    monkeypatch.setattr('src.workers.temporal_worker._fetch_event_raw', lambda eid: {'user':'alice','src_ip':'1.2.3.4'})

    # Mock DB connection returned by _get_conn to intercept inserts/updates
    def fake_get_conn():
        cur = DummyCursor(rows=[{'raw':'{}'}])
        return DummyConn(cur)

    monkeypatch.setattr('src.workers.temporal_worker._get_conn', fake_get_conn)

    # Run
    res = await worker._process_task_row(row)
    assert res is True