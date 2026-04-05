import os
import sqlite3
from src.graph.cooccurrence import clear, add_pairs, flush_to_db, get_counts


def test_persistence_roundtrip(tmp_path, monkeypatch):
    db = tmp_path / 'coocc.db'
    monkeypatch.setenv('COOCCURRENCE_SQLITE_PATH', str(db))
    clear()
    add_pairs([('x','y'),('x','z'),('y','z')])
    flush_to_db()
    pair_counts, marg, total = get_counts()
    assert total >= 3
    # ensure marginals include 'x'
    assert 'x' in marg
