from __future__ import annotations
import shutil
from pathlib import Path
import importlib


def test_tfidf_per_tenant_persistence(tmp_path, monkeypatch):
    # use a temp directory for TFIDF_STORE
    monkeypatch.setenv('TFIDF_STORE', str(tmp_path / 'tfidf'))
    import src.ml.tfidf_profile as tfmod
    importlib.reload(tfmod)
    mgr = tfmod.GLOBAL_TFIDF_MANAGER
    t1 = 'tenantA'
    p1 = mgr.get(t1)
    p1.add_document(['host1', 'role:admin'])
    p1.add_document(['host2'])
    mgr.save(t1)
    path = mgr._path_for(t1)
    assert path.exists()
    # reload manager and ensure profile is restored
    importlib.reload(tfmod)
    mgr2 = tfmod.GLOBAL_TFIDF_MANAGER
    p2 = mgr2.get(t1)
    s = p2.get_rarity_score(['host1'])
    assert s >= 0.0 and s <= 1.0


def test_decay_and_eviction(tmp_path, monkeypatch):
    monkeypatch.setenv('TFIDF_STORE', str(tmp_path / 'tfidf'))
    monkeypatch.setenv('TFIDF_MAX_TERMS', '3')
    monkeypatch.setenv('TFIDF_DECAY_FACTOR', '0.5')
    import src.ml.tfidf_profile as tfmod
    importlib.reload(tfmod)
    mgr = tfmod.GLOBAL_TFIDF_MANAGER
    t = 'tenantX'
    p = mgr.get(t)
    # add several unique tokens
    for i in range(6):
        p.add_document([f'host{i}'])
    assert len(p._df) == 6
    # apply decay and eviction
    mgr.decay_and_persist_all()
    # after eviction, should be at most 3 terms
    assert len(p._df) <= 3