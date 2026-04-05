from __future__ import annotations
import time

from src.core.storage.report_store import ReportStoreProxy, InMemoryAdapter, incremental_rerank


def test_incremental_rerank_merges_and_sorts():
    store = ReportStoreProxy(adapter=InMemoryAdapter())
    aid = 'assessment-1'
    # seed with existing ranking
    store.save(aid, {'ranking': [{'id': 'a', 'score': 5.0, 'updated_ts': time.time()}, {'id': 'b', 'score': 3.0, 'updated_ts': time.time()}]})

    # new partial scores arrive
    new_scores = {'b': 8.0, 'c': 6.5}
    incremental_rerank(aid, new_scores, target=store)

    rep = store.get(aid)
    assert 'ranking' in rep
    ranking = rep['ranking']
    # should contain three entries sorted by score desc
    ids = [r['id'] for r in ranking]
    assert ids == ['b', 'c', 'a']
    # scores updated
    scores = {r['id']: r['score'] for r in ranking}
    assert scores['b'] == 8.0
    assert scores['c'] == 6.5
    assert scores['a'] == 5.0
