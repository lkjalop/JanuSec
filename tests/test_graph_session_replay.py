import time
from types import SimpleNamespace

from src.api import graph_sessions as gs


def test_dependency_status_exposes_replay_history(monkeypatch):
    gs._DEGRADED_FACTOR_QUEUE.clear()
    gs._DEGRADED_REPLAY_LOG.clear()
    now = time.time()
    gs._DEGRADED_FACTOR_QUEUE.append({
        'session_id': 'sess-1',
        'factors': [{'factor': 'demo'}],
        'timestamp': now - 5,
    })
    summary: dict = {}
    dependency = {'hopgraph': {'available': True, 'stale': False}, 'redis': {'available': True}}
    gs._replay_degraded_factors(summary, dependency)
    assert summary.get('replayed_batch_count') == 1
    assert gs._DEGRADED_REPLAY_LOG
    monkeypatch.setenv('REDIS_URL', '')
    monkeypatch.setenv('CACHE_REDIS_URL', '')
    monkeypatch.setenv('TEMPORAL_REDIS_URL', '')
    dummy_graph = SimpleNamespace(last_snapshot_ts=now)
    monkeypatch.setattr(gs, 'get_graph', lambda: dummy_graph)
    status = gs._check_dependency_status(force_refresh=True)
    assert status.get('replay_history')
    assert status.get('last_replay_ts')
    assert status.get('queued_factor_batches') == 0
