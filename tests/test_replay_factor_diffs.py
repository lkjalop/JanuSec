import os, json, asyncio, time
from fastapi.testclient import TestClient
import src.api.server  # ensure routers
from src.api.app import create_app
app = create_app({'mode': 'test'})

from src.api.replay_endpoints import _run_reprocess

CLIENT = TestClient(app)


def test_replay_factor_diffs(tmp_path, monkeypatch):
    # create custody file
    custody_dir = tmp_path / 'file_batches'
    custody_dir.mkdir(parents=True, exist_ok=True)
    custody_path = custody_dir / 'custody.jsonl'
    # two events with factors
    ev1 = {'id':'e1','ts': 1000.0, 'factors': ['A','B']}
    ev2 = {'id':'e2','ts': 2000.0, 'factors': ['B']}
    with open(custody_path, 'w', encoding='utf8') as fh:
        fh.write(json.dumps(ev1) + '\n')
        fh.write(json.dumps(ev2) + '\n')
    monkeypatch.setenv('FILE_BATCH_CUSTODY_PATH', str(custody_path))
    # create a fake GLOBAL_HOPGRAPH with ingest_event that changes factors for ev1
    class FakeHG:
        def ingest_event(self, ev, source=''):
            if ev.get('id') == 'e1':
                return {'verdict': 'mal', 'score': 0.9, 'factors': ['A','C']}
            return {'verdict': 'ben', 'score': 0.1, 'factors': ['B']}
    monkeypatch.setitem(os.sys.modules, 'src.core.graph.hopgraph_core', None)
    # inject into module path used by replay_endpoints by creating a dummy module
    import types
    fake_mod = types.SimpleNamespace(GLOBAL_HOPGRAPH=FakeHG())
    monkeypatch.setitem(os.sys.modules, 'src.core.graph.hopgraph_core', fake_mod)

    # start a session meta and run worker
    sid = f'replay-{int(time.time()*1000)}'
    meta_dir = os.path.join(os.getcwd(), 'data', 'replays', sid)
    os.makedirs(meta_dir, exist_ok=True)
    # base meta
    with open(os.path.join(meta_dir, 'meta.json'), 'w', encoding='utf8') as fh:
        json.dump({'session_id': sid, 'status': 'queued'}, fh)
    # run worker
    asyncio.run(_run_reprocess(sid, {'from': 0, 'to': 9999999, 'force': True}))
    # read meta
    with open(os.path.join(meta_dir, 'meta.json'), 'r', encoding='utf8') as fh:
        meta = json.load(fh)
    assert meta.get('status') == 'completed'
    fd = meta.get('result', {}).get('factor_diff')
    assert 'added' in fd and 'removed' in fd
    # We expect 'C' added once (ev1 gained C), and 'B' removed from ev1? orig had B and replay had B still -> no removal
    assert fd['added'].get('C', 0) >= 1
    # 'A' remained, 'B' remained in ev2; ensure counts present
    assert isinstance(fd['added'], dict)
    assert isinstance(fd['removed'], dict)
