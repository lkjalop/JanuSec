import os, time, asyncio
from src.api import graph_sessions


def test_session_ttl_cleanup():
    os.environ['SESSION_TTL_SECONDS'] = '1'
    payload = {'session_ids': ['batch-overlap-1'], 'correlate': False, 'ewma': False}
    res = asyncio.get_event_loop().run_until_complete(graph_sessions.build_session(payload))
    sid = res.get('session_id') or res.get('summary',{}).get('session_id')
    assert sid
    l1 = asyncio.get_event_loop().run_until_complete(graph_sessions.list_sessions())
    # just created, not expired
    recs = {r['session_id']: r for r in l1.get('sessions',[])}
    assert sid in recs and recs[sid].get('expired') in (False, 0)
    # wait for TTL
    time.sleep(2)
    l2 = asyncio.get_event_loop().run_until_complete(graph_sessions.list_sessions())
    recs2 = {r['session_id']: r for r in l2.get('sessions',[])}
    # either removed or marked expired
    if sid in recs2:
        assert recs2[sid].get('expired') in (True, 1)
    else:
        # session may have been cleaned from _SESSIONS; acceptable
        assert True
    # cleanup env
    del os.environ['SESSION_TTL_SECONDS']
