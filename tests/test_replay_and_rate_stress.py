import time
from src.api.integrations_endpoints import _XDR_REPLAY_CACHE, _XDR_REPLAY_SET, _replay_check, _vendor_rl_allow, _VENDOR_RL_BUCKETS


def test_replay_cache_pruning():
    # simulated keys with old timestamps should be pruned
    # seed cache with timestamps far in past
    now = int(time.time())
    old_keys = []
    for i in range(5):
        k = ('tid', str(now - 10000 - i), f'sig{i}')
        _XDR_REPLAY_CACHE.append(k)
        _XDR_REPLAY_SET.add(k)
    # now call _replay_check with a new key; should prune old entries without error
    ok = _replay_check('tid', str(now), 'newsig')
    assert ok is True


def test_token_bucket_rate_allowance():
    tid = 'testtenant'
    # reset bucket
    _VENDOR_RL_BUCKETS.pop(tid, None)
    allowed = 0
    # consume several tokens quickly
    for _ in range(3):
        if _vendor_rl_allow(tid):
            allowed += 1
    assert allowed >= 1
