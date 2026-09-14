import time
from src.graph.cooccurrence import clear, add_pairs, get_top, prune_older, stats, reload_config, get_suppression_templates


def test_cooccurrence_basic():
    clear()
    add_pairs([('a','b'), ('b','c'), ('a','b')])
    top = get_top(10)
    assert len(top) >= 2
    # top[0] should be ('a','b') with count 2.0
    assert top[0][1] >= 2.0
    s = stats()
    assert s['unique_pairs'] >= 2


def test_prune():
    clear()
    add_pairs([('x','y')])
    # artificially set old timestamp by direct manipulation (not ideal but ok for unit test)
    from src.graph import cooccurrence as cc
    with cc._lock:
        for k in list(cc._pairs.keys()):
            cc._pairs[k] = (cc._pairs[k][0], time.time() - 60*60*24*8)
    removed = prune_older(60*60*24*7)
    assert removed >= 1


def test_reload_config_noerror():
    # Ensure reload doesn't crash when config missing
    reload_config('nonexistent.yaml')
    # suppression templates returns a dict
    st = get_suppression_templates()
    assert isinstance(st, dict)
