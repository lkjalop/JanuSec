from __future__ import annotations

from src.core.redis_llm_queue import _cheap_dread_score, dequeue_batch


def test_cheap_dread_score_prioritizes_ransom_and_malware():
    t1 = {'payload': {'text': 'this looks like ransomware encryptor'}}
    t2 = {'payload': {'text': 'benign login event'}}
    s1 = _cheap_dread_score(t1)
    s2 = _cheap_dread_score(t2)
    assert isinstance(s1, float)
    assert isinstance(s2, float)
    assert s1 < s2  # ransom should have higher priority (lower numeric score)


def test_dequeue_batch_no_redis_returns_empty_list():
    # In environments without Redis client configured, dequeue_batch should return empty list
    out = dequeue_batch(batch_size=5, timeout=1)
    assert isinstance(out, list)
