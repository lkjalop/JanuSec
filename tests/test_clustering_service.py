import asyncio
import hashlib
import time

import pytest

from core.clustering_service import ClusteringService


@pytest.mark.asyncio
async def test_cluster_id_stable_and_duplicate():
    svc = ClusteringService(window_seconds=10, max_samples=4)
    # Create synthetic signature parts (simulate same raw_sig => same cluster)
    sig = 'ruleA|ruleB::ioc:1.2.3.4'
    cluster_id = hashlib.sha1(sig.encode('utf-8')).hexdigest()

    res1 = await svc.update(cluster_id, 'evt-1', ts=time.time())
    assert res1['cluster_id'] == cluster_id
    assert res1['size'] == 1
    assert res1['is_duplicate'] is False

    # Within window -> duplicate
    res2 = await svc.update(cluster_id, 'evt-2', ts=time.time() + 1)
    assert res2['cluster_id'] == cluster_id
    assert res2['size'] == 2
    assert res2['is_duplicate'] is True

    # After window -> not duplicate
    res3 = await svc.update(cluster_id, 'evt-3', ts=time.time() + 20)
    assert res3['size'] == 3
    # previous last_ts was res2 last_ts; now gap > window_seconds so is_duplicate False
    assert res3['is_duplicate'] is False
