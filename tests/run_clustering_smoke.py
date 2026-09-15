import asyncio
import hashlib
import sys
import pathlib
import asyncio
import hashlib
import time

# Make the local 'src' package importable so this script runs without setting PYTHONPATH
ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / 'src'
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from core.clustering_service import ClusteringService


async def main():
    svc = ClusteringService(window_seconds=10, max_samples=4)
    sig = 'ruleA|ruleB::ioc:1.2.3.4'
    cluster_id = hashlib.sha1(sig.encode('utf-8')).hexdigest()

    res1 = await svc.update(cluster_id, 'evt-1', ts=time.time())
    print('res1', res1)
    res2 = await svc.update(cluster_id, 'evt-2', ts=time.time() + 1)
    print('res2', res2)
    res3 = await svc.update(cluster_id, 'evt-3', ts=time.time() + 20)
    print('res3', res3)


if __name__ == '__main__':
    asyncio.run(main())
