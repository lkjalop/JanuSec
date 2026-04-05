import sys
import pathlib

p = pathlib.Path(r'D:/AI/Threat_thy_sniffer')
src = p / 'src'
sys.path.insert(0, str(src))

from core.baseline_service import BASELINES, _ANOMALY_Z
import asyncio


async def run():
    try:
        BASELINES._store.clear()
    except Exception:
        pass
    for v in [10, 10, 10, 10, 10, 10]:
        rec_u = await BASELINES.update('host', 'h1', 'score', v)
        print('updated ->', rec_u.count, rec_u.mean, 'rec_id', id(rec_u))
        print('store obj id', id(BASELINES._store), 'type', type(BASELINES._store))
    rec = await BASELINES.get('host', 'h1', 'score')
    print('store keys', list(BASELINES._store.keys()))
    print('store size', len(BASELINES._store))
    print('count', rec.count, 'mean', rec.mean, 'stddev', rec.stddev)
    test_val = 10 + 5 * _ANOMALY_Z
    z = rec.z_score(test_val)
    print('test_val', test_val, 'z', z, 'anomaly?', (abs(z) >= _ANOMALY_Z and rec.count > 5))


asyncio.run(run())
