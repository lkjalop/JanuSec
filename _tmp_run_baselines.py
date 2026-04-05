import sys, pathlib
root = pathlib.Path(__file__).resolve().parents[0]
src = root / 'src'
sys.path.insert(0,str(src))
import asyncio
from core.baseline_service import BASELINES, _ANOMALY_Z

async def _run():
    for v in [10,10,10,10,10,10]:
        rec = await BASELINES.update('host','h1','score',v)
        print('updated rec count:', rec.count, 'mean:', rec.mean)
    rec = await BASELINES.get('host','h1','score')
    print('rec meta:', rec.count, rec.mean, rec.welford_mean, rec.m2, rec.stddev)
    res = await BASELINES.get_z('host','h1','score',10)
    print('res z', res)
    res2 = await BASELINES.get_z('host','h1','score', 10 + 5*_ANOMALY_Z)
    print('res2', res2)

asyncio.run(_run())
