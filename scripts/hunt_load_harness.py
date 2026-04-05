"""Hunt Load Harness

Generates synthetic cost events & launches a sequence of hunts for profiling.
Run manually: python -m scripts.hunt_load_harness --hunts 5 --windows 3 24 72
"""
from __future__ import annotations
import argparse, time, random
from core.finops.finops_manager import get_finops_manager
from core.hunt.sidecar_session import get_sidecar_manager

def run(hunts: int, windows: list[int]):
    fm = get_finops_manager(); mgr = get_sidecar_manager()
    tenant = 'load'
    for i in range(hunts):
        # simulate prior hourly costs for variability
        fm._hourly[(tenant,'inference', int(time.time()//3600*3600) - i*3600)] = random.uniform(5,25)
        win = random.choice(windows)
        sess_id = f'load_{i}_{win}'
        mgr.start(sess_id, tenant, window_hours=win, model_enabled=bool(random.getrandbits(1)))
        print('completed', sess_id)

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--hunts', type=int, default=3)
    ap.add_argument('--windows', type=int, nargs='+', default=[3,24,72])
    args = ap.parse_args()
    run(args.hunts, args.windows)
