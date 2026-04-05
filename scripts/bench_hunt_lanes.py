"""Benchmark Hunt Lane Overhead

Runs synthetic events through pipeline twice:
  1. Lanes enabled (advisory)
  2. Lanes disabled
Reports p50/p95 latency and overhead ratio.

Usage:
  python scripts/bench_hunt_lanes.py --events 2000
"""
from __future__ import annotations
import time, argparse, statistics, asyncio, random
from typing import List

async def run_pass(count: int, enable: bool) -> List[float]:
    from main import SecurityOrchestrator
    orch = SecurityOrchestrator()
    await orch.initialize()
    orch.event_pipeline.config.setdefault('pipeline', {}).setdefault('hunt_lanes', {})['enabled'] = enable  # type: ignore
    latencies = []
    for i in range(count):
        ev = {
            'id': f'ev{i}',
            'process_name': 'powershell.exe' if i % 17 == 0 else 'proc.exe',
            'parent_process_name': 'winword.exe' if i % 17 == 0 else 'parent.exe',
            'cmdline': 'powershell.exe -enc AAAA' if i % 23 == 0 else 'proc.exe',
            'ja3_hash': 'hash'+str(i%50)
        }
        start = time.perf_counter()
        await orch.process_event(ev)
        latencies.append((time.perf_counter()-start)*1000)
    await orch.shutdown()
    return latencies

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--events', type=int, default=1000)
    args = ap.parse_args()
    on_lat = await run_pass(args.events, True)
    off_lat = await run_pass(args.events, False)
    def stats(arr):
        return {
            'count': len(arr),
            'p50': statistics.median(arr),
            'p95': sorted(arr)[int(len(arr)*0.95)-1] if arr else 0.0
        }
    s_on = stats(on_lat)
    s_off = stats(off_lat)
    overhead_p95 = s_on['p95'] - s_off['p95']
    ratio = (s_on['p95']/s_off['p95']) if s_off['p95'] else None
    print({
        'lanes_enabled': s_on,
        'lanes_disabled': s_off,
        'p95_overhead_ms': overhead_p95,
        'p95_ratio': ratio
    })

if __name__ == '__main__':
    asyncio.run(main())
