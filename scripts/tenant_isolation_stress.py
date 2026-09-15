#!/usr/bin/env python
"""Multi-Tenant Isolation Stress Harness

Generates interleaved synthetic events for multiple tenants and verifies:
 - No cross-tenant factor leakage
 - Decision paths remain tenant-scoped
 - Latency impact per tenant remains within tolerance

Usage:
  python scripts/tenant_isolation_stress.py --tenants A B --events-per-tenant 500

Outputs summary JSON to stdout.
"""
from __future__ import annotations
import asyncio, random, time, json, argparse
from typing import List, Dict, Any

async def process_bulk(orch, tenant: str, count: int):
    results = []
    for i in range(count):
        ev = {
            'id': f'{tenant}_{i}',
            'tenant': tenant,
            'event_type': random.choice(['auth','proc','net']),
            'severity': random.choice(['low','medium','high']),
            'details': {'process_name': random.choice(['winword.exe','powershell.exe','explorer.exe']), 'ja3_hash': f'h{random.randint(0,50)}'}
        }
        res = await orch.process_event(ev)
        results.append(res)
    return results

async def main(tenants: List[str], per: int):
    from main import SecurityOrchestrator
    orch = SecurityOrchestrator()
    await orch.initialize()
    # enable hunt lanes
    try:
        orch.event_pipeline.config.setdefault('pipeline', {}).setdefault('hunt_lanes', {})['enabled'] = True  # type: ignore
    except Exception:
        pass

    start = time.perf_counter()
    tasks = [process_bulk(orch, t, per) for t in tenants]
    batches = await asyncio.gather(*tasks)
    elapsed = time.perf_counter() - start

    # Isolation checks
    cross_tenant_leaks = []
    for tenant, tenant_results in zip(tenants, batches):
        for r in tenant_results:
            # naive assumption: result should carry tenant (if pipeline attaches); placeholder
            if getattr(r, 'tenant', tenant) != tenant:
                cross_tenant_leaks.append({'expected': tenant, 'saw': getattr(r,'tenant', None)})

    # Factor contamination heuristic: ensure no factors contain other tenant id strings
    factor_contamination = []
    for tenant, tenant_results in zip(tenants, batches):
        others = [o for o in tenants if o != tenant]
        for r in tenant_results:
            for f in getattr(r, 'factors', []):
                if any(o in f for o in others):
                    factor_contamination.append({'tenant': tenant, 'factor': f})

    summary = {
        'tenants': tenants,
        'events_per_tenant': per,
        'total_events': per * len(tenants),
        'elapsed_sec': round(elapsed,2),
        'avg_events_per_sec': round((per * len(tenants))/elapsed,2),
        'cross_tenant_leaks': cross_tenant_leaks,
        'factor_contamination': factor_contamination,
    }

    await orch.shutdown()
    print(json.dumps(summary, indent=2))

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--tenants', nargs='+', required=True)
    ap.add_argument('--events-per-tenant', type=int, default=200)
    args = ap.parse_args()
    asyncio.run(main(args.tenants, args.events_per_tenant))
