"""Simple multi-tenant validation harness.

Generates synthetic events across tenants and verifies no factors leak between tenants.
Writes a JSON report to reports/tenant_isolation_snapshot.json and returns a violation count.
"""
import json
import os
import random
import time
from typing import List, Dict
import os

from src.core.correlation.rules.registry import CORRELATION_RULES

REPORT_PATH = os.path.join('reports','tenant_isolation_snapshot.json')


def generate_event(tenant: str, idx: int) -> Dict:
    base_ip = f'10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}'
    ev = {
        'event_id': f'{tenant}-{idx}',
        'tenant_id': tenant,
        'src_ip': base_ip,
        'dst_ip': '8.8.8.8',
        'protocol': random.choice(['ssh','http','dns']),
        'dst_port': random.choice([22,80,443,2223,8080]),
        'user_agent': random.choice(['curl/7.68.0','Mozilla/5.0','wget/1.20']),
        'failed_login_count': random.randint(0,10),
        'process': random.choice(['certutil.exe','powershell.exe','svchost.exe']),
    }
    return ev


def run_harness(tenants: List[str], events_per_tenant: int = 50, seed: int | None = None) -> Dict:
    # Deterministic seed: use provided seed or env var, default 42
    try:
        seed_val = int(seed) if seed is not None else int(os.getenv('MULTITENANT_HARNESS_SEED', '42'))
    except Exception:
        seed_val = 42
    random.seed(seed_val)

    # capture produced factors per-tenant
    produced = {t: set() for t in tenants}
    violations = 0
    for t in tenants:
        for i in range(events_per_tenant):
            ev = generate_event(t, i)
            fired = CORRELATION_RULES.evaluate(ev)
            for r in fired:
                produced[t].add(r.name)
    # detect cross-tenant leakage: if any factor from tenant A appears in tenant B's produced set
    all_pairs = []
    for i, a in enumerate(tenants):
        for b in tenants[i+1:]:
            overlap = produced[a] & produced[b]
            if overlap:
                violations += len(overlap)
                all_pairs.append({'a': a, 'b': b, 'overlap': list(overlap)})
    report = {
        'ts': time.time(),
        'tenants': tenants,
        'produced': {k: list(v) for k, v in produced.items()},
        'violations': violations,
        'pairs': all_pairs,
    }
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    with open(REPORT_PATH, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    # Fail CI optionally when violations detected
    if int(os.getenv('MULTITENANT_FAIL_ON_VIOLATIONS', '0')):
        if violations > 0:
            print(f"[multi_tenant_harness] Detected {violations} violations; failing as configured.")
            raise SystemExit(2)

    return report


if __name__ == '__main__':
    r = run_harness(['tenantA','tenantB','tenantC'], events_per_tenant=30)
    print(json.dumps(r, indent=2))
