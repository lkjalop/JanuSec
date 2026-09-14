from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import httpx

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.multicloud_pressure_replay import build_multicloud_rows


def _chunk_rows(rows: List[Dict[str, Any]], batch_size: int) -> List[List[Dict[str, Any]]]:
    if batch_size <= 0:
        batch_size = 50
    return [rows[idx:idx + batch_size] for idx in range(0, len(rows), batch_size)]


async def _flush_batch(app: Any, tenant: str, variant: str, batch_id: int, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    transport = httpx.ASGITransport(app=app)
    started = time.perf_counter()
    async with httpx.AsyncClient(transport=transport, base_url='http://testserver') as client:
        resp = await client.post(
            '/api/v1/csv/deep_analyze',
            headers={'x-api-key': 'devkey123', 'X-Tenant-ID': tenant},
            json={
                'org': tenant,
                'rows': rows,
                'options': {
                    'auto_llm': True,
                    'intake_mode': 'live',
                    'provider_profile': 'multi_cloud',
                    'queue_mode': 'kafka_compatible_microbatch',
                },
            },
        )
    payload = resp.json()
    latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
    return {
        'variant': variant,
        'batch_id': batch_id,
        'rows': len(rows),
        'status_code': resp.status_code,
        'latency_ms': latency_ms,
        'clusters': len(payload.get('correlation_clusters') or []),
        'correlated_rows': len([row for row in (payload.get('evidence_rows') or []) if row.get('correlation_type') == 'correlated']),
    }


async def run_queue_pressure_async(employee_count: int = 200, batch_size: int = 60, workers: int = 3) -> Dict[str, Any]:
    os.environ.setdefault('API_KEYS_JSON', '[{"key":"devkey123","scopes":["*"]}]')
    os.environ.setdefault('DEFAULT_FRONTEND', 'investigate')
    os.environ.setdefault('LLM_MOCK', '1')
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from src.api.app import create_app

    app = create_app()
    queue: asyncio.Queue[Dict[str, Any] | None] = asyncio.Queue()
    results: List[Dict[str, Any]] = []
    enqueue_waits: List[float] = []
    producer_latencies: List[float] = []

    async def producer(variant: str) -> None:
        rows = build_multicloud_rows(employee_count=employee_count, variant=variant)
        for batch_id, batch in enumerate(_chunk_rows(rows, batch_size), start=1):
            envelope = {
                'topic': 'janusec.normalized',
                'key': f'{variant}:{batch_id}',
                'tenant': f'queue-{variant}',
                'variant': variant,
                'batch_id': batch_id,
                'rows': batch,
                'enqueued_at': time.perf_counter(),
            }
            t0 = time.perf_counter()
            await queue.put(envelope)
            enqueue_waits.append((time.perf_counter() - t0) * 1000.0)
            producer_latencies.append((time.perf_counter() - envelope['enqueued_at']) * 1000.0)

    async def consumer(worker_id: int) -> None:
        while True:
            envelope = await queue.get()
            try:
                if envelope is None:
                    return
                result = await _flush_batch(
                    app,
                    tenant=envelope['tenant'],
                    variant=envelope['variant'],
                    batch_id=int(envelope['batch_id']),
                    rows=envelope['rows'],
                )
                result['worker_id'] = worker_id
                result['queue_lag_ms'] = round((time.perf_counter() - envelope['enqueued_at']) * 1000.0, 2)
                results.append(result)
            finally:
                queue.task_done()

    started = time.perf_counter()
    consumers = [asyncio.create_task(consumer(worker_id)) for worker_id in range(1, workers + 1)]
    await asyncio.gather(producer('okta_aws_azure'), producer('ad_aws_vmware_bec'))
    for _ in consumers:
        await queue.put(None)
    await queue.join()
    await asyncio.gather(*consumers)
    elapsed_ms = round((time.perf_counter() - started) * 1000.0, 2)
    total_rows = sum(item['rows'] for item in results)
    throughput = round(total_rows / max(elapsed_ms / 1000.0, 0.001), 2)
    queue_lags = [item['queue_lag_ms'] for item in results]
    p95 = sorted(queue_lags)[max(0, int(len(queue_lags) * 0.95) - 1)] if queue_lags else 0.0
    pressure = 'high' if p95 > 8000 else 'medium' if p95 > 3000 else 'low'
    return {
        'employee_count': employee_count,
        'batch_size': batch_size,
        'workers': workers,
        'total_batches': len(results),
        'total_rows': total_rows,
        'elapsed_ms': elapsed_ms,
        'throughput_rows_per_second': throughput,
        'queue_pressure': pressure,
        'enqueue_wait_p95_ms': round(sorted(enqueue_waits)[max(0, int(len(enqueue_waits) * 0.95) - 1)] if enqueue_waits else 0.0, 2),
        'queue_lag_p95_ms': round(p95, 2),
        'batch_latency_p95_ms': round(sorted([item['latency_ms'] for item in results])[max(0, int(len(results) * 0.95) - 1)] if results else 0.0, 2),
        'recommendations': [
            'Keep Kafka-compatible microbatch envelopes tenant-scoped and partitioned by provider-rich evidence mode.',
            'Scale consumer workers horizontally before introducing Flink-class stateful streaming.',
            'Apply backpressure by slowing producers or raising batch size when queue lag crosses the medium threshold.',
        ],
        'batches': results,
    }


def run_queue_pressure(employee_count: int = 200, batch_size: int = 60, workers: int = 3) -> Dict[str, Any]:
    return asyncio.run(run_queue_pressure_async(employee_count=employee_count, batch_size=batch_size, workers=workers))


def main() -> int:
    parser = argparse.ArgumentParser(description='Run queue-backed Kafka-compatible replay pressure.')
    parser.add_argument('--employees', type=int, default=200)
    parser.add_argument('--batch-size', type=int, default=60)
    parser.add_argument('--workers', type=int, default=3)
    parser.add_argument('--out', default='')
    args = parser.parse_args()
    report = run_queue_pressure(employee_count=args.employees, batch_size=args.batch_size, workers=args.workers)
    text = json.dumps(report, indent=2)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding='utf-8')
    else:
        print(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
