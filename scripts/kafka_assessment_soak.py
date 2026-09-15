from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.aws_pressure_replay import build_aws_pressure_rows
from src.queue.kafka_assessment_queue import build_assessment_job
from src.workers.kafka_assessment_worker import KafkaAssessmentWorker


def _scenario_rows(employee_count: int, scenario: str) -> List[Dict[str, Any]]:
    if scenario == 'enterprise':
        return build_aws_pressure_rows(employee_count=employee_count, variant='enterprise')
    if scenario == 'zero_firewall':
        return build_aws_pressure_rows(employee_count=employee_count, variant='zero_firewall')
    if scenario == 'ransomware':
        rows = build_aws_pressure_rows(employee_count=employee_count, variant='enterprise')
        base_idx = len(rows)
        rows.extend([
            {
                'row_index': base_idx,
                'sheet': 'Endpoint',
                'timestamp': '2026-03-22T11:01:00Z',
                'accountId': '111111111111',
                'subnet': 'private-data',
                'host': 'prod-data-1',
                'user': 'svc-backup@example.com',
                'role': 'BackupServiceRole',
                'session_id': 'ransom-01',
                'description': 'Ransomware encryptor process spawned from compromised admin session, followed by vssadmin delete shadows.',
                'review_state': 'critical',
                'factors': ['endpoint:ransomware_encryptor', 'endpoint:vssadmin_delete_shadows', 'lateral_movement:smb_spread'],
                'mitre': ['T1486', 'T1490'],
            },
            {
                'row_index': base_idx + 1,
                'sheet': 'Storage',
                'timestamp': '2026-03-22T11:04:00Z',
                'accountId': '111111111111',
                'subnet': 'private-data',
                'host': 'prod-data-1',
                'resource': 'efs-prod-data',
                'description': 'High-volume file rename and extension churn indicates active ransomware encryption against business-critical data.',
                'review_state': 'critical',
                'factors': ['storage:file_churn_spike', 'endpoint:ransomware_encryptor'],
                'mitre': ['T1486'],
            },
        ])
        return rows
    if scenario == 'ddos_no_cdn':
        rows = build_aws_pressure_rows(employee_count=employee_count, variant='zero_firewall')
        base_idx = len(rows)
        rows.extend([
            {
                'row_index': base_idx,
                'sheet': 'ALB',
                'timestamp': '2026-03-22T12:00:00Z',
                'accountId': '111111111111',
                'subnet': 'public-ingress',
                'host': 'alb-prod-web',
                'resource': 'alb-prod-web',
                'description': 'No-CDN environment experienced multi-pronged DDoS traffic burst against ALB with origin saturation and autoscale lag.',
                'review_state': 'critical',
                'factors': ['network:ddos_burst', 'control:no_cdn', 'availability:origin_saturation'],
                'mitre': ['T1498'],
            },
            {
                'row_index': base_idx + 1,
                'sheet': 'Network_AWS',
                'timestamp': '2026-03-22T12:01:00Z',
                'accountId': '111111111111',
                'subnet': 'public-ingress',
                'host': 'alb-prod-web',
                'sourceIPAddress': '203.0.113.77',
                'destinationIp': '10.10.10.15',
                'description': 'Distributed request flood from rotating source ASN set with no CDN shielding and uneven autoscale response.',
                'review_state': 'critical',
                'factors': ['network:ddos_burst', 'network:asn_spike', 'autoscale:lag'],
                'mitre': ['T1498'],
            },
        ])
        return rows
    if scenario == 'marketing_burst':
        rows = build_aws_pressure_rows(employee_count=employee_count, variant='enterprise')
        base_idx = len(rows)
        rows.extend([
            {
                'row_index': base_idx,
                'sheet': 'Marketing',
                'timestamp': '2026-03-22T13:10:00Z',
                'accountId': '111111111111',
                'subnet': 'public-ingress',
                'host': 'alb-prod-web',
                'user': 'marketing.ops@example.com',
                'description': 'Approved marketing campaign caused a sudden but expected CDN and application traffic surge after newsletter launch.',
                'review_state': 'review',
                'factors': ['business:marketing_campaign', 'traffic:burst_expected'],
                'mitre': [],
            },
            {
                'row_index': base_idx + 1,
                'sheet': 'CDN_Edge',
                'timestamp': '2026-03-22T13:11:00Z',
                'accountId': '111111111111',
                'subnet': 'public-ingress',
                'host': 'cdn-edge',
                'description': 'CDN cache hit ratio stayed healthy during approved marketing campaign burst; no malicious indicators yet.',
                'review_state': 'review',
                'factors': ['business:marketing_campaign', 'traffic:healthy_cache'],
                'mitre': [],
            },
        ])
        return rows
    raise ValueError(f'unsupported scenario: {scenario}')


def _percentile(values: List[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(math.ceil(len(ordered) * q)) - 1))
    return float(ordered[idx])


async def run_assessment_soak_async(
    employee_count: int = 200,
    iterations: int = 3,
    worker_parallelism: int = 3,
) -> Dict[str, Any]:
    os.environ.setdefault('API_KEYS_JSON', '[{"key":"devkey123","scopes":["*"]}]')
    os.environ.setdefault('DEFAULT_FRONTEND', 'console')
    os.environ.setdefault('LLM_MOCK', '1')
    os.environ.setdefault('KAFKA_ASSESSMENT_WORKER_CONCURRENCY', str(worker_parallelism))

    worker = KafkaAssessmentWorker()
    scenarios = ['enterprise', 'zero_firewall', 'ransomware', 'ddos_no_cdn', 'marketing_burst']
    jobs: List[dict] = []
    expected: Dict[str, dict] = {}
    for idx in range(iterations):
        for scenario in scenarios:
            tenant = f'soak-tenant-{idx % 3}'
            rows = _scenario_rows(employee_count, scenario)
            payload = {
                'org': tenant,
                'rows': rows,
                'options': {
                    'auto_llm': True,
                    'intake_mode': 'live',
                    'provider_profile': 'aws',
                },
            }
            job = build_assessment_job(payload, tenant_id=tenant, source=f'soak:{scenario}')
            jobs.append(job)
            expected[job['job_id']] = {'scenario': scenario, 'tenant': tenant, 'row_count': len(rows)}
            if scenario == 'marketing_burst':
                jobs.append(job)

    results: List[dict] = []
    queue_depths: List[int] = []
    in_flight = 0
    pending = list(jobs)
    offset = 0

    async def _run_one(job: dict) -> None:
        nonlocal in_flight, offset
        in_flight += 1
        queue_depths.append(len(pending) + in_flight)
        started = time.perf_counter()
        ok, result = await worker.process_job(job, 'janusec.assessment.requests', job.get('partition_hint', 0), offset)
        latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
        offset += 1
        in_flight -= 1
        scenario = expected[job['job_id']]['scenario']
        payload = result if isinstance(result, dict) else {}
        clusters = payload.get('correlation_clusters') or []
        personas = payload.get('persona_reports') or {}
        crisis = ((personas.get('ciso') or {}).get('crisis_management') or payload.get('crisis_management') or {})
        results.append({
            'job_id': job['job_id'],
            'tenant_id': job['tenant_id'],
            'scenario': scenario,
            'ok': ok,
            'latency_ms': latency_ms,
            'assessment_id': payload.get('assessment_id'),
            'cluster_count': len(clusters),
            'human_validation_required': any(bool(row.get('human_validation_required')) for row in (payload.get('evidence_rows') or [])[:20]),
            'top_cluster_severity': (clusters[0] or {}).get('severity') if clusters else None,
            'crisis_summary': crisis.get('summary') or '',
            'security_posture': (clusters[0] or {}).get('security_posture', {}) if clusters else {},
            'provider_list': (clusters[0] or {}).get('providers', []) if clusters else [],
        })

    sem = asyncio.Semaphore(worker_parallelism)

    async def _guarded(job: dict) -> None:
        async with sem:
            await _run_one(job)

    await asyncio.gather(*[_guarded(job) for job in jobs])
    stats = worker.get_stats()
    report = {
        'employees': employee_count,
        'iterations': iterations,
        'total_jobs': len(jobs),
        'processed_jobs': len(results),
        'deduped_jobs': stats.get('deduped', 0),
        'tenant_isolation_ok': all(
            item.get('tenant_id') == expected.get(item.get('job_id'), {}).get('tenant')
            for item in results
        ),
        'latency_p95_ms': round(_percentile([item['latency_ms'] for item in results], 0.95), 2),
        'queue_depth_p95': round(_percentile([float(v) for v in queue_depths], 0.95), 2),
        'scenario_summaries': results,
        'worker_stats': stats,
        'recommendations': [
            'Use tenant-keyed Kafka partitions plus worker fan-out to keep deep-analyze burst latency bounded.',
            'Keep ransomware, DDoS/no-CDN, and benign-marketing overload scenarios in the release-candidate wringer.',
            'Run 12-24h soak first, then 3-day and 7-day accelerated soak only after queue lag and dedupe stay stable.',
        ],
    }
    return report


def run_assessment_soak(employee_count: int = 200, iterations: int = 3, worker_parallelism: int = 3) -> Dict[str, Any]:
    return asyncio.run(run_assessment_soak_async(employee_count=employee_count, iterations=iterations, worker_parallelism=worker_parallelism))


def main() -> int:
    parser = argparse.ArgumentParser(description='Run accelerated Kafka assessment soak scenarios.')
    parser.add_argument('--employees', type=int, default=200)
    parser.add_argument('--iterations', type=int, default=3)
    parser.add_argument('--workers', type=int, default=3)
    parser.add_argument('--out', default='')
    args = parser.parse_args()
    report = run_assessment_soak(employee_count=args.employees, iterations=args.iterations, worker_parallelism=args.workers)
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
