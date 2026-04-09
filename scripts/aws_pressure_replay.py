from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

import httpx


def _baseline_user_rows(employee_count: int) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    accounts = ['111111111111', '222222222222', '333333333333']
    subnets = ['private-app', 'private-data', 'dev-subnet']
    regions = ['ap-southeast-2', 'ap-southeast-1']
    for idx in range(employee_count):
        account_id = accounts[idx % len(accounts)]
        subnet = subnets[idx % len(subnets)]
        rows.append({
            'row_index': idx,
            'sheet': 'Cloud_AWS',
            'timestamp': f"2026-03-21T{8 + ((idx // 30) % 10):02d}:{(idx * 3) % 60:02d}:00Z",
            'accountId': account_id,
            'awsRegion': regions[idx % len(regions)],
            'subnet': subnet,
            'host': f"workstation-{idx % 40 + 1}",
            'user': f"user{idx:03d}@example.com",
            'role': 'EmployeeRole',
            'session_id': f"sess-user-{idx:03d}",
            'eventName': 'ConsoleLogin',
            'auth_strength': 'phishing-resistant mfa',
            'description': 'Normal workforce sign-in with phishing-resistant MFA and expected regional access pattern.',
            'review_state': 'low',
            'factors': ['identity:baseline_auth'],
            'mitre': [],
        })
    return rows


def build_aws_pressure_rows(employee_count: int = 200, variant: str = 'enterprise') -> List[Dict[str, Any]]:
    rows = _baseline_user_rows(employee_count)
    next_index = len(rows)

    def add(sheet: str, data: Dict[str, Any]) -> None:
        nonlocal next_index
        row = {
            'row_index': next_index,
            'sheet': sheet,
            'source_file': f'{variant}.json',
        }
        row.update(data)
        rows.append(row)
        next_index += 1

    # Benign MFA / guest onboarding path
    add('Identity_AWS', {
        'timestamp': '2026-03-21T09:15:00Z',
        'accountId': '222222222222',
        'awsRegion': 'ap-southeast-2',
        'subnet': 'dev-subnet',
        'user': 'guest.contractor@example.net',
        'role': 'ReadOnlyProjectGuest',
        'eventName': 'InviteExternalUser',
        'session_id': 'guest-mfa-001',
        'description': 'Approved temporary guest onboarding with sponsor ticket SR-9912 and MFA registered successfully.',
        'auth_strength': 'mfa registered',
        'review_state': 'review',
        'factors': ['identity:guest_onboarding'],
        'mitre': ['T1078'],
    })

    # Compromised MFA chain
    add('Identity_AWS', {
        'timestamp': '2026-03-21T10:02:00Z',
        'accountId': '111111111111',
        'awsRegion': 'ap-southeast-2',
        'subnet': 'public-ingress',
        'user': 'finance.admin@example.com',
        'role': 'BillingReadRole',
        'session_id': 'mfa-fatigue-01',
        'sourceIPAddress': '198.51.100.44',
        'eventName': 'ConsoleLogin',
        'description': 'Impossible travel followed by MFA fatigue push accepted from suspicious ASN and geovelocity impossible travel indicators.',
        'auth_strength': 'mfa fatigue',
        'review_state': 'critical',
        'factors': ['identity:mfa_fatigue', 'identity:impossible_travel'],
        'mitre': ['T1078', 'T1110'],
    })
    add('Cloud_AWS', {
        'timestamp': '2026-03-21T10:05:00Z',
        'accountId': '111111111111',
        'awsRegion': 'ap-southeast-2',
        'subnet': 'private-app',
        'host': 'prod-app-1',
        'user': 'finance.admin@example.com',
        'role': 'ProdBreakGlassRole',
        'session_id': 'mfa-fatigue-01',
        'resource': 'arn:aws:iam::111111111111:role/ProdBreakGlassRole',
        'eventName': 'AssumeRole',
        'description': 'Short-lived privileged role activation after compromised MFA session.',
        'review_state': 'critical',
        'factors': ['iam:aws_assumerole_anomaly', 'cloud:privilege_change'],
        'mitre': ['T1078', 'T1098'],
    })
    add('Cloud_AWS', {
        'timestamp': '2026-03-21T10:08:00Z',
        'accountId': '111111111111',
        'awsRegion': 'ap-southeast-2',
        'subnet': 'private-data',
        'host': 'prod-app-1',
        'user': 'finance.admin@example.com',
        'role': 'ProdBreakGlassRole',
        'session_id': 'mfa-fatigue-01',
        'resource': 's3://crown-jewel-prod/customer-exports',
        'eventName': 'GetObject',
        'description': 'Privileged session accessed crown-jewel export data after compromised MFA path.',
        'review_state': 'critical',
        'factors': ['data:access_after_elevation', 'exfil:prestage'],
        'mitre': ['T1530', 'T1078'],
    })

    # Dev supply chain + prod resilience chain
    add('Dev_Endpoint', {
        'timestamp': '2026-03-21T10:12:00Z',
        'accountId': '222222222222',
        'awsRegion': 'ap-southeast-2',
        'subnet': 'dev-subnet',
        'host': 'dev-build-1',
        'user': 'contractor.dev@example.com',
        'role': 'CICDPublisherRole',
        'session_id': 'supply-chain-77',
        'resource': 'package:lodasdh@1.4.2',
        'description': 'Developer subnet installed a typosquat npm package with lifecycle script abuse and outbound beaconing.',
        'review_state': 'high',
        'factors': ['supply_chain:typosquat', 'endpoint:lolbin_cmd_tfidf_rare', 'network:c2_beacon'],
        'mitre': ['T1195', 'T1071'],
    })
    add('Cloud_AWS', {
        'timestamp': '2026-03-21T10:15:00Z',
        'accountId': '222222222222',
        'awsRegion': 'ap-southeast-2',
        'subnet': 'dev-subnet',
        'host': 'dev-build-1',
        'user': 'contractor.dev@example.com',
        'role': 'CICDPublisherRole',
        'session_id': 'supply-chain-77',
        'resource': 'arn:aws:iam::111111111111:role/ProdDeployRole',
        'eventName': 'AssumeRole',
        'description': 'Supply-chain-compromised CI/CD identity assumed prod deployment role after package poisoning.',
        'review_state': 'critical',
        'factors': ['iam:aws_assumerole_anomaly', 'cloud:privilege_change'],
        'mitre': ['T1078', 'T1098'],
    })
    add('Cloud_AWS', {
        'timestamp': '2026-03-21T10:17:00Z',
        'accountId': '111111111111',
        'awsRegion': 'ap-southeast-2',
        'subnet': 'private-app',
        'host': 'prod-app-1',
        'user': 'contractor.dev@example.com',
        'role': 'ProdDeployRole',
        'session_id': 'supply-chain-77',
        'resource': 'alb-prod-web',
        'eventName': 'RunCommand',
        'description': 'Prod application node shows curl bootstrap execution and autoscale replacement should be simulated after ALB drain.',
        'review_state': 'critical',
        'factors': ['cloud:remote_command', 'endpoint:curl_http_bootstrap'],
        'mitre': ['T1059', 'T1105'],
    })
    add('Cloud_AWS', {
        'timestamp': '2026-03-21T10:18:00Z',
        'accountId': '111111111111',
        'awsRegion': 'ap-southeast-2',
        'subnet': 'private-app',
        'host': 'prod-app-1',
        'user': 'aws-guardduty',
        'resource': 'prod-app-1',
        'eventName': 'GuardDutyFinding',
        'description': 'GuardDuty detected C2 beaconing from prod-app-1 shortly after suspicious deployment.',
        'review_state': 'critical',
        'factors': ['network:c2_beacon', 'guardduty:c2'],
        'mitre': ['T1071'],
    })
    add('Cloud_AWS', {
        'timestamp': '2026-03-21T10:19:00Z',
        'accountId': '111111111111',
        'awsRegion': 'ap-southeast-2',
        'subnet': 'private-app',
        'host': 'prod-app-1',
        'user': 'securityhub',
        'resource': 'prod-app-1',
        'eventName': 'SecurityHubFinding',
        'description': 'SecurityHub correlated prod-app-1 compromise with suspicious data access path.',
        'review_state': 'high',
        'factors': ['securityhub:compromise', 'exfil:prestage'],
        'mitre': ['T1530'],
    })
    add('Network_AWS', {
        'timestamp': '2026-03-21T10:20:00Z',
        'accountId': '111111111111',
        'awsRegion': 'ap-southeast-2',
        'subnet': 'private-app',
        'host': 'prod-app-1',
        'user': 'flow-log',
        'session_id': 'supply-chain-77',
        'sourceIPAddress': '10.10.10.41',
        'destinationIp': '198.51.100.88',
        'resource': 'prod-app-1',
        'eventName': 'VPCFlow',
        'description': 'VPC Flow observed repeated egress from prod-app-1 to suspicious external infrastructure after role assumption.',
        'review_state': 'critical',
        'factors': ['network:c2_beacon', 'network:egress_spike'],
        'mitre': ['T1071', 'T1041'],
    })

    # Policy drift
    add('Cloud_AWS', {
        'timestamp': '2026-03-21T10:13:00Z',
        'accountId': '222222222222',
        'awsRegion': 'ap-southeast-2',
        'subnet': 'dev-subnet',
        'host': 'dev-build-1',
        'user': 'contractor.dev@example.com',
        'role': 'CICDPublisherRole',
        'session_id': 'supply-chain-77',
        'eventName': 'PutRolePolicy',
        'resource': 'arn:aws:iam::222222222222:role/CICDPublisherRole',
        'description': 'Policy as code drift: inline IAM policy expanded to allow sts:AssumeRole into prod without CAB approval.',
        'review_state': 'high',
        'factors': ['iam:aws_iam_policy_drift', 'cloud:config_drift'],
        'mitre': ['T1098', 'T1484'],
    })

    # Enterprise vs zero-firewall / edge maturity
    if variant == 'enterprise':
        add('CDN_Edge', {
            'timestamp': '2026-03-21T10:16:00Z',
            'accountId': '111111111111',
            'awsRegion': 'ap-southeast-2',
            'subnet': 'public-ingress',
            'host': 'alb-prod-web',
            'sourceIPAddress': '198.51.100.88',
            'resource': 'd111111abcdef8.cloudfront.net',
            'description': 'CloudFront CDN edge observed suspicious origin pull toward prod application after compromised deployment.',
            'review_state': 'high',
            'factors': ['network:cdn_edge_anomaly'],
            'mitre': ['T1190'],
        })
        add('CheckPoint', {
            'timestamp': '2026-03-21T10:20:20Z',
            'accountId': '111111111111',
            'subnet': 'public-ingress',
            'host': 'cp-gateway-a',
            'sourceIPAddress': '10.10.10.41',
            'destinationIp': '198.51.100.88',
            'description': 'Check Point next-gen firewall pair blocked and logged repeated egress from prod-app-1 to suspicious CDN-adjacent infrastructure.',
            'review_state': 'high',
            'factors': ['network:firewall_evidence', 'network:egress_blocked'],
            'mitre': ['T1041'],
        })
        add('PaloAlto', {
            'timestamp': '2026-03-21T10:20:30Z',
            'accountId': '111111111111',
            'subnet': 'public-ingress',
            'host': 'panw-gateway-b',
            'sourceIPAddress': '10.10.10.41',
            'destinationIp': '198.51.100.88',
            'description': 'Palo Alto pair confirmed threat log hits for the same suspicious egress path from prod-app-1.',
            'review_state': 'high',
            'factors': ['network:firewall_evidence', 'network:threat_log_hit'],
            'mitre': ['T1041'],
        })
    elif variant == 'zero_firewall':
        add('CDN_Edge', {
            'timestamp': '2026-03-21T10:16:00Z',
            'accountId': '111111111111',
            'awsRegion': 'ap-southeast-2',
            'subnet': 'public-ingress',
            'host': 'alb-prod-web',
            'sourceIPAddress': '198.51.100.88',
            'resource': 'd111111abcdef8.cloudfront.net',
            'description': 'CloudFront CDN edge saw suspicious origin pull, but zero firewall posture means no perimeter firewall telemetry exists between edge and origin.',
            'review_state': 'high',
            'factors': ['network:cdn_edge_anomaly', 'control:no_perimeter_firewall'],
            'mitre': ['T1190'],
        })
        add('Cloud_AWS', {
            'timestamp': '2026-03-21T10:20:40Z',
            'accountId': '111111111111',
            'awsRegion': 'ap-southeast-2',
            'subnet': 'public-ingress',
            'host': 'alb-prod-web',
            'sourceIPAddress': '198.51.100.88',
            'resource': 'alb-prod-web',
            'description': 'Zero firewall posture: no perimeter firewall present. Incident responders must rely on ALB, VPC Flow, CDN, and CloudTrail evidence only.',
            'review_state': 'critical',
            'factors': ['control:no_perimeter_firewall'],
            'mitre': ['T1190'],
        })
    else:
        raise ValueError(f'unsupported variant: {variant}')

    return rows


def _chunk_rows(rows: Sequence[Dict[str, Any]], batch_count: int) -> List[List[Dict[str, Any]]]:
    size = max(1, math.ceil(len(rows) / max(1, batch_count)))
    return [list(rows[idx:idx + size]) for idx in range(0, len(rows), size)]


async def _post_assessment(
    app: Any,
    tenant: str,
    rows: Sequence[Dict[str, Any]],
    variant: str,
    label: str,
    provider_profile: str = 'aws',
    intake_mode: str = 'live',
) -> Dict[str, Any]:
    transport = httpx.ASGITransport(app=app)
    start = time.perf_counter()
    async with httpx.AsyncClient(transport=transport, base_url='http://testserver') as client:
        resp = await client.post(
            '/api/v1/csv/deep_analyze',
            headers={'x-api-key': 'devkey123', 'X-Tenant-ID': tenant},
            json={
                'org': tenant,
                'rows': list(rows),
                'options': {'auto_llm': True, 'intake_mode': intake_mode, 'provider_profile': provider_profile},
            },
        )
    latency_ms = round((time.perf_counter() - start) * 1000.0, 2)
    payload = resp.json()
    evidence_rows = payload.get('evidence_rows') or []
    clusters = payload.get('correlation_clusters') or []
    personas = payload.get('persona_reports') or {}
    return {
        'label': label,
        'variant': variant,
        'status_code': resp.status_code,
        'latency_ms': latency_ms,
        'row_count': len(rows),
        'correlated_rows': len([row for row in evidence_rows if row.get('correlation_type') == 'correlated']),
        'cluster_count': len(clusters),
        'max_cluster_size': max([len(cluster.get('row_refs') or []) for cluster in clusters] or [0]),
        'payload': payload,
        'persona_reports': personas,
    }


def _percentile(values: Sequence[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    pos = min(len(ordered) - 1, max(0, int(math.ceil(q * len(ordered))) - 1))
    return float(ordered[pos])


async def run_pressure_gate_async(employee_count: int = 200, concurrent_batches: int = 4) -> Dict[str, Any]:
    os.environ.setdefault('API_KEYS_JSON', '[{"key":"devkey123","scopes":["*"]}]')
    os.environ.setdefault('DEFAULT_FRONTEND', 'investigate')
    os.environ.setdefault('LLM_MOCK', '1')
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    from src.api.app import create_app

    app = create_app()
    report: Dict[str, Any] = {'employee_count': employee_count, 'variants': {}, 'backpressure': {}}
    for variant in ('enterprise', 'zero_firewall'):
        rows = build_aws_pressure_rows(employee_count=employee_count, variant=variant)
        full = await _post_assessment(app, f'pressure-{variant}', rows, variant, 'full')
        batches = _chunk_rows(rows, concurrent_batches)
        t0 = time.perf_counter()
        concurrent = await asyncio.gather(*[
            _post_assessment(app, f'pressure-{variant}-batch-{idx}', batch, variant, f'batch-{idx}')
            for idx, batch in enumerate(batches, start=1)
        ])
        total_elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        latencies = [item['latency_ms'] for item in concurrent]
        total_rows = sum(item['row_count'] for item in concurrent)
        throughput = round(total_rows / max(total_elapsed_ms / 1000.0, 0.001), 2)
        queue_pressure = 'high' if _percentile(latencies, 0.95) > 6000 else 'medium' if _percentile(latencies, 0.95) > 2500 else 'low'
        recommendations = []
        if queue_pressure == 'high':
            recommendations.append('Move deep-analyze requests behind a durable queue and process correlation in microbatches.')
        if throughput < 120:
            recommendations.append('Scale worker count vertically first, then introduce queue-backed fan-out for heavier tenants.')
        if variant == 'enterprise':
            recommendations.append('Retain CDN and dual-firewall telemetry in the same case so perimeter corroboration survives burst conditions.')
        else:
            recommendations.append('Without perimeter firewalls, prioritize ALB, VPC Flow, CDN, identity, and DNS telemetry for confirm/deny workflows.')
        report['variants'][variant] = {
            'full': full,
            'concurrent': {
                'batch_count': len(concurrent),
                'total_rows': total_rows,
                'total_elapsed_ms': total_elapsed_ms,
                'latency_p50_ms': round(statistics.median(latencies), 2) if latencies else 0.0,
                'latency_p95_ms': round(_percentile(latencies, 0.95), 2),
                'throughput_rows_per_second': throughput,
                'queue_pressure': queue_pressure,
                'recommendations': recommendations,
                'batches': [
                    {
                        'label': item['label'],
                        'latency_ms': item['latency_ms'],
                        'row_count': item['row_count'],
                        'correlated_rows': item['correlated_rows'],
                        'cluster_count': item['cluster_count'],
                    }
                    for item in concurrent
                ],
            },
        }
    report['backpressure'] = {
        'summary': 'A single-process local gate can validate correlation latency and queue pressure, but real production scale still needs worker fan-out plus durable ingestion.',
        'recommended_scaling_path': [
            'Vertical scaling and lower parallel UI worker counts for the closed-beta gate.',
            'Queue-backed microbatching with Kafka-compatible ingestion for sustained burst handling.',
            'Stream-processing fan-out such as Flink only after the multicloud tenant model is stable and tenant counts justify it.',
        ],
    }
    return report


def run_pressure_gate(employee_count: int = 200, concurrent_batches: int = 4) -> Dict[str, Any]:
    return asyncio.run(run_pressure_gate_async(employee_count=employee_count, concurrent_batches=concurrent_batches))


def main() -> int:
    parser = argparse.ArgumentParser(description='Run the AWS pressure replay gate.')
    parser.add_argument('--employees', type=int, default=200)
    parser.add_argument('--batches', type=int, default=4)
    parser.add_argument('--out', default='')
    args = parser.parse_args()
    report = run_pressure_gate(employee_count=args.employees, concurrent_batches=args.batches)
    text = json.dumps(report, indent=2)
    if args.out:
        Path(args.out).write_text(text, encoding='utf-8')
    else:
        print(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
