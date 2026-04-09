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

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.aws_pressure_replay import _chunk_rows, _percentile, _post_assessment


def _baseline_okta_rows(employee_count: int) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for idx in range(employee_count):
        rows.append({
            'row_index': idx,
            'sheet': 'Identity_Okta',
            'timestamp': f"2026-03-22T{8 + ((idx // 25) % 9):02d}:{(idx * 2) % 60:02d}:00Z",
            'provider': 'okta',
            'user': f"user{idx:03d}@contoso.example",
            'session_id': f'okta-baseline-{idx:03d}',
            'sourceIPAddress': f'203.0.113.{(idx % 80) + 10}',
            'eventName': 'user.session.start',
            'auth_strength': 'phishing-resistant mfa',
            'description': 'Normal Okta workforce login with phishing-resistant MFA and expected region.',
            'review_state': 'low',
            'factors': ['identity:baseline_auth'],
            'mitre': [],
        })
    return rows


def _baseline_ad_rows(employee_count: int) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for idx in range(employee_count):
        rows.append({
            'row_index': idx,
            'sheet': 'Active_Directory',
            'timestamp': f"2026-03-22T{7 + ((idx // 20) % 10):02d}:{(idx * 3) % 60:02d}:00Z",
            'provider': 'active_directory',
            'host': f'corp-ws-{idx % 60 + 1}',
            'user': f'user{idx:03d}@corp.example',
            'session_id': f'ad-baseline-{idx:03d}',
            'sourceIPAddress': f'10.50.{idx % 10}.{(idx % 200) + 10}',
            'eventName': 'KerberosTGS',
            'auth_strength': 'mfa approved',
            'description': 'Normal Active Directory logon from expected workstation and approved MFA step-up.',
            'review_state': 'low',
            'factors': ['identity:baseline_auth'],
            'mitre': [],
        })
    return rows


def build_multicloud_rows(employee_count: int = 200, variant: str = 'okta_aws_azure') -> List[Dict[str, Any]]:
    rows = _baseline_okta_rows(employee_count) if variant == 'okta_aws_azure' else _baseline_ad_rows(employee_count)
    next_index = len(rows)

    def add(sheet: str, data: Dict[str, Any]) -> None:
        nonlocal next_index
        row = {'row_index': next_index, 'sheet': sheet, 'source_file': f'{variant}.json'}
        row.update(data)
        rows.append(row)
        next_index += 1

    if variant == 'okta_aws_azure':
        add('Identity_Okta', {
            'timestamp': '2026-03-22T09:14:00Z',
            'provider': 'okta',
            'user': 'guest.partner@vendor.example',
            'session_id': 'okta-guest-001',
            'sourceIPAddress': '203.0.113.50',
            'eventName': 'user.lifecycle.invite',
            'auth_strength': 'fido2 success',
            'description': 'Approved temporary guest onboarding in Okta with sponsor ticket SR-2217 and phishing-resistant MFA success.',
            'review_state': 'review',
            'factors': ['identity:guest_onboarding'],
            'mitre': ['T1078'],
        })
        add('Identity_Okta', {
            'timestamp': '2026-03-22T10:02:00Z',
            'provider': 'okta',
            'user': 'alex.mercer@contoso.example',
            'session_id': 'okta-aws-azure-1',
            'sourceIPAddress': '198.51.100.120',
            'eventName': 'user.authentication.auth_via_mfa',
            'auth_strength': 'mfa fatigue',
            'description': 'Okta risky sign-in showed impossible travel, MFA fatigue acceptance, and new ASN for alex.mercer@contoso.example.',
            'review_state': 'critical',
            'factors': ['iam:okta_risky_sign_in', 'identity:mfa_fatigue', 'identity:impossible_travel'],
            'mitre': ['T1078', 'T1110'],
        })
        add('Identity_Okta', {
            'timestamp': '2026-03-22T10:04:00Z',
            'provider': 'okta',
            'user': 'alex.mercer@contoso.example',
            'session_id': 'okta-aws-azure-1',
            'sourceIPAddress': '198.51.100.120',
            'eventName': 'app.oauth2.as.consent.grant',
            'resource': 'Microsoft Graph delegated mail.readwrite',
            'description': 'Suspicious Okta OAuth consent grant to a newly seen app immediately after impossible travel.',
            'review_state': 'high',
            'factors': ['iam:okta_oauth_consent_suspicious'],
            'mitre': ['T1528'],
        })
        add('Cloud_Azure', {
            'timestamp': '2026-03-22T10:05:00Z',
            'provider': 'azure',
            'subscription_id': 'sub-prod-001',
            'azure_tenant_id': 'tenant-contoso-1',
            'userPrincipalName': 'alex.mercer@contoso.example',
            'session_id': 'okta-aws-azure-1',
            'ipAddress': '198.51.100.120',
            'resource': '/subscriptions/sub-prod-001/resourceGroups/prod-rg/providers/Microsoft.Authorization/roleAssignments/ga',
            'activityDisplayName': 'Add member to role',
            'description': 'Azure Entra PIM activation granted Global Administrator-equivalent access within minutes of Okta risky sign-in.',
            'review_state': 'critical',
            'factors': ['cloud:privilege_change', 'azure:pim_activation'],
            'mitre': ['T1078', 'T1098'],
        })
        add('Cloud_Azure', {
            'timestamp': '2026-03-22T10:08:00Z',
            'provider': 'azure',
            'subscription_id': 'sub-prod-001',
            'azure_tenant_id': 'tenant-contoso-1',
            'userPrincipalName': 'alex.mercer@contoso.example',
            'session_id': 'okta-aws-azure-1',
            'ipAddress': '198.51.100.120',
            'resource': '/subscriptions/sub-prod-001/resourceGroups/prod-rg/providers/Microsoft.Storage/storageAccounts/payrollexports',
            'activityDisplayName': 'Get Blob',
            'description': 'Azure storage account access to payroll exports followed the same suspicious federated identity session.',
            'review_state': 'critical',
            'factors': ['data:access_after_elevation', 'exfil:prestage'],
            'mitre': ['T1530'],
        })
        add('Cloud_AWS', {
            'timestamp': '2026-03-22T10:10:00Z',
            'provider': 'aws',
            'accountId': '111111111111',
            'awsRegion': 'ap-southeast-2',
            'user': 'alex.mercer@contoso.example',
            'role': 'ProdBreakGlassRole',
            'session_id': 'okta-aws-azure-1',
            'sourceIPAddress': '198.51.100.120',
            'eventName': 'AssumeRole',
            'resource': 'arn:aws:iam::111111111111:role/ProdBreakGlassRole',
            'description': 'Same federated identity session assumed AWS break-glass role after Okta and Azure elevation events.',
            'review_state': 'critical',
            'factors': ['iam:aws_assumerole_anomaly', 'cloud:privilege_change'],
            'mitre': ['T1078', 'T1098'],
        })
        add('Cloud_AWS', {
            'timestamp': '2026-03-22T10:13:00Z',
            'provider': 'aws',
            'accountId': '111111111111',
            'awsRegion': 'ap-southeast-2',
            'user': 'alex.mercer@contoso.example',
            'role': 'ProdBreakGlassRole',
            'session_id': 'okta-aws-azure-1',
            'host': 'prod-payroll-api-1',
            'resource': 's3://payroll-exports-prod/month-end',
            'eventName': 'GetObject',
            'description': 'AWS payroll export access occurred in the same cross-cloud identity chain after privileged federation.',
            'review_state': 'critical',
            'factors': ['data:access_after_elevation', 'exfil:prestage'],
            'mitre': ['T1530', 'T1041'],
        })
        add('Cloud_Azure', {
            'timestamp': '2026-03-22T10:14:00Z',
            'provider': 'azure',
            'subscription_id': 'sub-prod-001',
            'userPrincipalName': 'alex.mercer@contoso.example',
            'session_id': 'okta-aws-azure-1',
            'host': 'az-vm-jump-01',
            'ipAddress': '198.51.100.120',
            'activityDisplayName': 'NSG Flow',
            'description': 'Azure NSG flow observed the same suspicious external IP pivot touching administrative ingress after federated privilege escalation.',
            'review_state': 'high',
            'factors': ['network:egress_spike', 'network:cross_cloud_pivot'],
            'mitre': ['T1071'],
        })
    elif variant == 'ad_aws_vmware_bec':
        add('Active_Directory', {
            'timestamp': '2026-03-22T09:30:00Z',
            'provider': 'active_directory',
            'host': 'dc-01.corp.example',
            'user': 'guest.temp@corp.example',
            'session_id': 'guest-benign-01',
            'sourceIPAddress': '10.50.20.8',
            'eventName': 'UserProvisioned',
            'auth_strength': 'mfa approved',
            'description': 'Approved temporary guest onboarding in Active Directory with sponsor and MFA approval.',
            'review_state': 'review',
            'factors': ['identity:guest_onboarding'],
            'mitre': ['T1078'],
        })
        add('Active_Directory', {
            'timestamp': '2026-03-22T11:02:00Z',
            'provider': 'active_directory',
            'host': 'dc-02.corp.example',
            'user': 'finance.controller@corp.example',
            'session_id': 'hybrid-bec-44',
            'sourceIPAddress': '203.0.113.220',
            'eventName': 'KerberosTGT',
            'auth_strength': 'legacy auth',
            'description': 'Active Directory impossible-travel-like logon from unusual ASN preceded privileged access to hybrid infrastructure.',
            'review_state': 'critical',
            'factors': ['identity:impossible_travel', 'identity:legacy_auth'],
            'mitre': ['T1078', 'T1110'],
        })
        add('VMware', {
            'timestamp': '2026-03-22T11:05:00Z',
            'provider': 'vmware',
            'host': 'vcenter-01',
            'user': 'finance.controller@corp.example',
            'session_id': 'hybrid-bec-44',
            'resource': 'vm/payroll-app-01',
            'eventName': 'ReconfigVM_Task',
            'description': 'vCenter task modified payroll-app-01 network adapter and attached snapshot after suspicious AD login.',
            'review_state': 'critical',
            'factors': ['vmware:admin_task', 'cloud:config_drift'],
            'mitre': ['T1484', 'T1578'],
        })
        add('Cloud_AWS', {
            'timestamp': '2026-03-22T11:08:00Z',
            'provider': 'aws',
            'accountId': '444444444444',
            'awsRegion': 'ap-southeast-2',
            'user': 'finance.controller@corp.example',
            'role': 'BillingAdminRole',
            'session_id': 'hybrid-bec-44',
            'sourceIPAddress': '203.0.113.220',
            'eventName': 'AssumeRole',
            'resource': 'arn:aws:iam::444444444444:role/BillingAdminRole',
            'description': 'Hybrid identity session assumed AWS billing administration role after AD and vCenter activity.',
            'review_state': 'critical',
            'factors': ['iam:aws_assumerole_anomaly', 'cloud:privilege_change'],
            'mitre': ['T1078', 'T1098'],
        })
        add('Email_Exchange', {
            'timestamp': '2026-03-22T11:10:00Z',
            'provider': 'email',
            'user': 'finance.controller@corp.example',
            'session_id': 'hybrid-bec-44',
            'host': 'exchange-online',
            'resource': 'mailbox:finance.controller@corp.example',
            'eventName': 'Set-MailboxRule',
            'description': 'Mailbox rule and hidden forwarding were created during a business email compromise pattern targeting vendor payment changes.',
            'review_state': 'critical',
            'factors': ['email:bec_impersonation', 'email:mailbox_rule_burst'],
            'mitre': ['T1114', 'T1586'],
        })
        add('Email_Exchange', {
            'timestamp': '2026-03-22T11:12:00Z',
            'provider': 'email',
            'user': 'finance.controller@corp.example',
            'session_id': 'hybrid-bec-44',
            'resource': 'vendor-wire-change',
            'eventName': 'MessageTrace',
            'description': 'Message trace showed a BEC payment-change thread sent to treasury leadership from the compromised finance mailbox.',
            'review_state': 'high',
            'factors': ['email:bec_language', 'email:payment_change'],
            'mitre': ['T1598'],
        })
    else:
        raise ValueError(f'unsupported variant: {variant}')

    return rows


async def run_multicloud_gate_async(employee_count: int = 200, concurrent_batches: int = 4) -> Dict[str, Any]:
    os.environ.setdefault('API_KEYS_JSON', '[{"key":"devkey123","scopes":["*"]}]')
    os.environ.setdefault('DEFAULT_FRONTEND', 'investigate')
    os.environ.setdefault('LLM_MOCK', '1')
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from src.api.app import create_app

    app = create_app()
    report: Dict[str, Any] = {'employee_count': employee_count, 'variants': {}, 'backpressure': {}}
    for variant in ('okta_aws_azure', 'ad_aws_vmware_bec'):
        rows = build_multicloud_rows(employee_count=employee_count, variant=variant)
        full = await _post_assessment(app, f'multicloud-{variant}', rows, variant, 'full', provider_profile='multi_cloud', intake_mode='live')
        batches = _chunk_rows(rows, concurrent_batches)
        t0 = time.perf_counter()
        concurrent = await asyncio.gather(*[
            _post_assessment(app, f'multicloud-{variant}-batch-{idx}', batch, variant, f'batch-{idx}', provider_profile='multi_cloud', intake_mode='live')
            for idx, batch in enumerate(batches, start=1)
        ])
        total_elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        latencies = [item['latency_ms'] for item in concurrent]
        total_rows = sum(item['row_count'] for item in concurrent)
        throughput = round(total_rows / max(total_elapsed_ms / 1000.0, 0.001), 2)
        queue_pressure = 'high' if _percentile(latencies, 0.95) > 7000 else 'medium' if _percentile(latencies, 0.95) > 3000 else 'low'
        recommendations = [
            'Keep cross-cloud identity and email evidence in the same case so actor movement survives provider boundaries.',
            'Microbatch identity-heavy replay into a Kafka-compatible queue before widening to live multi-tenant polling.',
        ]
        if variant == 'okta_aws_azure':
            recommendations.append('Preserve Okta, Azure Entra, and AWS CloudTrail timestamps in one bitemporal chain to prove impossible travel and privilege progression.')
        else:
            recommendations.append('Preserve AD, virtualization, AWS, and mailbox traces together so BEC and hybrid privilege abuse are not investigated in separate silos.')
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
            },
        }
    report['backpressure'] = {
        'summary': 'Multicloud pressure is still replay-backed, but it now exercises cross-provider identity chains, hybrid infrastructure pivots, and BEC-linked evidence.',
        'recommended_scaling_path': [
            'Run Kafka-compatible queue buffering in front of deep-analyze so identity, email, and cloud bursts do not contend directly on request workers.',
            'Partition by tenant and evidence mode before adding multicloud live polling.',
            'Consider Flink-class stateful stream processing only after Kafka-backed replay pressure is stable.',
        ],
    }
    return report


def run_multicloud_gate(employee_count: int = 200, concurrent_batches: int = 4) -> Dict[str, Any]:
    return asyncio.run(run_multicloud_gate_async(employee_count=employee_count, concurrent_batches=concurrent_batches))


def main() -> int:
    parser = argparse.ArgumentParser(description='Run the multicloud replay pressure gate.')
    parser.add_argument('--employees', type=int, default=200)
    parser.add_argument('--batches', type=int, default=4)
    parser.add_argument('--out', default='')
    args = parser.parse_args()
    report = run_multicloud_gate(employee_count=args.employees, concurrent_batches=args.batches)
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
