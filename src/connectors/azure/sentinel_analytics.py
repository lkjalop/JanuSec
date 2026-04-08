"""
Sentinel Analytics Rule Deployment (P1)
Programmatically creates and manages Azure Sentinel Analytics Rules (Scheduled
query rules) and Automation Playbook links via the Sentinel REST API.

Customers use this during onboarding to wire their Sentinel workspace so that
high-severity Analytics Rule alerts are automatically pushed to JanuSec via
Event Hub.

Usage:
    python -m src.connectors.azure.sentinel_analytics --deploy \\
        --workspace-id <GUID> \\
        --resource-group <rg> \\
        --subscription-id <sub>

Env vars:
    SENTINEL_WORKSPACE_ID           — required
    SENTINEL_RESOURCE_GROUP         — required
    SENTINEL_SUBSCRIPTION_ID        — required
    SENTINEL_TENANT_ID              — Azure AD tenant
    SENTINEL_CLIENT_ID              — SPN client ID
    SENTINEL_CLIENT_SECRET          — SPN secret
    SENTINEL_API_VERSION            — default 2024-01-01-preview
    SENTINEL_RULE_PREFIX            — rule name prefix (default 'janusec-')
    SENTINEL_EVENT_HUB_NAMESPACE    — namespace for Automation trigger
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import time
import urllib.request as _req
from typing import Any

logger = logging.getLogger(__name__)

_API_VERSION = os.getenv('SENTINEL_API_VERSION', '2024-01-01-preview')
_RULE_PREFIX = os.getenv('SENTINEL_RULE_PREFIX', 'janusec-')
_BASE_URL = 'https://management.azure.com'

_WORKSPACE_ID = os.getenv('SENTINEL_WORKSPACE_ID', '')
_RESOURCE_GROUP = os.getenv('SENTINEL_RESOURCE_GROUP', '')
_SUBSCRIPTION_ID = os.getenv('SENTINEL_SUBSCRIPTION_ID', '')
_TENANT_ID = os.getenv('SENTINEL_TENANT_ID', '')
_CLIENT_ID = os.getenv('SENTINEL_CLIENT_ID', '')
_CLIENT_SECRET = os.getenv('SENTINEL_CLIENT_SECRET', '')


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------

def _get_token() -> str:
    try:
        import msal  # type: ignore
        app = msal.ConfidentialClientApplication(
            _CLIENT_ID,
            authority=f'https://login.microsoftonline.com/{_TENANT_ID}',
            client_credential=_CLIENT_SECRET,
        )
        result = app.acquire_token_for_client(
            scopes=['https://management.azure.com/.default']
        )
        return result.get('access_token', '')
    except ImportError:
        pass
    # MSI fallback
    try:
        url = (
            'http://169.254.169.254/metadata/identity/oauth2/token'
            '?api-version=2018-02-01&resource=https://management.azure.com/'
        )
        request = _req.Request(url, headers={'Metadata': 'true'})
        with _req.urlopen(request, timeout=5) as resp:  # noqa: S310
            return json.loads(resp.read()).get('access_token', '')
    except Exception as exc:
        logger.warning('sentinel_analytics: token fetch failed: %s', exc)
        return ''


# ---------------------------------------------------------------------------
# KQL Analytics Rule definitions — JanuSec canonical detection rules
# ---------------------------------------------------------------------------

def _build_rules() -> list[dict[str, Any]]:
    """Return the canonical JanuSec Analytics Rule definitions."""
    return [
        {
            'name': f'{_RULE_PREFIX}high-risk-signin',
            'displayName': 'JanuSec: High-risk Entra ID sign-in',
            'description': 'Detects high or medium risk sign-ins from Entra ID - forwards to JanuSec via Event Hub Automation Playbook.',
            'severity': 'High',
            'query': (
                'SigninLogs\n'
                '| where ResultType == 0\n'
                '| where RiskLevelDuringSignIn in ("high", "medium")\n'
                '| where AppDisplayName !in ("Microsoft Teams", "Office 365")\n'
                '| project TimeGenerated, UserPrincipalName, IPAddress, Location,\n'
                '          RiskLevelDuringSignIn, AppDisplayName, DeviceDetail'
            ),
            'queryFrequency': 'PT5M',
            'queryPeriod': 'PT1H',
            'triggerOperator': 'GreaterThan',
            'triggerThreshold': 0,
            'suppressionDuration': 'PT1H',
            'suppressionEnabled': False,
            'tactics': ['InitialAccess', 'CredentialAccess'],
            'techniques': ['T1078'],
        },
        {
            'name': f'{_RULE_PREFIX}lateral-movement',
            'displayName': 'JanuSec: Lateral movement (SMB / logon spread)',
            'description': 'Detects accounts authenticating to 4+ hosts via logon type 3/10 in a 5-minute window.',
            'severity': 'Medium',
            'query': (
                'SecurityEvent\n'
                '| where EventID in (4624, 4648, 4672)\n'
                '| where LogonType in (3, 10)\n'
                '| where Account !endswith "$"\n'
                '| summarize count(), dcount(Computer) by Account, bin(TimeGenerated, 5m)\n'
                '| where dcount_Computer > 3'
            ),
            'queryFrequency': 'PT5M',
            'queryPeriod': 'PT30M',
            'triggerOperator': 'GreaterThan',
            'triggerThreshold': 0,
            'suppressionDuration': 'PT30M',
            'suppressionEnabled': False,
            'tactics': ['LateralMovement'],
            'techniques': ['T1021'],
        },
        {
            'name': f'{_RULE_PREFIX}privileged-role-assignment',
            'displayName': 'JanuSec: Privileged role assignment (Global Admin)',
            'description': 'Fires when any account is added to the Global Administrator role in Entra ID.',
            'severity': 'High',
            'query': (
                'AuditLogs\n'
                '| where OperationName startswith "Add member to role"\n'
                '| where TargetResources[0].modifiedProperties[0].newValue contains "Global Administrator"\n'
                '| project TimeGenerated, InitiatedBy, TargetResources'
            ),
            'queryFrequency': 'PT1M',
            'queryPeriod': 'PT5M',
            'triggerOperator': 'GreaterThan',
            'triggerThreshold': 0,
            'suppressionDuration': 'PT5M',
            'suppressionEnabled': False,
            'tactics': ['PrivilegeEscalation', 'Persistence'],
            'techniques': ['T1078.004'],
        },
        {
            'name': f'{_RULE_PREFIX}rare-process-execution',
            'displayName': 'JanuSec: Rare process execution on endpoint',
            'description': 'Uses frequency analysis to flag process executions that are rare across the environment.',
            'severity': 'Medium',
            'query': (
                'DeviceProcessEvents\n'
                '| summarize GlobalCount = count() by FileName\n'
                '| top 95 by GlobalCount\n'
                '| join kind=anti (DeviceProcessEvents\n'
                '  | project FileName, DeviceName, TimeGenerated, ProcessCommandLine)\n'
                '  on FileName\n'
                '| project TimeGenerated, DeviceName, FileName, ProcessCommandLine'
            ),
            'queryFrequency': 'PT15M',
            'queryPeriod': 'P1D',
            'triggerOperator': 'GreaterThan',
            'triggerThreshold': 0,
            'suppressionDuration': 'PT1H',
            'suppressionEnabled': False,
            'tactics': ['Execution', 'DefenseEvasion'],
            'techniques': ['T1059', 'T1036'],
        },
    ]


# ---------------------------------------------------------------------------
# Deployment helpers
# ---------------------------------------------------------------------------

def _workspace_url(workspace_id: str, rg: str, sub: str) -> str:
    return (
        f'{_BASE_URL}/subscriptions/{sub}/resourceGroups/{rg}'
        f'/providers/Microsoft.OperationalInsights/workspaces/{workspace_id}'
        f'/providers/Microsoft.SecurityInsights'
    )


def _http(method: str, url: str, token: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode('utf-8') if body else None
    request = _req.Request(
        url,
        data=data,
        headers={
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        },
        method=method,
    )
    try:
        with _req.urlopen(request, timeout=30) as resp:  # noqa: S310
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except Exception as exc:
        logger.error('sentinel_analytics: HTTP %s %s failed: %s', method, url, exc)
        return {'error': str(exc)}


def deploy_rules(
    workspace_id: str = _WORKSPACE_ID,
    resource_group: str = _RESOURCE_GROUP,
    subscription_id: str = _SUBSCRIPTION_ID,
) -> dict[str, Any]:
    """Create/update all JanuSec Analytics Rules in the Sentinel workspace."""
    token = _get_token()
    if not token:
        return {'error': 'authentication_failed'}

    base = _workspace_url(workspace_id, resource_group, subscription_id)
    rules = _build_rules()
    results: dict[str, Any] = {}

    for rule in rules:
        rule_id = rule.pop('name')
        url = f'{base}/alertRules/{rule_id}?api-version={_API_VERSION}'
        body = {
            'kind': 'Scheduled',
            'properties': {
                'enabled': True,
                'displayName': rule.pop('displayName'),
                'description': rule.pop('description'),
                'severity': rule.pop('severity'),
                'query': rule.pop('query'),
                'queryFrequency': rule.pop('queryFrequency'),
                'queryPeriod': rule.pop('queryPeriod'),
                'triggerOperator': rule.pop('triggerOperator'),
                'triggerThreshold': rule.pop('triggerThreshold'),
                'suppressionDuration': rule.pop('suppressionDuration'),
                'suppressionEnabled': rule.pop('suppressionEnabled'),
                'tactics': rule.pop('tactics', []),
                'techniques': rule.pop('techniques', []),
            },
        }
        result = _http('PUT', url, token, body)
        if 'error' in result:
            results[rule_id] = {'status': 'failed', 'error': result['error']}
        else:
            results[rule_id] = {'status': 'deployed'}
        logger.info('sentinel_analytics: rule %s → %s', rule_id, results[rule_id]['status'])

    return results


def list_rules(
    workspace_id: str = _WORKSPACE_ID,
    resource_group: str = _RESOURCE_GROUP,
    subscription_id: str = _SUBSCRIPTION_ID,
) -> list[dict]:
    """List all Analytics Rules whose names start with the janusec prefix."""
    token = _get_token()
    if not token:
        return []
    base = _workspace_url(workspace_id, resource_group, subscription_id)
    url = f'{base}/alertRules?api-version={_API_VERSION}'
    resp = _http('GET', url, token)
    return [
        r for r in resp.get('value', [])
        if r.get('name', '').startswith(_RULE_PREFIX)
    ]


def delete_rules(
    workspace_id: str = _WORKSPACE_ID,
    resource_group: str = _RESOURCE_GROUP,
    subscription_id: str = _SUBSCRIPTION_ID,
) -> dict[str, Any]:
    """Delete all JanuSec-prefixed Analytics Rules."""
    token = _get_token()
    if not token:
        return {'error': 'authentication_failed'}
    base = _workspace_url(workspace_id, resource_group, subscription_id)
    rules = list_rules(workspace_id, resource_group, subscription_id)
    results: dict[str, Any] = {}
    for rule in rules:
        rule_id = rule.get('name', '')
        url = f'{base}/alertRules/{rule_id}?api-version={_API_VERSION}'
        result = _http('DELETE', url, token)
        results[rule_id] = {'status': 'deleted'} if 'error' not in result else result
    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description='Manage JanuSec Sentinel Analytics Rules')
    parser.add_argument('--deploy', action='store_true')
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--delete', action='store_true')
    parser.add_argument('--workspace-id', default=_WORKSPACE_ID)
    parser.add_argument('--resource-group', default=_RESOURCE_GROUP)
    parser.add_argument('--subscription-id', default=_SUBSCRIPTION_ID)
    args = parser.parse_args()

    ws = args.workspace_id
    rg = args.resource_group
    sub = args.subscription_id

    if args.deploy:
        print(json.dumps(deploy_rules(ws, rg, sub), indent=2))
    elif args.list:
        print(json.dumps(list_rules(ws, rg, sub), indent=2))
    elif args.delete:
        print(json.dumps(delete_rules(ws, rg, sub), indent=2))
    else:
        parser.print_help()
