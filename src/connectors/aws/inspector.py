"""AWS Inspector v2 connector — fetch vulnerability findings and normalize.

Inspector v2 covers:
- EC2 instance vulnerabilities (CVE-based with EPSS score)
- ECR container image vulnerabilities
- Lambda function vulnerabilities

Environment variables
---------------------
AWS_INSPECTOR_FILTER_SEVERITY: comma-separated severities to fetch (default: CRITICAL,HIGH)
AWS_INSPECTOR_ECR_ENABLED    : '1' to include ECR findings (default: '1')
AWS_INSPECTOR_LAMBDA_ENABLED : '1' to include Lambda findings (default: '1')
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from .base import (
    AWSConnectorConfig,
    boto3_client,
    canonical_envelope,
    coerce_unix_ts,
    load_checkpoint,
    record_error,
    record_fetch,
    record_yield,
    save_checkpoint,
)
from src.connectors.correlation_keys import build_correlation_keys

logger = logging.getLogger(__name__)

_DEFAULT_SEVERITIES = {'CRITICAL', 'HIGH'}
_ALL_TYPES = ['PACKAGE_VULNERABILITY', 'CODE_VULNERABILITY', 'NETWORK_REACHABILITY']


def _parse_severities() -> List[str]:
    import os
    raw = os.getenv('AWS_INSPECTOR_FILTER_SEVERITY', 'CRITICAL,HIGH')
    sevs = [s.strip().upper() for s in raw.split(',') if s.strip()]
    return sevs or list(_DEFAULT_SEVERITIES)


def _normalize_finding(f: Dict[str, Any], region: str) -> Dict[str, Any]:
    """Normalize an Inspector v2 finding to the canonical event envelope."""
    env = canonical_envelope(
        f,
        'inspector',
        account_id=f.get('awsAccountId'),
        region=region,
    )
    env['ingest_source'] = 'inspector'
    sev = f.get('severity', 'INFORMATIONAL')
    env['severity'] = sev

    # Package vulnerability details
    vuln = (f.get('packageVulnerabilityDetails') or {})
    vuln_id = vuln.get('vulnerabilityId') or f.get('findingArn', '')
    env['title'] = f.get('title') or vuln_id
    env['cve_id'] = vuln_id
    env['cvss_score'] = _extract_cvss(vuln)
    env['epss_score'] = _extract_epss(f)
    env['fixed_in_version'] = _extract_fixed_version(vuln)

    # Resource context
    resources = f.get('resources') or []
    if resources:
        r = resources[0]
        rtype = r.get('type', '')
        rdetails = r.get('details') or {}
        env['resource_type'] = rtype
        env['resource_id'] = r.get('id')
        if rtype == 'AWS_EC2_INSTANCE':
            ec2 = rdetails.get('awsEc2Instance') or {}
            env['host'] = ec2.get('ipV4Addresses', [None])[0] or r.get('id')
            env['platform'] = ec2.get('platform')
            env['ami_id'] = ec2.get('imageId')
        elif rtype == 'AWS_ECR_CONTAINER_IMAGE':
            ecr = rdetails.get('awsEcrContainerImage') or {}
            env['image_digest'] = ecr.get('imageDigest')
            env['image_tags'] = ecr.get('imageTags') or []
            env['repository_name'] = ecr.get('repositoryName')
        elif rtype == 'AWS_LAMBDA_FUNCTION':
            lam = rdetails.get('awsLambdaFunction') or {}
            env['function_name'] = lam.get('functionName')
            env['runtime'] = lam.get('runtime')

    # Timestamps
    updated_ts = coerce_unix_ts(f.get('updatedAt') or f.get('firstObservedAt'))
    if updated_ts:
        env['ts'] = updated_ts

    # Affected packages
    vuln_pkgs = vuln.get('vulnerablePackages') or []
    env['affected_packages'] = [
        {
            'name': p.get('name'),
            'version': p.get('version'),
            'fixed_in': p.get('fixedInVersion'),
            'remediation': p.get('remediation'),
        }
        for p in vuln_pkgs[:10]
    ]

    env['finding_arn'] = f.get('findingArn')
    env['status'] = f.get('status')
    env['description'] = (f.get('description') or '')[:500]
    env['remediation'] = _extract_remediation(f)
    env['factors'] = [f'inspector:vuln_{sev.lower()}']
    if vuln_id:
        env['factors'].append(f'cve:{vuln_id}')

    env['correlation_keys'] = build_correlation_keys(
        env,
        extra_values={'cve_id': vuln_id, 'account_id': f.get('awsAccountId')},
    )
    return env


def _extract_cvss(vuln: Dict[str, Any]) -> Optional[float]:
    try:
        scores = vuln.get('cvss') or []
        if scores:
            return float(scores[0].get('baseScore') or 0)
    except Exception:
        pass
    return None


def _extract_epss(f: Dict[str, Any]) -> Optional[float]:
    try:
        score = (f.get('epss') or {}).get('score')
        if score is not None:
            return float(score)
    except Exception:
        pass
    return None


def _extract_fixed_version(vuln: Dict[str, Any]) -> Optional[str]:
    pkgs = vuln.get('vulnerablePackages') or []
    if pkgs:
        return pkgs[0].get('fixedInVersion')
    return None


def _extract_remediation(f: Dict[str, Any]) -> Optional[str]:
    try:
        rem = f.get('remediation') or {}
        rec = rem.get('recommendation') or {}
        return rec.get('text') or rec.get('url')
    except Exception:
        return None


class InspectorConnector:
    """AWS Inspector v2 findings connector."""

    def __init__(self, cfg: AWSConnectorConfig) -> None:
        self.cfg = cfg
        self.name = 'inspector'
        self.ck = load_checkpoint(self.name, cfg)

    def fetch_findings(self) -> Iterable[Dict[str, Any]]:
        """Yield normalized Inspector findings since last checkpoint."""
        try:
            record_fetch(self.name)
            client = boto3_client('inspector2', self.cfg)
            region = self.cfg.region or 'us-east-1'
            severities = _parse_severities()
            newest_ts = coerce_unix_ts(self.ck.get('last_ts')) or 0

            filter_criteria: Dict[str, Any] = {
                'severity': [{'comparison': 'EQUALS', 'value': s} for s in severities],
                'findingStatus': [{'comparison': 'EQUALS', 'value': 'ACTIVE'}],
            }
            if newest_ts:
                iso = datetime.fromtimestamp(newest_ts, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                filter_criteria['updatedAt'] = [
                    {'startInclusive': iso, 'endExclusive': datetime.now(tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
                ]

            import os
            paginator = client.get_paginator('list_findings')
            page_iter = paginator.paginate(
                filterCriteria=filter_criteria,
                PaginationConfig={'MaxItems': int(os.getenv('AWS_INSPECTOR_MAX_FINDINGS', '1000'))},
            )
            for page in page_iter:
                for f in page.get('findings') or []:
                    env = _normalize_finding(f, region)
                    finding_ts = env.get('ts') or newest_ts
                    newest_ts = max(newest_ts, finding_ts or 0)
                    record_yield(self.name, 1)
                    yield env

            if newest_ts:
                self.ck['last_ts'] = newest_ts
                save_checkpoint(self.name, self.cfg, self.ck)

        except Exception:
            record_error(self.name)
            logger.exception('Inspector fetch failed')

    def commit(self, marker: Any) -> None:
        self.ck['marker'] = marker
        save_checkpoint(self.name, self.cfg, self.ck)

    def get_sbom_for_resource(self, resource_id: str) -> Dict[str, Any]:
        """Fetch SBOM component list for a given EC2 instance or Lambda ARN."""
        try:
            client = boto3_client('inspector2', self.cfg)
            resp = client.list_finding_aggregations(
                aggregationType='AMI',
                aggregationRequest={
                    'amiAggregation': {
                        'amis': [{'comparison': 'EQUALS', 'value': resource_id}]
                    }
                },
            )
            return {'resource_id': resource_id, 'aggregations': resp.get('responses', [])}
        except Exception as exc:
            logger.warning('SBOM fetch for %s failed: %s', resource_id, exc)
            return {'resource_id': resource_id, 'error': str(exc)}
