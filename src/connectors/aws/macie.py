"""AWS Macie connector — fetch S3 data-classification and sensitive-data findings.

Amazon Macie continuously monitors S3 buckets for sensitive data (PII, PHI,
credentials) and policy violations. This connector fetches:
  - Sensitive data findings   (SENSITIVE_DATA finding type)
  - Policy findings            (POLICY finding type)
  - Bucket statistics          (coverage summary)

Required IAM permissions:
  macie2:ListFindings
  macie2:GetFindings
  macie2:DescribeBuckets

Environment variables:
  AWS_MACIE_REGION   — Macie region (default: same as AWS_REGION)

boto3 is an optional dependency; when absent the connector yields nothing.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional

from .base import (
    AWSConnectorConfig,
    boto3_client,
    load_checkpoint,
    save_checkpoint,
    canonical_envelope,
    record_fetch,
    record_error,
    record_yield,
    coerce_unix_ts,
)
from src.connectors.correlation_keys import build_correlation_keys

logger = logging.getLogger(__name__)

# Macie severity mapping
_MACIE_SEVERITY: Dict[str, str] = {
    'LOW': 'low',
    'MEDIUM': 'medium',
    'HIGH': 'high',
    'CRITICAL': 'critical',
}

# Sensitive data categories → canonical factors
_SENSITIVE_CATEGORY_FACTORS: Dict[str, str] = {
    'FINANCIAL_INFORMATION': 'data:pci_sensitive',
    'PERSONAL_HEALTH_INFORMATION': 'data:phi_exposure',
    'PERSONAL_INFORMATION': 'data:pii_exposure',
    'CREDENTIALS': 'data:credential_exposure',
    'CUSTOM_IDENTIFIER': 'data:custom_sensitive',
}


def _extract_sensitive_categories(finding: Dict[str, Any]) -> List[str]:
    """Return canonical factor strings for each sensitive data category found."""
    categories: List[str] = []
    sensitive = finding.get('classificationDetails') or {}
    result = sensitive.get('result') or {}
    for cat_obj in (result.get('sensitiveData') or []):
        cat = str(cat_obj.get('category') or '').upper()
        factor = _SENSITIVE_CATEGORY_FACTORS.get(cat)
        if factor:
            categories.append(factor)
    return categories or ['data:sensitive_data_detected']


class MacieConnector:
    """AWS Macie findings connector with checkpoint support."""

    def __init__(self, cfg: AWSConnectorConfig):
        self.cfg = cfg
        self.name = 'macie'
        self.ck = load_checkpoint(self.name, cfg)

    def fetch_findings(
        self,
        finding_types: Optional[List[str]] = None,
    ) -> Iterable[Dict[str, Any]]:
        """Yield canonical envelopes for Macie findings.

        Args:
            finding_types: List of Macie finding type prefixes to include,
                e.g. ['SensitiveData', 'Policy']. Defaults to both.
        """
        try:
            record_fetch(self.name)
            client = boto3_client('macie2', self.cfg)

            last_ts = coerce_unix_ts(self.ck.get('last_ts')) or 0
            newest_ts = last_ts

            # Build finding criteria filter
            filter_criteria: Dict[str, Any] = {}
            if last_ts:
                from datetime import datetime, timezone
                iso = datetime.fromtimestamp(int(last_ts), tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                filter_criteria['updatedAt'] = {'gte': iso}

            # List finding IDs
            list_kwargs: Dict[str, Any] = {
                'maxResults': 50,
                'sortCriteria': {'attributeName': 'updatedAt', 'orderBy': 'DESC'},
            }
            if filter_criteria:
                list_kwargs['findingCriteria'] = {'criterion': filter_criteria}

            # Apply type filter if requested
            if finding_types:
                type_filters = [{'eq': [ft]} for ft in finding_types]
                list_kwargs.setdefault('findingCriteria', {}).setdefault('criterion', {})['type'] = {'eq': finding_types}

            all_finding_ids: List[str] = []
            next_token: Optional[str] = None
            while True:
                if next_token:
                    list_kwargs['nextToken'] = next_token
                try:
                    resp = client.list_findings(**list_kwargs)
                except Exception as exc:
                    logger.warning('Macie: list_findings failed: %s', exc)
                    record_error(self.name)
                    return
                all_finding_ids.extend(resp.get('findingIds') or [])
                next_token = resp.get('nextToken')
                if not next_token or len(all_finding_ids) >= 500:
                    break

            if not all_finding_ids:
                return

            # Fetch findings in batches of 25 (Macie API max)
            for batch_start in range(0, len(all_finding_ids), 25):
                batch = all_finding_ids[batch_start: batch_start + 25]
                try:
                    details_resp = client.get_findings(findingIds=batch)
                except Exception as exc:
                    logger.warning('Macie: get_findings batch failed: %s', exc)
                    record_error(self.name)
                    continue

                for f in details_resp.get('findings') or []:
                    sev_label = _MACIE_SEVERITY.get(
                        str((f.get('severity') or {}).get('description') or '').upper(),
                        'medium',
                    )
                    resource_arn = None
                    resource_obj = f.get('resourcesAffected') or {}
                    s3_bucket = resource_obj.get('s3Bucket') or {}
                    s3_obj = resource_obj.get('s3Object') or {}
                    resource_arn = s3_bucket.get('arn') or s3_obj.get('bucketArn')
                    bucket_name = s3_bucket.get('name') or s3_obj.get('bucketName')

                    sensitive_factors = _extract_sensitive_categories(f)
                    env = canonical_envelope(
                        f,
                        'macie',
                        account_id=f.get('accountId'),
                        region=self.cfg.region,
                    )
                    env['severity'] = sev_label
                    env['confidence'] = float((f.get('severity') or {}).get('score') or 50) / 100.0
                    env['title'] = f.get('title') or f.get('description') or 'Macie data finding'
                    env['finding_id'] = f.get('id')
                    env['finding_type'] = f.get('type')
                    env['resource'] = resource_arn or bucket_name
                    env['bucket_name'] = bucket_name
                    env['factors'] = sensitive_factors + ['cloud:provider_detection']
                    env['category'] = f.get('category')
                    env['correlation_keys'] = build_correlation_keys(
                        env,
                        extra_values={'bucket': bucket_name, 'account_id': f.get('accountId')},
                    )
                    finding_ts = coerce_unix_ts(f.get('updatedAt') or f.get('createdAt'))
                    if finding_ts:
                        env['ts'] = finding_ts
                        newest_ts = max(newest_ts, finding_ts)
                    record_yield(self.name, 1)
                    yield env

            if newest_ts > last_ts:
                self.ck['last_ts'] = newest_ts
                save_checkpoint(self.name, self.cfg, self.ck)

        except Exception:
            record_error(self.name)
            logger.exception('Macie: fetch_findings failed')

    def describe_buckets(self) -> List[Dict[str, Any]]:
        """Return a summary list of S3 bucket coverage statistics."""
        try:
            client = boto3_client('macie2', self.cfg)
            resp = client.describe_buckets()
            return [
                {
                    'bucket': b.get('bucketName'),
                    'account_id': b.get('accountId'),
                    'object_count': b.get('objectCount'),
                    'size_bytes': b.get('sizeInBytes'),
                    'classifiable_object_count': b.get('classifiableObjectCount'),
                    'unclassifiable_object_count': b.get('unclassifiableObjectCount'),
                    'public_access': (b.get('publicAccess') or {}).get('effectivePermission'),
                    'encryption_type': (b.get('serverSideEncryption') or {}).get('type'),
                    'sensitive_data_found': b.get('sensitiveDataOccurrencesEquality'),
                }
                for b in (resp.get('buckets') or [])
            ]
        except Exception as exc:
            logger.warning('Macie: describe_buckets failed: %s', exc)
            return []

    def commit(self, marker: Any) -> None:
        self.ck['marker'] = marker
        save_checkpoint(self.name, self.cfg, self.ck)
