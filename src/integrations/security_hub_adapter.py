"""Boto3-backed Security Hub connector with AssumeRole and SQS buffering.

Configuration via env vars:
- AWS_ASSUME_ROLE_ARN: ARN to assume (optional)
- AWS_REGION: region for boto3 clients
- SECURITY_HUB_SQS_URL: optional local SQS queue to buffer findings
"""
from __future__ import annotations

import json
import time
import os
import logging
from typing import Any, Dict, List, Optional, Tuple

try:
    import boto3
    from botocore.exceptions import ClientError
except Exception:
    boto3 = None
    ClientError = Exception

try:
    from .connector_base import ConnectorBase
except Exception:
    from src.integrations.connector_base import ConnectorBase  # type: ignore

logger = logging.getLogger(__name__)

ROLE_ARN = os.getenv('AWS_ASSUME_ROLE_ARN')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
SQS_URL = os.getenv('SECURITY_HUB_SQS_URL')


def _assume_role_session(role_arn: str, region_name: str = 'us-east-1'):
    sts = boto3.client('sts', region_name=region_name)
    resp = sts.assume_role(RoleArn=role_arn, RoleSessionName='janusec-securityhub')
    creds = resp['Credentials']
    return boto3.Session(
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken'],
        region_name=region_name,
    )


class SecurityHubAdapter(ConnectorBase):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._cursor: Optional[str] = None
        self._session = None
        self._client = None
        self._sqs = None

        if boto3:
            try:
                if ROLE_ARN:
                    self._session = _assume_role_session(ROLE_ARN, region_name=AWS_REGION)
                else:
                    self._session = boto3.Session(region_name=AWS_REGION)
                self._client = self._session.client('securityhub')
                if SQS_URL:
                    self._sqs = self._session.client('sqs')
            except Exception:
                logger.exception('Failed to initialize AWS clients')

    async def connect(self) -> bool:
        return self._client is not None

    async def fetch_since(self, since: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """Poll Security Hub findings since `since` timestamp. Uses `get_findings`.

        Returns list of canonical findings and a cursor (timestamp) to ack.
        """
        if not self._client:
            return [], None
        # Build filter: use timestamp greater than since if provided
        filters = {}
        try:
            kwargs: Dict[str, Any] = {'MaxResults': 50}
            if since:
                # Security Hub filters expect date-time strings; use ISO format
                kwargs['Filters'] = {'UpdatedAt': [{'DateRange': {'Value': int(time.time() - int(since)), 'Unit': 'SECONDS'}}]}
            resp = self._client.get_findings(**kwargs)
            findings = resp.get('Findings') or []
            out = [self.canonical_finding(f) for f in findings]
            cursor = str(int(time.time()))
            return out, cursor
        except ClientError:
            logger.exception('SecurityHub get_findings failed')
            return [], None

    async def ack(self, cursor: Optional[str]) -> bool:
        self._cursor = cursor or self._cursor
        return True

    async def health(self) -> Dict[str, Any]:
        return {'connected': bool(self._client), 'cursor': self._cursor}

    def canonical_finding(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'ts': raw.get('UpdatedAt') or raw.get('CreatedAt') or int(time.time()),
            'id': raw.get('Id') or raw.get('Title'),
            'title': raw.get('Title'),
            'severity': (raw.get('Severity') or {}).get('Label') if isinstance(raw.get('Severity'), dict) else raw.get('Severity'),
            'resource': raw.get('Resources', []),
            'raw': raw,
        }

    async def buffer_to_sqs(self, findings: List[Dict[str, Any]]) -> None:
        if not (self._sqs and SQS_URL):
            return
        for f in findings:
            try:
                self._sqs.send_message(QueueUrl=SQS_URL, MessageBody=json.dumps(f, default=str))
            except Exception:
                logger.exception('Failed to enqueue finding to SQS')

    async def push_findings(self, base_url: str, api_key: str, tenant_id: str, findings: List[Dict[str, Any]]) -> None:
        """If SQS buffering configured, push to SQS; otherwise send directly using resilient_post."""
        if SQS_URL and self._sqs:
            await self.buffer_to_sqs(findings)
            return

        # send directly
        try:
            from .resilient_ingest import resilient_post, build_post_payload
        except Exception:
            from integrations.resilient_ingest import resilient_post, build_post_payload

        # idempotency: use the IdempotencyStore to avoid duplicate pushes
        try:
            from src.core.idempotency import IdempotencyStore, run_idempotent
        except Exception:
            from core.idempotency import IdempotencyStore, run_idempotent  # type: ignore

        import hashlib

        payload = json.dumps({'findings': findings}).encode('utf-8')
        url = f"{base_url.rstrip('/')}/api/v1/ingest/securityhub"

        def _do_post():
            import urllib.request
            req = urllib.request.Request(
                url,
                data=payload,
                method='POST',
                headers={
                    'Content-Type': 'application/json',
                    'x-api-key': api_key,
                    'x-tenant-id': tenant_id,
                },
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.read()

        # idempotency key: tenant + timestamp + payload hash
        store = IdempotencyStore()
        idemp_key = '|'.join([tenant_id or 'no-tenant', str(int(time.time())), hashlib.sha256(payload).hexdigest()])

        meta = build_post_payload(base_url, api_key, tenant_id, findings)
        meta['idempotency_key'] = idemp_key

        try:
            run_idempotent(store, idemp_key, lambda: resilient_post(_do_post, meta, attempts=4))
        except RuntimeError:
            logger.info('Idempotent push already in progress; skipping')
        except Exception:
            logger.exception('Failed to push findings idempotently')
