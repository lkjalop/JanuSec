from __future__ import annotations
import os, time, json
from typing import List, Dict, Any, Tuple
from .base import EventCollector

# Module-level third-party imports so tests can monkeypatch them
import logging
try:
    import boto3
except Exception:
    boto3 = None

try:
    from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
except Exception:
    # Provide no-op fallbacks if tenacity isn't installed; tests can monkeypatch these.
    def retry(*args, **kwargs):
        def decorator(f):
            return f
        return decorator

    def stop_after_attempt(n):
        return None

    def wait_exponential(**kwargs):
        return None

    def retry_if_exception_type(exc):
        return (lambda e: True)

    # Best-effort preserve signature on the no-op retry factory so wrappers
    # don't expose a generic ``*args, **kwargs`` signature to introspection
    try:
        from src.security.signature_helpers import preserve_signature
        try:
            preserve_signature(retry, retry)
        except Exception:
            import inspect as _inspect
            try:
                retry.__signature__ = _inspect.signature(retry)
            except Exception:
                pass
    except Exception:
        try:
            import inspect as _inspect
            retry.__signature__ = _inspect.signature(retry)
        except Exception:
            pass

import datetime


_BASELINE_CACHE: dict[str, dict[str, Any]] = {}

class AWSConfigCollector(EventCollector):
    source = "aws_config"

    def __init__(self, tenant_id: str = 'default'):
        self.tenant_id = tenant_id
        self._access = os.getenv("AWS_ACCESS_KEY_ID")
        self._secret = os.getenv("AWS_SECRET_ACCESS_KEY")
        self._region = os.getenv("AWS_REGION", "us-east-1")
        self._client = None
        if self._access and self._secret and boto3 is not None:
            try:
                self._client = boto3.client(
                    'config',
                    aws_access_key_id=self._access,
                    aws_secret_access_key=self._secret,
                    region_name=self._region
                )
            except Exception as e:
                logging.error(f"Failed to initialize boto3 client: {e}")
                self._client = None

    def _list_resource_types(self) -> List[str]:
        # Minimal curated subset for MVP
        # Order chosen to prefer IAM Role first to make tests deterministic
        # when paginator is mocked generically.
        return [
            'AWS::IAM::Role',
            'AWS::S3::Bucket',
            'AWS::EC2::Instance',
            'AWS::EC2::SecurityGroup',
        ]

    def _enumerate_ids(self, resource_type: str) -> List[str]:
        # For demo, rely on env-provided hints; production would query AWS APIs
        key = f"AWS_ENUM_{resource_type.replace('::','_')}_IDS"
        raw = os.getenv(key, '')
        ids = [r.strip() for r in raw.split(',') if r.strip()]
        # Fallback small default per type
        if not ids:
            if resource_type == 'AWS::S3::Bucket':
                ids = [os.getenv('AWS_CONFIG_BUCKET','sensitive-bucket')]
            elif resource_type == 'AWS::EC2::Instance':
                ids = [os.getenv('AWS_CONFIG_EC2','i-demo1234567890')]
            elif resource_type == 'AWS::EC2::SecurityGroup':
                ids = [os.getenv('AWS_CONFIG_SG','sg-demo1234567890')]
            elif resource_type == 'AWS::IAM::Role':
                ids = [os.getenv('AWS_CONFIG_ROLE','JanusecDemoRole')]
        return ids

    def _baseline_key(self, resource_type: str, resource_id: str) -> str:
        return f"{self.tenant_id}:{resource_type}:{resource_id}"

    def _compute_diff(self, resource_type: str, resource_id: str, item: dict[str, Any]) -> dict[str, Any]:
        k = self._baseline_key(resource_type, resource_id)
        prev = _BASELINE_CACHE.get(k)
        cur_conf = item.get('configuration') or {}
        changes: dict[str, Any] = {}
        if prev:
            try:
                for field, val in cur_conf.items():
                    if prev.get(field) != val:
                        changes[field] = {'old': prev.get(field), 'new': val}
                # detect removed keys
                for field in prev.keys():
                    if field not in cur_conf:
                        changes[field] = {'old': prev.get(field), 'new': None}
            except Exception:
                changes['error'] = 'diff_failed'
        _BASELINE_CACHE[k] = cur_conf
        return changes

    def fetch_events(self, since_ts: float) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        if not self._client:
            return []

        @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10),
               retry=retry_if_exception_type(Exception))
        def get_changes_for(resource_type: str, resource_id: str) -> List[Dict[str, Any]]:
            out: List[Dict[str, Any]] = []
            try:
                paginator = self._client.get_paginator('get_resource_config_history')
                for page in paginator.paginate(resourceType=resource_type, resourceId=resource_id, limit=100):
                    for item in page.get('configurationItems', []):
                        capture = item.get('configurationItemCaptureTime')
                        ts = since_ts + 1
                        if capture:
                            if hasattr(capture, 'timestamp'):
                                ts = capture.timestamp()
                            else:
                                try:
                                    ts = time.mktime(capture.timetuple())
                                except Exception:
                                    ts = since_ts + 1
                        if ts < since_ts:
                            continue
                        diff = self._compute_diff(resource_type, resource_id, item)
                        record = {
                            'resource_type': resource_type,
                            'resource_id': resource_id,
                            # include original-cased key; prefer item value when provided
                            'resourceId': item.get('resourceId', resource_id),
                            'ts': ts,
                            'raw': item,
                            'diff': diff
                        }
                        out.append(record)
            except Exception as e:
                logging.error(f"AWS resource history error {resource_type}/{resource_id}: {e}")
            return out

        # Enumerate resource types & IDs
        for rtype in self._list_resource_types():
            for rid in self._enumerate_ids(rtype):
                events.extend(get_changes_for(rtype, rid))
        return events


__all__ = ["AWSConfigCollector"]
