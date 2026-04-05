"""AWS connector base helpers: lightweight, import-safe wrappers.

These helpers avoid hard dependency on `boto3` at import time and provide
common utilities: assume-role, checkpointing (file-based by default), idempotent
envelope creation, backoff, and safe list/pagination helpers.
"""
from __future__ import annotations

import json
import os
import time
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)
try:
    from src.api.metrics_init import _safe_counter
    _AWS_FETCH_TOTAL = _safe_counter('aws_connector_fetch_total', 'AWS connector fetch attempts', labels=['connector'])
    _AWS_FETCH_ERRORS = _safe_counter('aws_connector_fetch_errors_total', 'AWS connector fetch errors', labels=['connector'])
    _AWS_EVENTS_YIELD = _safe_counter('aws_connector_events_total', 'AWS connector events yielded', labels=['connector'])
except Exception:
    _AWS_FETCH_TOTAL = _AWS_FETCH_ERRORS = _AWS_EVENTS_YIELD = None


def _aws_metric_inc(counter, connector: str, value: int = 1) -> None:
    try:
        if counter is not None:
            counter.labels(connector=connector).inc(value)
    except Exception:
        pass


def record_fetch(connector: str) -> None:
    _aws_metric_inc(_AWS_FETCH_TOTAL, connector, 1)


def record_error(connector: str) -> None:
    _aws_metric_inc(_AWS_FETCH_ERRORS, connector, 1)


def record_yield(connector: str, count: int = 1) -> None:
    _aws_metric_inc(_AWS_EVENTS_YIELD, connector, count)


class AWSConnectorConfig:
    def __init__(
        self,
        role_arn: Optional[str] = None,
        region: Optional[str] = None,
        checkpoint_dir: str | None = None,
        log_group_name: Optional[str] = None,
        securityhub_region: Optional[str] = None,
    ):
        self.role_arn = role_arn
        self.region = region or os.getenv('AWS_REGION')
        self.checkpoint_dir = checkpoint_dir or os.getenv('CONNECTORS_CHECKPOINT_DIR', 'data/checkpoints')
        self.log_group_name = log_group_name or os.getenv('AWS_VPCFLOW_LOG_GROUP')
        self.securityhub_region = securityhub_region or os.getenv('AWS_SECURITYHUB_REGION') or self.region


def _ensure_checkpoint_dir(path: str) -> None:
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        pass


def checkpoint_path(name: str, cfg: AWSConnectorConfig) -> str:
    base = cfg.checkpoint_dir or 'data/checkpoints'
    _ensure_checkpoint_dir(base)
    return os.path.join(base, f"aws_{name}.checkpoint.json")


def load_checkpoint(name: str, cfg: AWSConnectorConfig) -> dict:
    p = checkpoint_path(name, cfg)
    try:
        if os.path.exists(p):
            with open(p, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        logger.exception('failed to load checkpoint')
    return {}


def save_checkpoint(name: str, cfg: AWSConnectorConfig, data: dict) -> None:
    p = checkpoint_path(name, cfg)
    tmp = p + '.tmp'
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f)
        os.replace(tmp, p)
    except Exception:
        logger.exception('failed to save checkpoint')
        try:
            os.remove(tmp)
        except Exception:
            pass


# Boto3 lazy import helper
def boto3_client(service: str, cfg: AWSConnectorConfig, assume_role_session_name: str = 'connector-session'):
    try:
        import boto3
        from botocore.config import Config as BConfig
    except Exception:
        raise RuntimeError(
            'boto3 is required for AWS connectors. Install with: pip install boto3\n'
            'Also configure credentials: AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY + AWS_DEFAULT_REGION '
            'environment variables, an IAM instance role, or ~/.aws/credentials.'
        )

    # Emit a clear warning when no credentials appear to be configured
    has_key = bool(os.getenv('AWS_ACCESS_KEY_ID') or os.getenv('AWS_PROFILE'))
    has_role = bool(cfg.role_arn or os.getenv('AWS_ROLE_ARN'))
    has_instance_meta = os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount/token') or \
                        os.path.exists('/proc/self/cgroup')  # running in a container/EC2 with instance role
    if not (has_key or has_role or has_instance_meta):
        logger.warning(
            'AWS connector (%s): no credentials detected. Set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, '
            'configure an IAM role, or set up ~/.aws/credentials. '
            'See: https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html',
            service
        )

    region = cfg.region or None
    botoconf = BConfig(retries={'max_attempts': 3})

    # Role assumption if requested
    if cfg.role_arn:
        try:
            sts = boto3.client('sts', region_name=region)
            resp = sts.assume_role(RoleArn=cfg.role_arn, RoleSessionName=assume_role_session_name)
            creds = resp.get('Credentials') or {}
            return boto3.client(
                service,
                region_name=region,
                aws_access_key_id=creds.get('AccessKeyId'),
                aws_secret_access_key=creds.get('SecretAccessKey'),
                aws_session_token=creds.get('SessionToken'),
                config=botoconf,
            )
        except Exception:
            logger.exception('assume role failed; falling back to default credentials')
    # Default client
    return boto3.client(service, region_name=region, config=botoconf)


def canonical_envelope(raw: dict[str, Any], source: str, account_id: Optional[str] = None, region: Optional[str] = None) -> dict:
    """Wrap raw event into a canonical envelope used by ingestion pipeline."""
    env = {
        'source': source,
        'raw': raw,
        'account_id': account_id,
        'region': region,
        'recv_ts': int(time.time()),
        'id': raw.get('id') or raw.get('eventId') or raw.get('EventId') or hashlib_fingerprint(raw),
    }
    return env


def coerce_unix_ts(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, datetime):
        try:
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return int(value.timestamp())
        except Exception:
            return None
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None
        try:
            if cleaned.endswith('Z'):
                cleaned = cleaned[:-1] + '+00:00'
            return int(datetime.fromisoformat(cleaned).timestamp())
        except Exception:
            try:
                return int(float(cleaned))
            except Exception:
                return None
    return None


def as_utc_datetime(value: Any) -> datetime | None:
    ts = coerce_unix_ts(value)
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def hashlib_fingerprint(obj: Any) -> str:
    try:
        import hashlib
        s = json.dumps(obj, sort_keys=True, separators=(',', ':'), default=str)
        return hashlib.sha256(s.encode('utf-8')).hexdigest()
    except Exception:
        return str(int(time.time() * 1000))
