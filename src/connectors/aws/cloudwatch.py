"""CloudWatch Logs connector — full filter_log_events implementation.

Supports:
- Multiple log groups (comma-separated AWS_CW_LOG_GROUPS)
- Incremental checkpointing per log group (nextToken + last timestamp)
- Pattern/filter matching (AWS_CW_FILTER_PATTERN)
- Event normalization to the canonical envelope

Environment variables
---------------------
AWS_CW_LOG_GROUPS       : Comma-separated log group names (required)
AWS_CW_FILTER_PATTERN   : CloudWatch filter pattern (default: '' = all events)
AWS_CW_LOG_STREAM_PREFIX: Optional stream prefix filter
AWS_CW_BATCH_SECONDS    : Time window per batch in seconds (default: 300)
AWS_CW_MAX_EVENTS       : Max events per fetch (default: 1000)
"""
from __future__ import annotations

import json
import logging
import os
import time
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


def _log_groups() -> List[str]:
    raw = os.getenv('AWS_CW_LOG_GROUPS', '')
    if not raw:
        single = os.getenv('AWS_VPCFLOW_LOG_GROUP', '')
        return [single] if single else []
    return [g.strip() for g in raw.split(',') if g.strip()]


def _parse_log_event(event: Dict[str, Any], log_group: str, region: str, account_id: Optional[str]) -> Dict[str, Any]:
    raw_message = event.get('message', '')
    ts_ms = event.get('timestamp', 0)
    ts = ts_ms / 1000.0 if ts_ms else time.time()
    parsed: Dict[str, Any] = {}
    try:
        parsed = json.loads(raw_message)
    except Exception:
        parsed = {'raw_message': raw_message}
    env = canonical_envelope(parsed, 'cloudwatch', account_id=account_id, region=region)
    env['ts'] = ts
    env['log_group'] = log_group
    env['log_stream'] = event.get('logStreamName', '')
    env['event_id'] = event.get('eventId', '')
    env['raw_message'] = raw_message[:2000]
    _enrich_from_message(env, parsed, raw_message)
    env['correlation_keys'] = build_correlation_keys(
        env, extra_values={'log_group': log_group, 'account_id': account_id}
    )
    return env


def _enrich_from_message(env: Dict[str, Any], parsed: Dict[str, Any], raw: str) -> None:
    parts = raw.split()
    if len(parts) >= 13 and parts[0].isdigit():
        try:
            env.setdefault('src_ip', parts[3] if parts[3] != '-' else None)
            env.setdefault('dst_ip', parts[4] if parts[4] != '-' else None)
            env.setdefault('src_port', int(parts[5]) if parts[5].isdigit() else None)
            env.setdefault('dst_port', int(parts[6]) if parts[6].isdigit() else None)
            env.setdefault('protocol', parts[7])
            env.setdefault('action', parts[12] if len(parts) > 12 else None)
        except Exception:
            pass
    for src_key, dst_key in [
        ('userIdentity', 'user'), ('sourceIPAddress', 'src_ip'),
        ('eventName', 'event_name'), ('eventSource', 'source'),
        ('awsRegion', 'region'), ('errorCode', 'error_code'),
        ('errorMessage', 'error_message'),
    ]:
        val = parsed.get(src_key)
        if val is not None:
            if dst_key == 'user' and isinstance(val, dict):
                env[dst_key] = val.get('userName') or val.get('principalId') or str(val)
            else:
                env.setdefault(dst_key, val)
    level = parsed.get('level') or parsed.get('severity') or parsed.get('logLevel', '')
    if level:
        env['severity'] = str(level).upper()


class CloudWatchConnector:
    """CloudWatch Logs connector — full filter_log_events implementation."""

    def __init__(self, cfg: AWSConnectorConfig) -> None:
        self.cfg = cfg
        self.name = 'cloudwatch'
        self.ck = load_checkpoint(self.name, cfg)

    def fetch_events(self, log_group: Optional[str] = None) -> Iterable[Dict[str, Any]]:
        groups = [log_group] if log_group else _log_groups()
        if not groups:
            logger.warning('CloudWatch: no log groups configured (set AWS_CW_LOG_GROUPS)')
            return
        for group in groups:
            yield from self._fetch_group(group)

    def _fetch_group(self, log_group: str) -> Iterable[Dict[str, Any]]:
        try:
            record_fetch(self.name)
            client = boto3_client('logs', self.cfg)
            region = self.cfg.region or 'us-east-1'
            account_id: Optional[str] = None
            try:
                import boto3 as _b3
                sts = _b3.client('sts', region_name=region)
                account_id = sts.get_caller_identity()['Account']
            except Exception:
                pass

            batch_seconds = int(os.getenv('AWS_CW_BATCH_SECONDS', '300'))
            max_events = int(os.getenv('AWS_CW_MAX_EVENTS', '1000'))
            filter_pattern = os.getenv('AWS_CW_FILTER_PATTERN', '')
            stream_prefix = os.getenv('AWS_CW_LOG_STREAM_PREFIX', '')

            ck_key = f"group_{log_group.replace('/', '_')}"
            group_ck = self.ck.get(ck_key) or {}
            next_token = group_ck.get('next_token')
            last_ts_ms = int(group_ck.get('last_ts_ms') or 0)
            newest_ts_ms = last_ts_ms

            if not last_ts_ms and not next_token:
                last_ts_ms = int((time.time() - batch_seconds) * 1000)

            end_ts_ms = int(time.time() * 1000)
            kwargs: Dict[str, Any] = {
                'logGroupName': log_group,
                'startTime': last_ts_ms,
                'endTime': end_ts_ms,
                'limit': min(max_events, 10000),
                'interleaved': True,
            }
            if filter_pattern:
                kwargs['filterPattern'] = filter_pattern
            if stream_prefix:
                kwargs['logStreamNamePrefix'] = stream_prefix
            if next_token:
                kwargs['nextToken'] = next_token

            count = 0
            while True:
                resp = client.filter_log_events(**kwargs)
                for ev in resp.get('events') or []:
                    env = _parse_log_event(ev, log_group, region, account_id)
                    newest_ts_ms = max(newest_ts_ms, ev.get('timestamp', 0))
                    record_yield(self.name, 1)
                    count += 1
                    yield env
                next_token = resp.get('nextToken')
                if next_token and count < max_events:
                    kwargs['nextToken'] = next_token
                else:
                    break

            group_ck['last_ts_ms'] = newest_ts_ms or end_ts_ms
            group_ck.pop('next_token', None)
            self.ck[ck_key] = group_ck
            save_checkpoint(self.name, self.cfg, self.ck)
            logger.debug('CloudWatch %s: fetched %d events', log_group, count)

        except Exception:
            record_error(self.name)
            logger.exception('CloudWatch fetch failed for group: %s', log_group)

    def commit(self, marker: Any) -> None:
        self.ck['marker'] = marker
        save_checkpoint(self.name, self.cfg, self.ck)
