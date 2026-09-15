"""VPC Flow Logs connector — incremental fetch and parser.

Supports S3-backed delivery or CloudWatch Logs subscription pulls.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Iterable

from .base import (
    AWSConnectorConfig,
    boto3_client,
    load_checkpoint,
    save_checkpoint,
    canonical_envelope,
    record_fetch,
    record_error,
    record_yield,
    as_utc_datetime,
    coerce_unix_ts,
)
from src.connectors.correlation_keys import build_correlation_keys

logger = logging.getLogger(__name__)

class VPCFlowConnector:
    def __init__(self, cfg: AWSConnectorConfig):
        self.cfg = cfg
        self.name = 'vpcflow'
        self.ck = load_checkpoint(self.name, cfg)

    def fetch_records(self) -> Iterable[Dict[str, Any]]:
        record_fetch(self.name)
        if not self.cfg.log_group_name:
            return
        try:
            client = boto3_client('logs', self.cfg)
            kwargs: Dict[str, Any] = {
                'logGroupName': self.cfg.log_group_name,
                'limit': 1000,
            }
            start_dt = as_utc_datetime(self.ck.get('last_ts') or (int(__import__('time').time()) - 3600))
            if start_dt is not None:
                kwargs['startTime'] = int(start_dt.timestamp() * 1000)
            next_token = self.ck.get('next_token')
            if next_token:
                kwargs['nextToken'] = next_token
            newest_ts = coerce_unix_ts(self.ck.get('last_ts')) or 0
            while True:
                page = client.filter_log_events(**kwargs)
                for record in page.get('events', []) or []:
                    parsed = self._parse_record(record)
                    if parsed is None:
                        continue
                    env = canonical_envelope(
                        parsed,
                        'vpcflow',
                        account_id=parsed.get('account_id'),
                        region=self.cfg.region,
                    )
                    env['src_ip'] = parsed.get('src_ip')
                    env['dst_ip'] = parsed.get('dst_ip')
                    env['resource'] = parsed.get('interface_id')
                    env['correlation_keys'] = build_correlation_keys(parsed)
                    ts = parsed.get('ts')
                    if ts:
                        env['ts'] = ts
                        newest_ts = max(newest_ts, int(ts))
                    record_yield(self.name, 1)
                    yield env
                token = page.get('nextToken')
                if not token or token == kwargs.get('nextToken'):
                    break
                kwargs['nextToken'] = token
            self.ck['next_token'] = kwargs.get('nextToken')
            if newest_ts:
                self.ck['last_ts'] = newest_ts
            save_checkpoint(self.name, self.cfg, self.ck)
        except Exception:
            record_error(self.name)
            logger.exception('vpcflow fetch failed')

    def commit(self, marker: Any):
        self.ck['marker'] = marker
        save_checkpoint(self.name, self.cfg, self.ck)

    @staticmethod
    def _parse_record(record: Dict[str, Any]) -> Dict[str, Any] | None:
        message = record.get('message')
        if not isinstance(message, str) or not message.strip():
            return None
        parts = message.split()
        if len(parts) < 14:
            return {
                'message': message,
                'ts': coerce_unix_ts(record.get('timestamp')),
                'raw_record': record,
            }
        version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes_count, start, end, action, log_status = parts[:14]
        return {
            'version': version,
            'account_id': account_id,
            'interface_id': interface_id,
            'src_ip': srcaddr,
            'dst_ip': dstaddr,
            'src_port': int(srcport) if srcport.isdigit() else srcport,
            'dst_port': int(dstport) if dstport.isdigit() else dstport,
            'protocol': protocol,
            'packets': int(packets) if packets.isdigit() else packets,
            'bytes': int(bytes_count) if bytes_count.isdigit() else bytes_count,
            'flow_start': int(start) if start.isdigit() else start,
            'flow_end': int(end) if end.isdigit() else end,
            'action': action,
            'log_status': log_status,
            'ts': coerce_unix_ts(record.get('timestamp')) or (int(end) if str(end).isdigit() else None),
            'raw_record': record,
        }
