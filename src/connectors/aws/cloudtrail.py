"""CloudTrail connector: incremental fetcher for management + data events.

Uses S3 or LookupEvents depending on deployment. Supports checkpointing and
backfill via stored lastSeen timestamp / S3 object marker.
"""
from __future__ import annotations

import time
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


class CloudTrailConnector:
    def __init__(self, cfg: AWSConnectorConfig):
        self.cfg = cfg
        self.name = 'cloudtrail'
        self.ck = load_checkpoint(self.name, cfg)

    def fetch_events(self, start_time: float | None = None) -> Iterable[Dict[str, Any]]:
        """Fetch CloudTrail events since `start_time`.

        For demo: prefer LookupEvents via CloudTrail API; production can read
        S3 log files for higher throughput and full event detail.
        """
        record_fetch(self.name)
        client = boto3_client('cloudtrail', self.cfg)
        if start_time is None:
            start_time = self.ck.get('last_ts')
        start_time = start_time or (int(time.time()) - 3600)

        try:
            paginator = client.get_paginator('lookup_events')
            kwargs: Dict[str, Any] = {}
            start_dt = as_utc_datetime(start_time)
            if start_dt is not None:
                kwargs['StartTime'] = start_dt
            newest_ts = coerce_unix_ts(start_time) or 0
            for page in paginator.paginate(**kwargs):
                    for ev in page.get('Events', []) or []:
                        raw = ev
                        ct_raw = ev.get('CloudTrailEvent')
                        if isinstance(ct_raw, str) and ct_raw.strip():
                            try:
                                import json
                                raw = json.loads(ct_raw)
                            except Exception:
                                raw = ev
                        account_id = raw.get('recipientAccountId') or ev.get('AccountId')
                        region = raw.get('awsRegion') or self.cfg.region
                        envelope = canonical_envelope(raw, 'cloudtrail', account_id=account_id, region=region)
                        ev_ts = coerce_unix_ts(raw.get('eventTime') or ev.get('EventTime'))
                        identity = raw.get('userIdentity') or {}
                        source_ip = raw.get('sourceIPAddress')
                        actor = identity.get('arn') or identity.get('userName') or identity.get('principalId')
                        resource_values = raw.get('resources') or []
                        envelope['actor'] = actor
                        envelope['ip'] = source_ip
                        envelope['event_name'] = raw.get('eventName')
                        envelope['resource'] = [r.get('ARN') or r.get('ResourceName') for r in resource_values if isinstance(r, dict)]
                        envelope['correlation_keys'] = build_correlation_keys(
                            envelope,
                            extra_values={'source_ip': source_ip, 'account_id': account_id, 'resource': envelope.get('resource')},
                        )
                        if ev_ts:
                            envelope['ts'] = ev_ts
                            newest_ts = max(newest_ts, ev_ts)
                        record_yield(self.name, 1)
                        yield envelope
            if newest_ts:
                self.commit(newest_ts)
        except Exception:
            record_error(self.name)
            logger.exception('cloudtrail fetch failed')

    def commit(self, last_ts: float):
        self.ck['last_ts'] = int(last_ts)
        save_checkpoint(self.name, self.cfg, self.ck)
