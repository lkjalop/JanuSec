"""GuardDuty findings connector — fetch findings and normalize."""
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
    coerce_unix_ts,
)
from src.connectors.correlation_keys import build_correlation_keys

logger = logging.getLogger(__name__)

class GuardDutyConnector:
    def __init__(self, cfg: AWSConnectorConfig):
        self.cfg = cfg
        self.name = 'guardduty'
        self.ck = load_checkpoint(self.name, cfg)

    def fetch_findings(self) -> Iterable[Dict[str, Any]]:
        try:
            record_fetch(self.name)
            client = boto3_client('guardduty', self.cfg)
            detector_id = self.ck.get('detector_id')
            if not detector_id:
                # List detectors
                dets = client.list_detectors()
                detector_id = (dets.get('DetectorIds') or [None])[0]
                self.ck['detector_id'] = detector_id
            if detector_id:
                newest_ts = coerce_unix_ts(self.ck.get('last_ts')) or 0
                paginator = client.get_paginator('list_findings')
                paginate_kwargs: Dict[str, Any] = {'DetectorId': detector_id}
                last_seen = self.ck.get('last_ts')
                if last_seen:
                    # GuardDuty updatedAt criterion uses Unix epoch milliseconds (int, not str/list)
                    paginate_kwargs['FindingCriteria'] = {
                        'Criterion': {
                            'updatedAt': {
                                'Gte': int(last_seen) * 1000
                            }
                        }
                    }
                for page in paginator.paginate(**paginate_kwargs):
                    ids = page.get('FindingIds') or []
                    if not ids:
                        continue
                    resp = client.get_findings(DetectorId=detector_id, FindingIds=ids)
                    for f in resp.get('Findings', []) or []:
                        region = f.get('Region') or self.cfg.region
                        env = canonical_envelope(f, 'guardduty', account_id=f.get('AwsAccountId'), region=region)
                        env['severity'] = f.get('Severity')
                        env['title'] = f.get('Title') or f.get('Type')
                        env['resource'] = ((f.get('Resource') or {}).get('InstanceDetails') or {}).get('InstanceId') or (f.get('Resource') or {}).get('ResourceType')
                        env['ip'] = ((f.get('Service') or {}).get('Action') or {}).get('NetworkConnectionAction', {}).get('RemoteIpDetails', {}).get('IpAddressV4')
                        env['correlation_keys'] = build_correlation_keys(env, extra_values={'account_id': f.get('AwsAccountId')})
                        finding_ts = coerce_unix_ts(f.get('UpdatedAt') or f.get('CreatedAt'))
                        if finding_ts:
                            env['ts'] = finding_ts
                            newest_ts = max(newest_ts, finding_ts)
                        record_yield(self.name, 1)
                        yield env
                if newest_ts:
                    self.ck['last_ts'] = newest_ts
                    save_checkpoint(self.name, self.cfg, self.ck)
        except Exception:
            record_error(self.name)
            logger.exception('guardduty fetch failed')

    def commit(self, marker: Any):
        self.ck['marker'] = marker
        save_checkpoint(self.name, self.cfg, self.ck)
