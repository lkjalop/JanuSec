"""Security Hub integration connector skeleton."""
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

class SecurityHubConnector:
    def __init__(self, cfg: AWSConnectorConfig):
        self.cfg = cfg
        self.name = 'securityhub'
        self.ck = load_checkpoint(self.name, cfg)

    def fetch_findings(self) -> Iterable[Dict[str, Any]]:
        try:
            record_fetch(self.name)
            client = boto3_client('securityhub', self.cfg)
            paginator = client.get_paginator('get_findings')
            paginate_kwargs: Dict[str, Any] = {}
            last_seen = self.ck.get('last_ts')
            newest_ts = coerce_unix_ts(last_seen) or 0
            if last_seen:
                # SecurityHub UpdatedAt filter requires ISO 8601 datetime string, not Unix timestamp
                from datetime import datetime, timezone
                _iso = datetime.fromtimestamp(int(last_seen), tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                paginate_kwargs['Filters'] = {
                    'UpdatedAt': [{'Start': _iso}]
                }
            for page in paginator.paginate(**paginate_kwargs):
                for f in page.get('Findings', []) or []:
                    env = canonical_envelope(
                        f,
                        'securityhub',
                        account_id=f.get('AwsAccountId'),
                        region=f.get('Region') or self.cfg.securityhub_region,
                    )
                    resource_items = f.get('Resources') or []
                    env['severity'] = ((f.get('Severity') or {}).get('Label') or (f.get('Severity') or {}).get('Normalized'))
                    env['resource'] = [r.get('Id') for r in resource_items if isinstance(r, dict)]
                    env['title'] = f.get('Title')
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
            logger.exception('securityhub fetch failed')

    def commit(self, marker: Any):
        self.ck['marker'] = marker
        save_checkpoint(self.name, self.cfg, self.ck)
