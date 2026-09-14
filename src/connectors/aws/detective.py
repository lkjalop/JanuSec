"""AWS Detective connector — fetch graph-based investigation findings.

AWS Detective automatically analyses CloudTrail, VPC Flow, GuardDuty and
other sources to build a behaviour graph. This connector fetches:
  - Findings groups (entity-centric suspicious activity clusters)
  - Entity summaries attached to the graph (accounts, roles, EC2 instances)

Required IAM permissions on the role specified in AWSConnectorConfig.role_arn:
  detective:ListGraphs
  detective:ListFindingsGroups
  detective:GetFindingsGroupDetails
  detective:SearchGraph

Environment variables:
  AWS_DETECTIVE_REGION   — Detective graph region (default: same as AWS_REGION)

boto3 is an optional dependency; when absent the connector returns an empty
iterable so the rest of the pipeline continues without AWS credentials.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, Optional

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

# Severity mapping from Detective confidence scores
_CONF_TO_SEVERITY = {
    (0.0, 0.4): 'low',
    (0.4, 0.7): 'medium',
    (0.7, 0.85): 'high',
    (0.85, 1.01): 'critical',
}


def _map_confidence(score: float) -> str:
    for (lo, hi), label in _CONF_TO_SEVERITY.items():
        if lo <= score < hi:
            return label
    return 'medium'


class DetectiveConnector:
    """AWS Detective findings-group connector with checkpoint support."""

    def __init__(self, cfg: AWSConnectorConfig):
        self.cfg = cfg
        self.name = 'detective'
        self.ck = load_checkpoint(self.name, cfg)

    def _get_graph_arn(self, client) -> Optional[str]:
        """Return the first Detective graph ARN available in the region."""
        cached = self.ck.get('graph_arn')
        if cached:
            return cached
        try:
            resp = client.list_graphs(MaxResults=1)
            graphs = resp.get('GraphList') or []
            if graphs:
                arn = graphs[0].get('Arn')
                self.ck['graph_arn'] = arn
                return arn
        except Exception as exc:
            logger.debug('Detective: list_graphs failed: %s', exc)
        return None

    def fetch_findings_groups(self) -> Iterable[Dict[str, Any]]:
        """Yield canonical envelopes for each Detective findings group."""
        try:
            record_fetch(self.name)
            client = boto3_client('detective', self.cfg)
            graph_arn = self._get_graph_arn(client)
            if not graph_arn:
                logger.info('Detective: no graph found in region %s', self.cfg.region)
                return

            last_ts = coerce_unix_ts(self.ck.get('last_ts')) or 0
            newest_ts = last_ts
            paginate_kwargs: Dict[str, Any] = {'GraphArn': graph_arn, 'MaxResults': 100}

            # Paginate findings groups
            next_token: Optional[str] = None
            while True:
                if next_token:
                    paginate_kwargs['NextToken'] = next_token
                try:
                    resp = client.list_findings_groups(**paginate_kwargs)
                except Exception as exc:
                    logger.warning('Detective: list_findings_groups failed: %s', exc)
                    record_error(self.name)
                    return

                for fg in resp.get('FindingsGroupList') or []:
                    created_at = coerce_unix_ts(fg.get('CreatedTime'))
                    if created_at and created_at <= last_ts:
                        continue

                    # Fetch detail for each findings group
                    detail: Dict[str, Any] = {}
                    fg_id = fg.get('Id')
                    if fg_id:
                        try:
                            det_resp = client.get_findings_group_details(
                                GraphArn=graph_arn, Id=fg_id
                            )
                            detail = det_resp.get('FindingsGroup') or {}
                        except Exception as exc:
                            logger.debug('Detective: get_findings_group_details(%s) failed: %s', fg_id, exc)

                    confidence = float(fg.get('Severity') or detail.get('Severity') or 0.5)
                    env = canonical_envelope(
                        {**fg, **detail},
                        'detective',
                        account_id=fg.get('OwnerDetails', {}).get('AccountId'),
                        region=self.cfg.region,
                    )
                    env['severity'] = _map_confidence(confidence)
                    env['confidence'] = confidence
                    env['title'] = fg.get('Description') or detail.get('Description') or 'Detective findings group'
                    env['finding_id'] = fg_id
                    env['entity_count'] = len(detail.get('MemberDetails') or [])
                    # Extract associated entities (accounts, roles, instances)
                    env['related_entities'] = [
                        {
                            'type': m.get('Type'),
                            'id': m.get('Id'),
                            'account_id': m.get('AccountId'),
                        }
                        for m in (detail.get('MemberDetails') or [])[:10]
                        if isinstance(m, dict)
                    ]
                    env['factors'] = ['cloud:detective_findings_group', 'cloud:provider_detection']
                    env['correlation_keys'] = build_correlation_keys(
                        env,
                        extra_values={'account_id': (fg.get('OwnerDetails') or {}).get('AccountId')},
                    )
                    if created_at:
                        env['ts'] = created_at
                        newest_ts = max(newest_ts, created_at)
                    record_yield(self.name, 1)
                    yield env

                next_token = resp.get('NextToken')
                if not next_token:
                    break

            if newest_ts > last_ts:
                self.ck['last_ts'] = newest_ts
                save_checkpoint(self.name, self.cfg, self.ck)

        except Exception:
            record_error(self.name)
            logger.exception('Detective: fetch_findings_groups failed')

    def commit(self, marker: Any) -> None:
        self.ck['marker'] = marker
        save_checkpoint(self.name, self.cfg, self.ck)
