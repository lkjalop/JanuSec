"""SentinelOne connector — threats and alerts via SentinelOne Management API v2.1.

Environment variables
---------------------
S1_MGMT_URL         : Management console URL, e.g. https://usea1.sentinelone.net (required)
S1_API_TOKEN        : API token with Viewer scope (required)
S1_SITE_IDS         : Comma-separated site IDs to filter (optional)
S1_ACCOUNT_IDS      : Comma-separated account IDs to filter (optional)
S1_SEVERITY_MIN     : Minimum severity: 'low', 'medium', 'high', 'critical' (default: medium)
S1_MAX_PER_POLL     : Maximum threats per poll (default: 500)
"""
from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

_CHECKPOINT_PATH = 'data/checkpoints/sentinelone.checkpoint.json'
_SEVERITY_ORDER = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def _load_ck() -> dict:
    try:
        if os.path.exists(_CHECKPOINT_PATH):
            with open(_CHECKPOINT_PATH, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_ck(data: dict) -> None:
    os.makedirs(os.path.dirname(_CHECKPOINT_PATH), exist_ok=True)
    tmp = _CHECKPOINT_PATH + '.tmp'
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f)
        os.replace(tmp, _CHECKPOINT_PATH)
    except Exception:
        pass


class _S1Client:
    """Minimal REST client for SentinelOne Management API v2.1."""

    def __init__(self, mgmt_url: str, api_token: str) -> None:
        self.base = mgmt_url.rstrip('/')
        self.headers = {
            'Authorization': f'ApiToken {api_token}',
            'Content-Type': 'application/json',
        }

    def get(self, path: str, params: Optional[Dict] = None) -> dict:
        import urllib.request, urllib.parse
        url = f"{self.base}{path}"
        if params:
            url += '?' + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        req = urllib.request.Request(url, headers=self.headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())


def _normalize_threat(t: Dict[str, Any]) -> Dict[str, Any]:
    """Map a SentinelOne threat dict to the canonical event envelope."""
    agent = t.get('agentDetectionInfo') or {}
    indicators = t.get('indicators') or []
    threat_info = t.get('threatInfo') or {}

    sev = str(threat_info.get('confidenceLevel') or t.get('rank') or 'medium').lower()
    sev_label = {'low': 'LOW', 'medium': 'MEDIUM', 'high': 'HIGH', 'critical': 'CRITICAL'}.get(sev, 'MEDIUM')

    ts_raw = threat_info.get('createdAt') or t.get('createdAt', '')
    ts = time.time()
    try:
        ts = datetime.fromisoformat(str(ts_raw).replace('Z', '+00:00')).timestamp()
    except Exception:
        pass

    mitre_tags: List[str] = []
    for ind in indicators:
        for tac in ind.get('tactics') or []:
            for tech in tac.get('techniques') or []:
                tid = tech.get('id')
                if tid:
                    mitre_tags.append(tid)

    env: Dict[str, Any] = {
        'ingest_source': 'sentinelone',
        'source_type': 'edr',
        'ts': ts,
        'event_id': t.get('id', ''),
        'host': agent.get('agentComputerName'),
        'host_ip': agent.get('agentIpV4'),
        'platform': agent.get('agentOsName'),
        'os_version': agent.get('agentOsRevision'),
        'agent_id': agent.get('agentId'),
        'severity': sev_label,
        'process': threat_info.get('originatorProcess') or threat_info.get('threatName'),
        'file_path': threat_info.get('filePath'),
        'sha256': threat_info.get('sha256'),
        'sha1': threat_info.get('sha1'),
        'cmdline': (t.get('processInfo') or {}).get('commandLine'),
        'user': agent.get('agentLastLoggedInUserName'),
        'classification': threat_info.get('classification'),
        'classification_source': threat_info.get('classificationSource'),
        'confidence': threat_info.get('confidenceLevel'),
        'mitre_tags': mitre_tags[:10],
        'indicators_count': len(indicators),
        'threat_id': t.get('id'),
        'raw': t,
    }

    factors: List[str] = [f'sentinelone:threat_{sev_label.lower()}']
    for tid in mitre_tags[:5]:
        factors.append(f'mitre:{tid}')
    env['factors'] = factors

    try:
        from src.connectors.correlation_keys import build_correlation_keys
        env['correlation_keys'] = build_correlation_keys(env)
    except Exception:
        env['correlation_keys'] = {}

    return env


class SentinelOneConnector:
    """SentinelOne threats connector."""

    def __init__(self) -> None:
        self.mgmt_url = os.getenv('S1_MGMT_URL', '')
        api_token = os.getenv('S1_API_TOKEN', '')
        if not self.mgmt_url or not api_token:
            raise RuntimeError('S1_MGMT_URL and S1_API_TOKEN must be set')
        self._client = _S1Client(self.mgmt_url, api_token)
        self.ck = _load_ck()
        self.severity_min = os.getenv('S1_SEVERITY_MIN', 'medium').lower()
        self.max_per_poll = int(os.getenv('S1_MAX_PER_POLL', '500'))
        self._site_ids = [s.strip() for s in os.getenv('S1_SITE_IDS', '').split(',') if s.strip()]
        self._account_ids = [s.strip() for s in os.getenv('S1_ACCOUNT_IDS', '').split(',') if s.strip()]

    def fetch_threats(self) -> Iterable[Dict[str, Any]]:
        """Yield normalized threat events since last checkpoint."""
        try:
            params: Dict[str, Any] = {
                'limit': self.max_per_poll,
                'sortBy': 'createdAt',
                'sortOrder': 'asc',
                'resolved': 'false',
            }
            if self._site_ids:
                params['siteIds'] = ','.join(self._site_ids)
            if self._account_ids:
                params['accountIds'] = ','.join(self._account_ids)
            last_ts = self.ck.get('last_threat_ts')
            if last_ts:
                params['createdAt__gt'] = last_ts

            newest_ts: Optional[str] = last_ts
            cursor: Optional[str] = None
            count = 0

            while True:
                if cursor:
                    params['cursor'] = cursor
                resp = self._client.get('/web/api/v2.1/threats', params=params)
                threats = resp.get('data') or []
                for t in threats:
                    sev = str((t.get('threatInfo') or {}).get('confidenceLevel') or 'medium').lower()
                    if _SEVERITY_ORDER.get(sev, 0) < _SEVERITY_ORDER.get(self.severity_min, 1):
                        continue
                    env = _normalize_threat(t)
                    created = (t.get('threatInfo') or {}).get('createdAt', '')
                    if created and (not newest_ts or created > newest_ts):
                        newest_ts = created
                    count += 1
                    yield env

                pagination = resp.get('pagination') or {}
                cursor = pagination.get('nextCursor')
                if not cursor or count >= self.max_per_poll:
                    break

            if newest_ts:
                self.ck['last_threat_ts'] = newest_ts
                _save_ck(self.ck)
            logger.debug('SentinelOne: fetched %d threats', count)

        except Exception:
            logger.exception('SentinelOne: fetch_threats failed')

    def fetch_alerts(self) -> Iterable[Dict[str, Any]]:
        """Yield STAR-rule and policy alert events."""
        try:
            resp = self._client.get('/web/api/v2.1/alerts', params={
                'limit': 200,
                'sortBy': 'createdAt',
                'sortOrder': 'desc',
            })
            for alert in resp.get('data') or []:
                yield {
                    'ingest_source': 'sentinelone',
                    'source_type': 'edr',
                    'ts': time.time(),
                    'event_id': alert.get('id'),
                    'host': (alert.get('agentDetectionInfo') or {}).get('agentComputerName'),
                    'severity': str(alert.get('severity') or 'medium').upper(),
                    'rule_name': (alert.get('ruleInfo') or {}).get('name'),
                    'description': str(alert.get('description') or '')[:500],
                    'factors': ['sentinelone:alert'],
                    'raw': alert,
                }
        except Exception:
            logger.exception('SentinelOne: fetch_alerts failed')
