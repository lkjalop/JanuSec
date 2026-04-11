"""CrowdStrike Falcon connector — detections, incidents, and events via Falcon API.

Uses the CrowdStrike OAuth2 client_credentials flow (PKCE not required for server flows).

Environment variables
---------------------
CS_FALCON_CLIENT_ID     : OAuth2 client ID (required)
CS_FALCON_CLIENT_SECRET : OAuth2 client secret (required)
CS_FALCON_BASE_URL      : Base URL (default: https://api.crowdstrike.com)
CS_FALCON_CLOUD         : 'us-1', 'us-2', 'eu-1', 'us-gov-1' — sets base URL automatically
CS_FALCON_SEVERITY_MIN  : Minimum severity to fetch (default: 2 = Medium)
CS_FALCON_MAX_PER_POLL  : Max detections per poll (default: 500)
CS_FALCON_EVENTS_ENABLED: '1' to stream raw Falcon events via Event Streams API (default: '0')
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

_CLOUD_URLS = {
    'us-1': 'https://api.crowdstrike.com',
    'us-2': 'https://api.us-2.crowdstrike.com',
    'eu-1': 'https://api.eu-1.crowdstrike.com',
    'us-gov-1': 'https://api.laggar.gcw.crowdstrike.com',
}

_CHECKPOINT_PATH = 'data/checkpoints/crowdstrike.checkpoint.json'


def _base_url() -> str:
    cloud = os.getenv('CS_FALCON_CLOUD', 'us-1').lower()
    return os.getenv('CS_FALCON_BASE_URL', None) or _CLOUD_URLS.get(cloud, _CLOUD_URLS['us-1'])


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


class _FalconClient:
    """Minimal OAuth2 + REST client for the Falcon API."""

    def __init__(self, client_id: str, client_secret: str, base_url: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url.rstrip('/')
        self._token: Optional[str] = None
        self._token_expiry: float = 0.0

    def _ensure_token(self) -> None:
        if self._token and time.time() < self._token_expiry - 60:
            return
        import urllib.request, urllib.parse
        url = f"{self.base_url}/oauth2/token"
        data = urllib.parse.urlencode({
            'client_id': self.client_id,
            'client_secret': self.client_secret,
        }).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read())
        self._token = body['access_token']
        self._token_expiry = time.time() + int(body.get('expires_in', 1800))

    def get(self, path: str, params: Optional[Dict] = None) -> dict:
        self._ensure_token()
        import urllib.request, urllib.parse
        url = f"{self.base_url}{path}"
        if params:
            url += '?' + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={'Authorization': f'Bearer {self._token}'})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())

    def post(self, path: str, body: dict) -> dict:
        self._ensure_token()
        import urllib.request
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={
                'Authorization': f'Bearer {self._token}',
                'Content-Type': 'application/json',
            },
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())


def _normalize_detection(d: Dict[str, Any]) -> Dict[str, Any]:
    """Map a Falcon detection dict to the canonical event envelope."""
    behaviors = d.get('behaviors') or [{}]
    b = behaviors[0] if behaviors else {}
    device = d.get('device') or {}
    sev = int(d.get('max_severity') or b.get('severity') or 0)
    sev_label = {1: 'LOW', 2: 'MEDIUM', 3: 'HIGH', 4: 'CRITICAL'}.get(sev, 'INFO')
    ts_raw = d.get('first_behavior') or d.get('created_timestamp', '')
    ts = time.time()
    try:
        from datetime import datetime
        ts = datetime.fromisoformat(str(ts_raw).replace('Z', '+00:00')).timestamp()
    except Exception:
        pass

    env: Dict[str, Any] = {
        'ingest_source': 'crowdstrike',
        'source_type': 'edr',
        'ts': ts,
        'event_id': d.get('detection_id', ''),
        'host': device.get('hostname'),
        'host_ip': device.get('local_ip'),
        'external_ip': device.get('external_ip'),
        'platform': device.get('platform_name'),
        'os_version': device.get('os_version'),
        'agent_id': device.get('device_id'),
        'severity': sev_label,
        'tactic': b.get('tactic'),
        'technique': b.get('technique'),
        'technique_id': b.get('technique_id'),
        'process': b.get('filename') or b.get('parent_details', {}).get('filename'),
        'cmdline': b.get('cmdline'),
        'user': b.get('user_name'),
        'sha256': b.get('sha256'),
        'file_path': b.get('filepath'),
        'status': d.get('status'),
        'confidence': int(d.get('max_confidence') or 0),
        'detection_id': d.get('detection_id'),
        'raw': d,
    }

    # MITRE tags
    mitre_tags: List[str] = []
    if b.get('technique_id'):
        mitre_tags.append(b['technique_id'])
    env['mitre_tags'] = mitre_tags

    # Factors
    factors: List[str] = [f'crowdstrike:detection_{sev_label.lower()}']
    if b.get('technique_id'):
        factors.append(f"mitre:{b['technique_id']}")
    env['factors'] = factors

    try:
        from src.connectors.correlation_keys import build_correlation_keys
        env['correlation_keys'] = build_correlation_keys(env)
    except Exception:
        env['correlation_keys'] = {}

    return env


class CrowdStrikeConnector:
    """CrowdStrike Falcon detections + incidents connector."""

    def __init__(self) -> None:
        client_id = os.getenv('CS_FALCON_CLIENT_ID', '')
        client_secret = os.getenv('CS_FALCON_CLIENT_SECRET', '')
        if not client_id or not client_secret:
            raise RuntimeError(
                'CS_FALCON_CLIENT_ID and CS_FALCON_CLIENT_SECRET must be set'
            )
        self._client = _FalconClient(client_id, client_secret, _base_url())
        self.ck = _load_ck()
        self.severity_min = int(os.getenv('CS_FALCON_SEVERITY_MIN', '2'))
        self.max_per_poll = int(os.getenv('CS_FALCON_MAX_PER_POLL', '500'))

    def fetch_detections(self) -> Iterable[Dict[str, Any]]:
        """Yield normalized detection events since last checkpoint."""
        try:
            last_ts = self.ck.get('last_detection_ts', '')
            filter_str = f"max_severity:>={self.severity_min}"
            if last_ts:
                filter_str += f"+first_behavior:>'{last_ts}'"

            # Step 1: List detection IDs
            resp = self._client.get('/detects/queries/detects/v1', params={
                'filter': filter_str,
                'limit': self.max_per_poll,
                'sort': 'first_behavior.asc',
            })
            ids = resp.get('resources') or []
            if not ids:
                return

            # Step 2: Fetch full detection details in batches of 100
            newest_ts = last_ts
            for i in range(0, len(ids), 100):
                batch = ids[i:i + 100]
                details_resp = self._client.post('/detects/entities/summaries/GET/v1', {'ids': batch})
                for d in details_resp.get('resources') or []:
                    env = _normalize_detection(d)
                    ts_raw = d.get('first_behavior', '')
                    if ts_raw and (not newest_ts or ts_raw > newest_ts):
                        newest_ts = ts_raw
                    yield env

            if newest_ts:
                self.ck['last_detection_ts'] = newest_ts
                _save_ck(self.ck)

        except Exception:
            logger.exception('CrowdStrike: fetch_detections failed')

    def fetch_incidents(self) -> Iterable[Dict[str, Any]]:
        """Yield incidents (adversary campaign-level events)."""
        try:
            resp = self._client.get('/incidents/queries/incidents/v1', params={
                'sort': 'start.asc',
                'limit': 100,
            })
            ids = resp.get('resources') or []
            if not ids:
                return
            details = self._client.post('/incidents/entities/incidents/GET/v1', {'ids': ids})
            for inc in details.get('resources') or []:
                yield {
                    'ingest_source': 'crowdstrike',
                    'source_type': 'edr',
                    'ts': time.time(),
                    'event_id': inc.get('incident_id'),
                    'severity': inc.get('severity_name', 'MEDIUM'),
                    'status': inc.get('status'),
                    'tactics': inc.get('tactics') or [],
                    'techniques': inc.get('techniques') or [],
                    'hosts': [h.get('hostname') for h in (inc.get('hosts') or [])],
                    'description': inc.get('description', '')[:500],
                    'factors': ['crowdstrike:incident'],
                    'raw': inc,
                }
        except Exception:
            logger.exception('CrowdStrike: fetch_incidents failed')
