"""User Session Fusion Lane — Microsoft Sentinel UEBA + Fusion equivalent

Correlates cross-source user events within a sliding time window to detect
multi-stage attack scenarios that no single event lane can surface alone.

Built-in scenarios:
  1. Sentinel Fusion: AAD sign-in from new location + SharePoint bulk download
     + inbox rule creation → "Credentials + Collection + Exfiltration" chain
  2. UEBA anomaly stack: new-location login + privileged role assumption +
     off-hours sensitive access in the same session window
  3. Impossible travel: two authentications for the same user from geographically
     distant IPs within a short window (improbable travel time)

Event field contract (best-effort):
  user / user_id / upn — normalized user identifier
  event_name / operation / event_type — audit operation name
  source_ip / ip / src_ip
  country / src_country — ISO 2-letter country code
  timestamp / ts — ISO 8601 or unix float
  data_classification — sensitivity label of accessed resource
  files_accessed / files_downloaded_count — volume indicators
  is_new_location / new_ip — set by upstream UEBA enrichment (optional bool)
"""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from ..evidence_envelope import EvidenceEnvelope

# Window within which events are considered "same session" (seconds)
_SESSION_WINDOW_SECONDS = int(3600 * 4)   # 4 hours (matches Exabeam/Splunk typical)
_TRAVEL_WINDOW_SECONDS = int(3600 * 2)     # 2 hours for impossible travel
# Approx km/h threshold for "impossible" travel (commercial flight max ~900 km/h)
_IMPOSSIBLE_TRAVEL_KMH = 800.0

_SHAREPOINT_OPS = frozenset({
    'sharepointfiledownloaded', 'filedownloaded', 'filesyncdownloadedfull',
    'sharepoint_bulk_download', 'onedrive_bulk_download', 'filesyncdownloadedpartial',
})
_INBOX_RULE_OPS = frozenset({
    'new-inboxrule', 'set-inboxrule', 'new_inbox_rule', 'set_inbox_rule',
    'newinboxrule', 'updateinboxrule', 'new-mailboxrule',
})
_PRIV_ROLE_OPS = frozenset({
    'add member to role', 'addmember', 'assume_role', 'assumerole',
    'iam_self_escalation', 'grant_admin',
})
_AUTH_OPS = frozenset({
    'userloggedin', 'userauthenticated', 'sign-in', 'signin', 'interactivesignin',
    'noninteractivesignin', 'stslogon', 'stslogon_success',
})

# Approximate latitude/longitude of ISO country centroids (subset covering high-risk travel)
_COUNTRY_LATLON: Dict[str, Tuple[float, float]] = {
    'US': (38.0, -97.0), 'GB': (54.4, -2.1), 'DE': (51.2, 10.5),
    'FR': (46.8, 2.3),   'AU': (-25.3, 133.8), 'JP': (35.7, 139.7),
    'CN': (35.9, 104.2), 'RU': (61.5, 105.3), 'KP': (40.3, 127.5),
    'IR': (32.4, 53.7),  'NG': (9.1, 8.7),    'BR': (-14.2, -51.9),
    'IN': (20.6, 78.9),  'CA': (56.1, -106.3),'SG': (1.35, 103.8),
    'MY': (4.2, 101.9),  'NL': (52.1, 5.3),   'SE': (60.1, 18.6),
    'UA': (48.4, 31.2),  'ZA': (-30.6, 22.9),
}


def _country_distance_km(c1: str, c2: str) -> Optional[float]:
    """Haversine distance between two country centroids (km)."""
    try:
        import math
        p1 = _COUNTRY_LATLON.get(c1.upper())
        p2 = _COUNTRY_LATLON.get(c2.upper())
        if not p1 or not p2:
            return None
        lat1, lon1 = math.radians(p1[0]), math.radians(p1[1])
        lat2, lon2 = math.radians(p2[0]), math.radians(p2[1])
        dlat, dlon = lat2 - lat1, lon2 - lon1
        a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
        return 6371.0 * 2 * math.asin(min(1.0, math.sqrt(a)))
    except Exception:
        return None


def _parse_ts(val: Any) -> Optional[float]:
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, str):
        import re
        # unix float string
        try:
            return float(val)
        except ValueError:
            pass
        # ISO 8601 subset: YYYY-MM-DDTHH:MM:SS
        m = re.match(r'(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})', val)
        if m:
            import calendar
            import datetime as _dt
            dt = _dt.datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                              int(m.group(4)), int(m.group(5)), int(m.group(6)),
                              tzinfo=_dt.timezone.utc)
            return float(calendar.timegm(dt.timetuple()))
    return None


class UserSessionFusionLane:
    """Cross-source session fusion for per-user multi-stage attack detection.

    Maintains an in-process ring buffer of recent events per user (keyed by
    normalized user id).  On each new event, the buffer is scanned to detect
    scenario combinations.

    Mirrors Microsoft Sentinel Fusion ML alert types:
      - "Suspicious inbox manipulation rule set following suspicious sign-in"
      - "Mass cloud resource access following sign-in from new location"
      - "Credential access followed by data exfiltration activity"
    """

    name = 'user_session_fusion'

    def __init__(self, window_seconds: int = _SESSION_WINDOW_SECONDS,
                 max_per_user: int = 200):
        self._window = window_seconds
        self._max = max_per_user
        # user_id → deque[(ts, event_dict)]
        self._ring: Dict[str, Deque[Tuple[float, Dict]]] = defaultdict(
            lambda: deque(maxlen=self._max)
        )

    def _trim(self, user: str, now: float) -> None:
        buf = self._ring[user]
        cutoff = now - self._window
        while buf and buf[0][0] < cutoff:
            buf.popleft()

    def _add(self, user: str, ts: float, ev: Dict) -> None:
        self._ring[user].append((ts, ev))

    def _session_events(self, user: str) -> List[Tuple[float, Dict]]:
        return list(self._ring.get(user, []))

    async def run(self, envelope: EvidenceEnvelope, ctx) -> None:
        ev: Dict[str, Any] = getattr(envelope, 'event', {}) or {}
        factors: List[str] = []

        # Resolve user identifier
        user = (
            ev.get('user') or ev.get('user_id') or ev.get('upn') or
            ev.get('userPrincipalName') or ev.get('userName') or ''
        ).lower().strip()
        if not user:
            await asyncio.sleep(0)
            return

        ts_raw = ev.get('timestamp') or ev.get('ts') or time.time()
        ts = _parse_ts(ts_raw) or time.time()

        self._trim(user, ts)
        self._add(user, ts, ev)
        session = self._session_events(user)

        if len(session) < 2:
            await asyncio.sleep(0)
            return

        factors.extend(self._check_fusion_scenarios(session, ev))
        factors.extend(self._check_impossible_travel(session))
        factors.extend(self._check_ueba_anomaly_stack(session))

        if factors:
            envelope.add_emission(self.name, factors,
                                  notes='user-session-fusion', latency_ms=ctx.elapsed_ms())
        await asyncio.sleep(0)

    # ── Scenario 1: Sentinel Fusion – new-location sign-in + bulk download + inbox rule ──
    def _check_fusion_scenarios(self, session: List[Tuple[float, Dict]],
                                 current_ev: Dict) -> List[str]:
        factors: List[str] = []
        try:
            saw_new_loc_signin = False
            saw_bulk_download = False
            saw_inbox_rule = False
            saw_priv_role = False

            for _ts, se in session:
                en = (se.get('event_name') or se.get('operation') or
                      se.get('event_type') or '').lower().replace('-', '_').replace(' ', '_')

                # New-location sign-in: upstream UEBA enrichment sets is_new_location,
                # or country differs from user's baseline (handled separately).
                if en in _AUTH_OPS:
                    if se.get('is_new_location') or se.get('new_ip') or se.get('aad_risky_signin'):
                        saw_new_loc_signin = True
                    # Also flag if country is a high-risk nation
                    country = (se.get('country') or se.get('src_country') or '').upper()
                    if country in ('CN', 'RU', 'KP', 'IR'):
                        saw_new_loc_signin = True

                # Bulk SharePoint / OneDrive download
                if en in _SHAREPOINT_OPS:
                    saw_bulk_download = True
                files_count = se.get('files_downloaded_count') or se.get('files_accessed') or 0
                if isinstance(files_count, (int, float)) and files_count >= 20:
                    saw_bulk_download = True

                # Inbox rule creation / modification
                if en in _INBOX_RULE_OPS or 'inboxrule' in en:
                    saw_inbox_rule = True

                # Privileged role assignment / assumption
                if en in _PRIV_ROLE_OPS or 'admin' in en and 'assign' in en:
                    saw_priv_role = True

            # Sentinel Fusion scenario: sign-in from new location → bulk download
            if saw_new_loc_signin and saw_bulk_download:
                factors.append('fusion:new_location_signin_bulk_download')
                factors.append('fusion:T1530_data_from_cloud_storage')

            # Sentinel Fusion scenario: inbox rule + bulk download (Collection + Exfil)
            if saw_inbox_rule and saw_bulk_download:
                factors.append('fusion:inbox_rule_and_bulk_download')
                factors.append('fusion:T1114.003_plus_T1530')

            # Full three-stage Sentinel scenario
            if saw_new_loc_signin and saw_inbox_rule and saw_bulk_download:
                factors.append('fusion:sentinel_credential_collection_exfil')
                factors.append('fusion:high_confidence_multi_stage')

            # New-location sign-in + privileged role assumption
            if saw_new_loc_signin and saw_priv_role:
                factors.append('fusion:new_location_priv_escalation')

        except Exception:
            pass
        return factors

    # ── Scenario 2: Impossible Travel ──────────────────────────────────────────────────
    def _check_impossible_travel(self, session: List[Tuple[float, Dict]]) -> List[str]:
        factors: List[str] = []
        try:
            travel_window = _TRAVEL_WINDOW_SECONDS
            # Collect (ts, country) tuples for auth events only
            auth_events: List[Tuple[float, str, str]] = []
            for ts, se in session:
                en = (se.get('event_name') or se.get('operation') or '').lower()
                is_auth = any(a in en for a in ('login', 'signin', 'logon', 'authenticated'))
                if is_auth:
                    c = (se.get('country') or se.get('src_country') or '').upper()
                    ip = se.get('source_ip') or se.get('ip') or se.get('src_ip') or ''
                    if c:
                        auth_events.append((ts, c, ip))
            # Check consecutive auth pairs
            for i in range(len(auth_events) - 1):
                ts1, c1, _ = auth_events[i]
                ts2, c2, _ = auth_events[i + 1]
                if c1 == c2:
                    continue
                dt = abs(ts2 - ts1)
                if dt <= 0 or dt > travel_window:
                    continue
                dist = _country_distance_km(c1, c2)
                if dist is None:
                    continue
                required_speed = dist / (dt / 3600.0)  # km/h
                if required_speed > _IMPOSSIBLE_TRAVEL_KMH:
                    factors.append('fusion:impossible_travel')
                    factors.append(f'fusion:impossible_travel_{c1}_to_{c2}')
                    break
        except Exception:
            pass
        return factors

    # ── Scenario 3: UEBA anomaly stack ─────────────────────────────────────────────────
    def _check_ueba_anomaly_stack(self, session: List[Tuple[float, Dict]]) -> List[str]:
        """Stack ≥ 3 low-confidence anomalies into a higher-confidence combined signal.

        Mimics Sentinel UEBA entity-scoring: 3+ individual anomalies on the same
        user within the session window triggers a combined high-priority alert.
        """
        factors: List[str] = []
        try:
            anomaly_count = 0
            anomaly_types: Set[str] = set()
            for _ts, se in session:
                # Count UEBA signals already tagged by upstream lanes
                for key in se:
                    if 'anomaly' in key.lower() and se[key]:
                        anomaly_count += 1
                        anomaly_types.add(key)
                # Off-hours sensitive access
                hour = None
                ts_r = se.get('timestamp') or se.get('ts')
                if ts_r:
                    t = _parse_ts(ts_r)
                    if t:
                        import datetime as _dt
                        hour = _dt.datetime.utcfromtimestamp(t).hour
                if hour is not None and (hour >= 22 or hour < 6):
                    if se.get('data_classification') in (
                        'confidential', 'restricted', 'pii', 'secret'
                    ):
                        anomaly_types.add('off_hours_sensitive')
                        anomaly_count += 1
                # Country-based risk
                country = (se.get('country') or se.get('src_country') or '').upper()
                if country in ('CN', 'RU', 'KP', 'IR'):
                    anomaly_types.add('high_risk_country')
                    anomaly_count += 1

            if anomaly_count >= 3:
                factors.append('fusion:ueba_anomaly_stack_3plus')
                if anomaly_count >= 5:
                    factors.append('fusion:ueba_anomaly_stack_5plus')
        except Exception:
            pass
        return factors


LANE = UserSessionFusionLane()
