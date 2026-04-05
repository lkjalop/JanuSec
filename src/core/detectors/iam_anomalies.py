from __future__ import annotations

from typing import Any, Dict, List, Tuple
import time

def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    try:
        from math import radians, sin, cos, asin, sqrt
        R = 6371.0
        dlat = radians(lat2 - lat1)
        dlon = radians(lon2 - lon1)
        a = sin(dlat/2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon/2)**2
        c = 2 * asin(sqrt(a))
        return R * c
    except Exception:
        return 0.0

def _extract_login_records(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    recs = []
    for ev in events or []:
        try:
            src = (ev.get('source_platform') or ev.get('source') or '').lower()
            # Consider IdP and remote access sign-in events
            if any(s in src for s in ('okta','azuread','googleidp','auth0','vpn','rdp','remote')) or ev.get('type') in {'login','signin'}:
                user = ev.get('user') or ev.get('username') or ev.get('principal')
                ts = float(ev.get('timestamp') or ev.get('ts') or time.time())
                geo = ev.get('geo') or {}
                lat = geo.get('lat') or geo.get('latitude')
                lon = geo.get('lon') or geo.get('longitude')
                ip = ev.get('ip') or ev.get('src_ip') or ev.get('ip_src')
                if user and (lat is not None and lon is not None):
                    recs.append({'user': str(user), 'ts': ts, 'lat': float(lat), 'lon': float(lon), 'ip': ip})
        except Exception:
            continue
    return recs

def detect_iam_abuse(runtime) -> List[Dict[str, Any]]:
    """Detect lightweight IAM anomalies: impossible travel and MFA disable→login.

    Returns factor dicts suitable for session summaries.
    """
    out: List[Dict[str, Any]] = []
    try:
        events = list(getattr(runtime, 'sanitized_events', []) or [])
    except Exception:
        events = []

    # Impossible travel: successive logins implying > 900 km/h
    try:
        logins = _extract_login_records(events)
        by_user: Dict[str, List[Dict[str, Any]]] = {}
        for r in logins:
            by_user.setdefault(r['user'], []).append(r)
        for user, arr in by_user.items():
            arr.sort(key=lambda x: x['ts'])
            for i in range(1, len(arr)):
                a, b = arr[i-1], arr[i]
                dt = max(1.0, float(b['ts'] - a['ts']))
                dist = _haversine_km(a['lat'], a['lon'], b['lat'], b['lon'])
                speed_kmh = (dist / dt) * 3600.0
                if speed_kmh >= float(900.0):
                    out.append({
                        'factor': 'iam_impossible_travel',
                        'user': user,
                        'from_geo': {'lat': a['lat'], 'lon': a['lon'], 'ip': a.get('ip')},
                        'to_geo': {'lat': b['lat'], 'lon': b['lon'], 'ip': b.get('ip')},
                        'speed_kmh': round(speed_kmh, 1),
                        'score': 0.65,
                        'reason': f'Login hops imply {speed_kmh:.1f} km/h (>900)',
                        'tags': ['STRIDE:spoofing','ATTACK:T1078']
                    })
                    break
    except Exception:
        pass

    # MFA disable followed by login success within short window
    try:
        mfa_disable_events: List[Tuple[str, float]] = []
        login_success: Dict[str, float] = {}
        for ev in events:
            try:
                user = ev.get('user') or ev.get('username') or ev.get('principal')
                ts = float(ev.get('timestamp') or ev.get('ts') or time.time())
                act = (ev.get('action') or '').lower()
                if user:
                    if ('disable_mfa' in act) or (str(ev.get('mfa_state_change') or '').lower() in {'disable','disabled'}):
                        mfa_disable_events.append((str(user), ts))
                    # treat verdict/factors indicating login success
                    if (ev.get('verdict') or '').upper() in {'ALLOW','SUCCESS'} or bool(ev.get('login_success')):
                        login_success[str(user)] = ts
            except Exception:
                continue
        for user, ts0 in mfa_disable_events:
            ts1 = login_success.get(user)
            if ts1 and (0.0 < (ts1 - ts0) <= 1800.0):  # within 30 minutes
                out.append({
                    'factor': 'iam_mfa_bypass',
                    'user': user,
                    'window_seconds': round(ts1 - ts0, 1),
                    'score': 0.6,
                    'reason': 'MFA disabled followed by login success within 30m',
                    'tags': ['ATTACK:T1556','STRIDE:elevation']
                })
    except Exception:
        pass

    return out

__all__ = ['detect_iam_abuse']
