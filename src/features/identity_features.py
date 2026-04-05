from __future__ import annotations

import time
from typing import Any, Dict


def _now_hour(ts: float | None) -> int:
    try:
        if ts is None:
            ts = time.time()
        return int(time.localtime(float(ts)).tm_hour)
    except Exception:
        return int(time.localtime().tm_hour)


def extract_features(ev: Dict[str, Any]) -> Dict[str, Any]:
    """Derive lightweight identity features from an event.

    Returns keys:
      - hour: int (0..23)
      - lateral_flag: bool
      - priv_escalation_flag: bool
      - cloud_pivot_flag: bool
    """
    ts = ev.get('ts') or ev.get('timestamp')
    hour = _now_hour(ts if isinstance(ts, (int, float)) else None)

    action = str(ev.get('action') or '').lower()
    groups = [str(g).lower() for g in (ev.get('groups') or []) if g]
    new_role = str(ev.get('new_role') or ev.get('target_role') or '').lower()

    src_h = ev.get('src_host') or ev.get('source_host')
    dst_h = ev.get('dest_host') or ev.get('host') or ev.get('hostname')
    etype = str(ev.get('event_type') or '').lower()
    login_type = str(ev.get('login_type') or '').lower()

    lateral = bool(
        (src_h and dst_h and str(src_h) != str(dst_h)) or
        ('remote' in login_type or 'interactive' in login_type) or
        (etype in {'login','auth','authentication'} and src_h and dst_h and str(src_h) != str(dst_h))
    )
    priv = bool(
        any(x in action for x in ('su', 'runas', 'assume_role')) or
        any('admin' in g or 'sudo' in g for g in groups) or
        ('admin' in new_role)
    )
    principal = str(ev.get('principal_arn') or ev.get('principal') or '').lower()
    cloud_res = str(ev.get('cloud_resource') or ev.get('resource_arn') or '').lower()
    cloud = bool(('arn:aws:' in principal or 'azure' in principal or 'gcp' in principal) or cloud_res)

    return {
        'hour': hour,
        'lateral_flag': lateral,
        'priv_escalation_flag': priv,
        'cloud_pivot_flag': cloud,
    }

