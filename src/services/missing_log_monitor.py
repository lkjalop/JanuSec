from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional

from src.core.soar.interface import get_soar_client

LOGGER = logging.getLogger(__name__)
ALERT_THROTTLE_SECONDS = float(os.getenv('IAM_MISSING_LOG_ALERT_THROTTLE', '300') or 300.0)


def _auto_ticket_enabled() -> bool:
    return os.getenv('IAM_MISSING_LOG_AUTO_TICKET', '0').lower() in {'1', 'true', 'yes'}


def _auto_ticket_threshold() -> int:
    try:
        return int(os.getenv('IAM_MISSING_LOG_AUTO_TICKET_THRESHOLD', '3') or 3)
    except Exception:
        return 3


def _auto_ticket_cooldown() -> float:
    try:
        return float(os.getenv('IAM_MISSING_LOG_AUTO_TICKET_COOLDOWN', '900') or 900.0)
    except Exception:
        return 900.0


def _auto_ticket_action() -> str:
    return os.getenv('IAM_MISSING_LOG_AUTO_TICKET_ACTION', 'ticket.create')


def _event_marker(entry: Dict[str, Any]) -> Any:
    marker = entry.get('last_event_ts')
    if marker in (None, 0):
        return '__never__'
    try:
        return round(float(marker), 3)
    except Exception:
        return '__never__'


async def dispatch_missing_log_alerts(
    tenant: str,
    runtime_health: Dict[str, Dict[str, Any]],
    missing_alerts: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Best-effort SOAR hook for connectors missing telemetry."""
    if not missing_alerts or not runtime_health:
        return []
    client = get_soar_client()
    triggered: List[Dict[str, Any]] = []
    now = time.time()
    for incoming in missing_alerts:
        alert = dict(incoming)
        connector_id = alert.get('connector')
        if not connector_id:
            continue
        entry = runtime_health.setdefault(connector_id, {})
        marker = _event_marker(entry)
        last_marker = entry.get('missing_alert_event_ref')
        last_fired = float(entry.get('missing_alert_ts') or 0.0)
        suppressed = bool(last_marker == marker and (now - last_fired) < ALERT_THROTTLE_SECONDS)
        entry['missing_alert_event_ref'] = marker
        if not suppressed:
            entry['missing_alert_ts'] = now
        entry['missing_alert_count'] = int(entry.get('missing_alert_count') or 0) + 1
        title = f"IAM missing telemetry: {alert.get('label') or connector_id}"
        severity = (alert.get('severity') or 'warning').lower()
        details = {
            'tenant': tenant,
            'connector_id': connector_id,
            'seconds_since_event': alert.get('seconds_since_event'),
            'ttl_seconds': alert.get('ttl_seconds'),
            'last_event_ts': alert.get('last_event_ts'),
            'recommendations': alert.get('recommendations') or [],
        }
        if not suppressed:
            try:
                LOGGER.info(
                    'dispatching_missing_log_alert connector=%s tenant=%s severity=%s idle=%.1f ttl=%s',
                    connector_id,
                    tenant,
                    severity,
                    float(alert.get('seconds_since_event') or 0.0),
                    alert.get('ttl_seconds'),
                )
                await client.create_alert(title=title, severity=severity, details=details)  # type: ignore[arg-type]
            except Exception:
                LOGGER.warning('missing_log_alert_failed connector=%s tenant=%s', connector_id, tenant, exc_info=True)
        else:
            alert['suppressed'] = True
        ticket_meta = await _maybe_auto_ticket(client, tenant, connector_id, alert, entry)
        if ticket_meta:
            alert['auto_ticket'] = ticket_meta
        if not suppressed or ticket_meta:
            triggered.append(alert)
    return triggered


async def _maybe_auto_ticket(client, tenant: str, connector_id: str, alert: Dict[str, Any], entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not _auto_ticket_enabled():
        return None
    count = int(entry.get('missing_alert_count') or 0)
    if count < _auto_ticket_threshold():
        return None
    now = time.time()
    last_ticket = float(entry.get('missing_ticket_ts') or 0.0)
    if last_ticket and (now - last_ticket) < _auto_ticket_cooldown():
        return None
    entry['missing_ticket_ts'] = now
    params = {
        'tenant': tenant,
        'connector_id': connector_id,
        'severity': alert.get('severity') or 'warning',
        'seconds_since_event': alert.get('seconds_since_event'),
        'ttl_seconds': alert.get('ttl_seconds'),
        'recommendations': alert.get('recommendations') or [],
        'auto_ticket_reason': 'iam_missing_logs',
    }
    action = _auto_ticket_action()
    try:
        result = await client.execute_action(action=action, target=connector_id, params=params)  # type: ignore[arg-type]
        LOGGER.info('missing_log_auto_ticket connector=%s tenant=%s action=%s', connector_id, tenant, action)
        return {'status': 'triggered', 'action': action, 'result': result}
    except Exception:
        LOGGER.warning('missing_log_ticket_failed connector=%s tenant=%s', connector_id, tenant, exc_info=True)
        return {'status': 'error', 'action': action}


__all__ = ['dispatch_missing_log_alerts']
