"""Report scheduling and webhook delivery.

Schedules are stored in data/report_schedules.json (one dict per tenant).
The scheduler dispatches reports by building the ingestion payload directly,
then POSTing a summary JSON to each configured delivery_webhook_urls entry.

Usage:
    from src.reporting.report_scheduler import get_scheduler
    scheduler = get_scheduler()
    scheduler.tick()   # call from a background task or APScheduler job
"""
from __future__ import annotations

import json
import os
import time
import uuid
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import httpx
    _HAS_HTTPX = True
except Exception:
    _HAS_HTTPX = False

LOGGER = logging.getLogger('report_scheduler')

_STORE_PATH = Path(os.getenv('REPORT_SCHEDULE_STORE', 'data/report_schedules.json'))
_DISPATCH_TIMEOUT_SECONDS = int(os.getenv('REPORT_SCHEDULE_DISPATCH_TIMEOUT', '15'))


# ─── Cron-like interval helpers ──────────────────────────────────────────────

def _interval_seconds(cadence: str) -> int:
    """Return repeat interval in seconds for a cadence string.

    Supported: 'hourly', 'daily', 'weekly', 'monthly', or '<N>h'/'<N>m'/'<N>s'.
    """
    c = (cadence or 'daily').strip().lower()
    if c == 'hourly':
        return 3600
    if c == 'daily':
        return 86400
    if c == 'weekly':
        return 7 * 86400
    if c == 'monthly':
        return 30 * 86400
    # numeric suffixes
    try:
        if c.endswith('h'):
            return int(c[:-1]) * 3600
        if c.endswith('m'):
            return int(c[:-1]) * 60
        if c.endswith('s'):
            return int(c[:-1])
    except ValueError:
        pass
    return 86400


# ─── Store ────────────────────────────────────────────────────────────────────

def _load_store() -> Dict[str, Any]:
    try:
        if _STORE_PATH.exists():
            return json.loads(_STORE_PATH.read_text(encoding='utf-8'))
    except Exception:
        pass
    return {}


def _save_store(data: Dict[str, Any]) -> None:
    try:
        _STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _STORE_PATH.write_text(json.dumps(data, indent=2), encoding='utf-8')
    except Exception as exc:
        LOGGER.warning('report_scheduler: store write failed: %s', exc)


# ─── Scheduler ────────────────────────────────────────────────────────────────

class ReportScheduler:
    """File-backed report schedule store with webhook dispatch."""

    def create_schedule(
        self,
        tenant_id: str,
        persona: str,
        cadence: str,
        delivery_webhook_urls: List[str],
        format: str = 'json',
        label: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create or replace a schedule entry. Returns the created record."""
        store = _load_store()
        schedule_id = uuid.uuid4().hex
        now = int(time.time())
        entry: Dict[str, Any] = {
            'schedule_id': schedule_id,
            'tenant_id': tenant_id,
            'label': label or f'{persona} {cadence} report',
            'persona': persona,
            'cadence': cadence,
            'interval_seconds': _interval_seconds(cadence),
            'format': format,
            'delivery_webhook_urls': delivery_webhook_urls,
            'filters': filters or {},
            'created_at': now,
            'next_run_at': now,  # run on first tick after creation
            'last_run_at': None,
            'last_run_status': None,
        }
        tenant_schedules: Dict[str, Any] = store.get(tenant_id) or {}
        tenant_schedules[schedule_id] = entry
        store[tenant_id] = tenant_schedules
        _save_store(store)
        return entry

    def list_schedules(self, tenant_id: str) -> List[Dict[str, Any]]:
        store = _load_store()
        return list((store.get(tenant_id) or {}).values())

    def get_schedule(self, tenant_id: str, schedule_id: str) -> Optional[Dict[str, Any]]:
        store = _load_store()
        return (store.get(tenant_id) or {}).get(schedule_id)

    def delete_schedule(self, tenant_id: str, schedule_id: str) -> bool:
        store = _load_store()
        tenant_schedules = store.get(tenant_id) or {}
        if schedule_id not in tenant_schedules:
            return False
        del tenant_schedules[schedule_id]
        store[tenant_id] = tenant_schedules
        _save_store(store)
        return True

    def tick(self) -> List[Dict[str, Any]]:
        """Check all schedules and dispatch any that are due. Returns dispatched entries."""
        now = int(time.time())
        store = _load_store()
        dispatched: List[Dict[str, Any]] = []
        changed = False
        for tenant_id, tenant_schedules in store.items():
            for schedule_id, entry in tenant_schedules.items():
                next_run = entry.get('next_run_at') or 0
                if now < next_run:
                    continue
                try:
                    status = self._dispatch(entry)
                except Exception as exc:
                    status = f'error:{exc}'
                entry['last_run_at'] = now
                entry['last_run_status'] = status
                entry['next_run_at'] = now + entry.get('interval_seconds', 86400)
                dispatched.append({'schedule_id': schedule_id, 'tenant_id': tenant_id, 'status': status})
                changed = True
        if changed:
            _save_store(store)
        return dispatched

    def trigger_now(self, tenant_id: str, schedule_id: str) -> str:
        """Manually trigger a schedule immediately. Returns dispatch status."""
        store = _load_store()
        entry = (store.get(tenant_id) or {}).get(schedule_id)
        if not entry:
            return 'not_found'
        try:
            status = self._dispatch(entry)
        except Exception as exc:
            status = f'error:{exc}'
        entry['last_run_at'] = int(time.time())
        entry['last_run_status'] = status
        store.setdefault(tenant_id, {})[schedule_id] = entry
        _save_store(store)
        return status

    # ── Internal dispatch ────────────────────────────────────────────────────

    def _dispatch(self, entry: Dict[str, Any]) -> str:
        """Build a report snapshot and POST it to each delivery webhook URL."""
        report_payload = self._build_report_payload(entry)
        urls = entry.get('delivery_webhook_urls') or []
        if not urls:
            return 'no_webhooks_configured'
        if not _HAS_HTTPX:
            return 'httpx_unavailable'
        errors: List[str] = []
        for url in urls:
            try:
                resp = httpx.post(
                    url,
                    json=report_payload,
                    timeout=_DISPATCH_TIMEOUT_SECONDS,
                    headers={'X-Janusec-Schedule-ID': entry.get('schedule_id', ''), 'X-Janusec-Tenant': entry.get('tenant_id', '')},
                )
                if resp.status_code >= 400:
                    errors.append(f'{url}:{resp.status_code}')
            except Exception as exc:
                errors.append(f'{url}:exception:{exc}')
        return 'ok' if not errors else f'partial_errors:{"|".join(errors)}'

    def _build_report_payload(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Build the report data to send.  Pulls from in-process report aggregation when available."""
        persona = entry.get('persona', 'soc_analyst')
        tenant_id = entry.get('tenant_id', 'default')
        filters = entry.get('filters') or {}
        fmt = entry.get('format', 'json')

        report: Dict[str, Any] = {
            'schedule_id': entry.get('schedule_id'),
            'tenant_id': tenant_id,
            'persona': persona,
            'format': fmt,
            'generated_at': int(time.time()),
            'label': entry.get('label'),
        }

        try:
            from src.api.report_aggregation import build_ingestion_report
            from src.api.dependencies import get_platform_state
            state = get_platform_state()
            agg = build_ingestion_report(
                session_ids=filters.get('session_ids') or [],
                include_alerts=True,
                limit_alerts=filters.get('limit_alerts', 100),
                state=state,
                tenant_id=tenant_id,
                persona=persona,
            )
            report.update(agg)
        except Exception as exc:
            report['aggregation_error'] = str(exc)

        # Apply persona view when available
        try:
            from src.reporting.persona_views import generate_persona_view
            report['persona_view'] = generate_persona_view(report, persona, disclosure_level=2)
        except Exception:
            pass

        return report


# ── Module-level singleton ────────────────────────────────────────────────────

_SCHEDULER: Optional[ReportScheduler] = None


def get_scheduler() -> ReportScheduler:
    global _SCHEDULER
    if _SCHEDULER is None:
        _SCHEDULER = ReportScheduler()
    return _SCHEDULER
