"""NotificationBus abstraction wrapping channel-specific notifiers (Slack, Teams).

Usage:
  from .notification_bus import get_bus
  await get_bus().alert('high', title='Process Anomaly', body='Details...')
"""
from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Dict, Optional

try:
    from integrations.slack_notifier import SlackNotifier  # type: ignore
except Exception:  # pragma: no cover
    SlackNotifier = None  # type: ignore

class NotificationBus:
    def __init__(self, slack: Any | None = None, teams: Any | None = None):
        self.slack = slack
        self.teams = teams
        self._lock = asyncio.Lock()
        self.last_delivery: dict[str, float] = {}

    async def alert(self, severity: str, title: str, body: str, enrich: dict[str, Any] | None = None) -> dict[str, Any]:
        delivered: dict[str, bool] = {}
        tasks = []
        text = f"[{severity.upper()}] {title} - {body}" if body else f"[{severity.upper()}] {title}"
        if self.slack:
            async def _slack():
                ok = await self.slack.send_alert(severity, text)
                delivered['slack'] = ok
            tasks.append(_slack())
        if self.teams:
            # Teams integration placeholder (future adapter)
            delivered['teams'] = False
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        now = time.time()
        for k, v in delivered.items():
            if v:
                self.last_delivery[k] = now
        return {'delivered': delivered, 'timestamp': now}

    def publish(self, event_type: str, payload: dict[str, Any]):  # lightweight sync facade
        """Route internal events to appropriate async handlers (fire-and-forget).

        Currently supports:
          - alert.created: payload fields -> severity/title/body mapping
        """
        if event_type == 'alert.created':
            # Derive fields
            sev = (payload.get('verdict') or 'observe').lower()
            score = payload.get('score') or payload.get('confidence') or 0
            if sev in ('malicious','block','escalate') and score >= 0.9:
                sev = 'critical'
            elif score >= 0.75:
                sev = 'high'
            elif score >= 0.55:
                sev = 'medium'
            else:
                sev = 'low'
            title = payload.get('rule_name') or payload.get('title') or payload.get('process_name') or payload.get('id') or 'Alert'
            host = payload.get('host') or ''
            body = f"Host {host}" if host else ''
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self.alert(sev, title, body, enrich={'id': payload.get('id')}))
            except RuntimeError:
                # No running loop (unlikely in FastAPI), fallback to synchronous run
                asyncio.run(self.alert(sev, title, body, enrich={'id': payload.get('id')}))
        # Future: other event types

_BUS: NotificationBus | None = None

def get_bus() -> NotificationBus:
    global _BUS
    if _BUS is None:
        slack_url = os.getenv('SLACK_WEBHOOK_URL')
        slack = SlackNotifier(slack_url, None, None) if (SlackNotifier and slack_url) else None
        _BUS = NotificationBus(slack=slack)
    return _BUS

__all__ = ['get_bus', 'NotificationBus']