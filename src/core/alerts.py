"""Simple alerting helpers for critical events (DLQ max attempts).

Provides a webhook POST helper and an email stub (best-effort).
Configure via env vars: ALERT_WEBHOOK_URL, ALERT_EMAIL_FROM, ALERT_EMAIL_TO
"""
from __future__ import annotations

import os
import logging
import json
import asyncio

logger = logging.getLogger(__name__)


async def send_webhook(payload: dict):
    url = os.getenv('ALERT_WEBHOOK_URL')
    if not url:
        return False
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5.0) as c:
            await c.post(url, json=payload)
        return True
    except Exception:
        logger.debug('Webhook alert failed', exc_info=True)
        return False


def send_email(subject: str, body: str):
    # Best-effort: send via local sendmail or external SMTP if configured
    to = os.getenv('ALERT_EMAIL_TO')
    frm = os.getenv('ALERT_EMAIL_FROM')
    if not to or not frm:
        logger.debug('Email alert not configured')
        return False
    try:
        # Try simple SMTP relay via localhost
        import smtplib
        from email.message import EmailMessage
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = frm
        msg['To'] = to
        msg.set_content(body)
        with smtplib.SMTP('localhost') as s:
            s.send_message(msg)
        return True
    except Exception:
        logger.debug('Email alert failed', exc_info=True)
        return False


async def alert_dlq_max_attempts(dlq_row: dict):
    payload = {
        'type': 'dlq_max_attempts',
        'row': dlq_row,
    }
    policy = (os.getenv('ALERT_ESCALATION_POLICY') or 'webhook,slack,email').split(',')
    # Normalize and iterate
    for channel in [c.strip().lower() for c in policy]:
        try:
            if channel == 'webhook':
                await send_webhook(payload)
            elif channel == 'slack':
                # send a formatted slack message with blocks
                text = f"DLQ alert: event={dlq_row.get('event_id')} attempts={dlq_row.get('attempts')}"
                blocks = {
                    "blocks": [
                        {"type": "section", "text": {"type": "mrkdwn", "text": f"*DLQ entry reached max attempts*\n*event:* `{dlq_row.get('event_id')}`\n*attempts:* {dlq_row.get('attempts')}"}},
                        {"type": "section", "text": {"type": "mrkdwn", "text": f"Error: ```{dlq_row.get('error')}```"}},
                        {"type": "context", "elements": [{"type": "mrkdwn", "text": "Use the admin UI to inspect and requeue or delete."}]}
                    ]
                }
                await send_slack(blocks)
            elif channel == 'pagerduty':
                # use event_id as dedup key so subsequent triggers update the same incident
                dedup = str(dlq_row.get('event_id') or f"dlq-{dlq_row.get('id')}")
                await send_pagerduty(payload, dedup_key=dedup)
            elif channel == 'email':
                send_email('DLQ max attempts', json.dumps(payload, default=str))
        except Exception:
            logger.debug('Alert channel %s failed', channel, exc_info=True)


async def send_slack(payload: dict):
    url = os.getenv('ALERT_SLACK_WEBHOOK')
    if not url:
        return False
    try:
        import httpx
        # payload may already be a blocks dict or a simple dict
        body = None
        if isinstance(payload, dict) and 'blocks' in payload:
            body = payload
        else:
            text = f"DLQ alert: {payload.get('row',{}).get('event_id')} attempts={payload.get('row',{}).get('attempts')}"
            body = {'blocks': [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]}
        async with httpx.AsyncClient(timeout=5.0) as c:
            await c.post(url, json=body)
        return True
    except Exception:
        logger.debug('Slack alert failed', exc_info=True)
        return False


async def send_pagerduty(payload: dict):
    key = os.getenv('ALERT_PAGERDUTY_KEY')
    if not key:
        return False
    try:
        import httpx
        # Use Events API v2
        url = 'https://events.pagerduty.com/v2/enqueue'
        body = {
            'routing_key': key,
            'event_action': 'trigger',
            'payload': {
                'summary': f"DLQ entry {payload.get('row',{}).get('event_id')} failed delivery",
                'source': 'janusec.dlq',
                'severity': 'error'
            }
        }
        # allow callers to pass dedup_key for incident de-duplication or updates
        if isinstance(payload, dict) and payload.get('dedup_key'):
            body['dedup_key'] = payload.get('dedup_key')
        async with httpx.AsyncClient(timeout=5.0) as c:
            await c.post(url, json=body)
        return True
    except Exception:
        logger.debug('PagerDuty alert failed', exc_info=True)
        return False
