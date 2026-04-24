"""Human factor playbook — routes non-attack security events to education
and awareness channels instead of the SOC ticket queue.

The entire premise: most security events are humans doing dumb things,
not adversaries doing clever things. Burning a SOC analyst's time on
"Dave from Finance clicked a weird link again" is expensive and demoralising.
This playbook routes those events to the right outcome:
  - A short, direct, non-threatening message to the user
  - Optional quiet notification to their line manager
  - A training assignment trigger (LMS webhook stub)
  - HR documentation for repeat or policy-violating behaviour

Notification channels supported:
  - Microsoft Teams: Incoming Webhook (TEAMS_WEBHOOK_URL env var)
  - Slack: Incoming Webhook (SLACK_WEBHOOK_URL env var)
  - Email: SMTP stub (EMAIL_SMTP_HOST / _PORT / _FROM env vars)

All channels are fire-and-forget with structured logging. If the channel
is unavailable, the action is logged as 'pending_delivery' and surfaced
in the incident record — NOT silently dropped.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import asdict, dataclass
from typing import Any

import httpx

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Education message templates — indexed by signal category
# ---------------------------------------------------------------------------
_NUDGE_TEMPLATES: dict[str, dict[str, str]] = {

    'personal_cloud_upload': {
        'subject': 'Quick note about a file you uploaded today',
        'short': (
            "Hi {name}, we noticed you uploaded a work file to a personal cloud account today. "
            "Work files should stay on approved company storage. "
            "It only takes a minute to move it: {storage_link}. "
            "No action required on your part if this was a mistake — we've already flagged it. "
            "If you need access to that file, just reply here."
        ),
        'training_module': 'data-handling-basics',
        'tone': 'friendly',
    },

    'mfa_bypass': {
        'subject': 'Your sign-in looked a bit unusual',
        'short': (
            "Hi {name}, we noticed you approved a multi-factor sign-in request even though "
            "you may not have been actively signing in at the time. "
            "If that was you on a new device — all good. "
            "If you didn't trigger it, change your password now: {password_reset_link}. "
            "Takes 2 minutes and protects your account."
        ),
        'training_module': 'mfa-fatigue-awareness',
        'tone': 'concerned-but-friendly',
    },

    'impossible_travel': {
        'subject': 'We saw a sign-in from an unexpected location',
        'short': (
            "Hi {name}, your account was accessed from {location} at {time}. "
            "If that was you using a VPN or travelling — no action needed. "
            "If you weren't signing in from there, "
            "please change your password immediately: {password_reset_link}"
        ),
        'training_module': 'account-security-basics',
        'tone': 'informational',
    },

    'sensitive_data_in_email': {
        'subject': 'Heads up: sensitive information in an email you sent',
        'short': (
            "Hi {name}, an email you sent today may have included sensitive information "
            "(like account numbers or personal data). "
            "We're not saying it was intentional — these things happen. "
            "Going forward, use our secure file share for anything sensitive: {secure_share_link}. "
            "No disciplinary action — just a reminder for next time."
        ),
        'training_module': 'email-data-handling',
        'tone': 'non-threatening',
    },

    'unapproved_software_install': {
        'subject': 'Software installation on your device',
        'short': (
            "Hi {name}, we noticed an installation of software on your device "
            "that isn't on the approved list. "
            "This isn't a problem if it was something you needed for work — "
            "just let IT know so we can approve it: {it_request_link}. "
            "If it installed itself without your action, "
            "please contact IT immediately: {it_contact}."
        ),
        'training_module': 'approved-software-policy',
        'tone': 'helpful',
    },

    'usb_storage': {
        'subject': 'USB device connected to a company computer',
        'short': (
            "Hi {name}, a USB storage device was connected to your workstation today. "
            "Our policy requires approval before using personal storage on company equipment. "
            "If you needed to transfer files, use our approved file share instead: {secure_share_link}. "
            "If you weren't at your computer when this happened, contact IT right away: {it_contact}."
        ),
        'training_module': 'removable-media-policy',
        'tone': 'policy-reminder',
    },

    'default': {
        'subject': 'Quick security check-in from the security team',
        'short': (
            "Hi {name}, our systems flagged some unusual activity on your account today. "
            "It's likely nothing, but we wanted to let you know. "
            "If anything seems off — unusual emails, unexpected sign-ins, or anything you're not sure about — "
            "just reply to this message or contact IT: {it_contact}."
        ),
        'training_module': 'general-security-awareness',
        'tone': 'friendly',
    },

    'policy_violation': {
        'subject': 'Important: Security policy reminder',
        'short': (
            "Hi {name}, this is a formal notice that your recent activity "
            "({violation_description}) is outside our security policy. "
            "Your line manager has been notified. "
            "A short training module has been assigned to your account: {training_link}. "
            "Please complete it within 5 business days. "
            "If you have questions, please speak to your manager or HR."
        ),
        'training_module': 'policy-compliance-refresher',
        'tone': 'formal',
    },
}

_MANAGER_TEMPLATE = (
    "Hi {manager_name}, this is an automated notification from the security team. "
    "{user_name} has {count} security awareness event{'s' if {count} != 1 else ''} "
    "recorded in the last 30 days — the most recent was {event_description}. "
    "No immediate action is required from you. "
    "We've sent {user_name} a direct education reminder. "
    "If this becomes a pattern, our policy recommends a 15-minute coaching conversation. "
    "Please do not raise this as a disciplinary matter without HR involvement."
)

# ---------------------------------------------------------------------------
# Delivery functions
# ---------------------------------------------------------------------------

async def _post_teams(webhook_url: str, title: str, body: str, color: str = '0078D4') -> bool:
    """Post an Adaptive Card message to a Teams channel via Incoming Webhook."""
    payload = {
        '@type': 'MessageCard',
        '@context': 'http://schema.org/extensions',
        'themeColor': color,
        'summary': title,
        'sections': [{'activityTitle': title, 'activityText': body}],
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(webhook_url, json=payload)
            return r.status_code in (200, 202)
    except Exception as exc:
        log.warning('Teams delivery failed: %s', exc)
        return False


async def _post_slack(webhook_url: str, title: str, body: str) -> bool:
    """Post a plain Slack message via Incoming Webhook."""
    payload = {'text': f'*{title}*\n{body}'}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(webhook_url, json=payload)
            return r.status_code == 200
    except Exception as exc:
        log.warning('Slack delivery failed: %s', exc)
        return False


async def _send_email(to: str, subject: str, body: str) -> bool:
    """SMTP send stub. Requires SMTP env vars to be set."""
    host = os.getenv('EMAIL_SMTP_HOST', '')
    port = int(os.getenv('EMAIL_SMTP_PORT', '587'))
    from_addr = os.getenv('EMAIL_FROM', 'security@company.invalid')
    if not host or not to:
        log.info('Email not sent — SMTP not configured or no recipient address')
        return False
    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = subject
        msg['From'] = from_addr
        msg['To'] = to
        with smtplib.SMTP(host, port, timeout=10) as s:
            s.sendmail(from_addr, [to], msg.as_string())
        return True
    except Exception as exc:
        log.warning('Email delivery failed to %s: %s', to, exc)
        return False


# ---------------------------------------------------------------------------
# Nudge builder
# ---------------------------------------------------------------------------

@dataclass
class HumanFactorAction:
    action_id: str
    disposition: str
    user: str
    event_description: str
    user_nudge_sent: bool
    manager_notified: bool
    hr_notified: bool
    training_assigned: bool
    training_module: str
    channels_attempted: list[str]
    channels_delivered: list[str]
    pending_delivery: list[str]    # channels that should be retried
    timestamp: float
    notes: str


def _pick_template(signals: list[str]) -> dict[str, str]:
    for sig in signals:
        for key in _NUDGE_TEMPLATES:
            if key in sig:
                return _NUDGE_TEMPLATES[key]
    return _NUDGE_TEMPLATES['default']


def _fill_template(tpl: str, context: dict[str, str]) -> str:
    for k, v in context.items():
        tpl = tpl.replace('{' + k + '}', str(v))
    return tpl


async def run_human_factor_playbook(
    disposition_result,          # DispositionResult from event_disposition
    user: str,
    user_email: str = '',
    manager_email: str = '',
    hr_email: str = '',
    company_context: dict | None = None,
    dry_run: bool = False,
) -> HumanFactorAction:
    """Execute the human-factor response playbook.

    Sends the appropriate nudge message to the user (and optionally their
    manager and HR) based on the DispositionResult, using whatever
    notification channels are configured.

    Set dry_run=True to build the action record without actually sending.
    """
    from src.analysis.event_disposition import Disposition
    import uuid

    co = company_context or {}
    context = {
        'name': user.split('@')[0].split('.')[0].capitalize() if '@' in user else user or 'there',
        'location': co.get('location', 'an unexpected location'),
        'time': co.get('event_time', 'recently'),
        'violation_description': co.get('violation_description', 'the activity described above'),
        'it_contact': co.get('it_contact', '#it-helpdesk on Teams'),
        'it_request_link': co.get('it_request_link', 'https://it.company.internal/request'),
        'password_reset_link': co.get('password_reset_link', 'https://account.company.internal/reset'),
        'storage_link': co.get('storage_link', 'https://files.company.internal'),
        'secure_share_link': co.get('secure_share_link', 'https://files.company.internal'),
        'training_link': co.get('training_link', 'https://training.company.internal'),
        'manager_name': co.get('manager_name', 'Hi'),
        'user_name': user,
        'event_description': disposition_result.evidence_sentence[:120],
        'count': str(co.get('event_count_30d', 1)),
    }

    tpl = _pick_template(disposition_result.raw_signals.get('human', [])
                         + disposition_result.raw_signals.get('policy', []))
    if disposition_result.disposition == Disposition.POLICY_VIOLATION.value or \
       disposition_result.disposition == 'policy_violation':
        tpl = _NUDGE_TEMPLATES['policy_violation']

    subject = _fill_template(tpl['subject'], context)
    body = _fill_template(tpl['short'], context)
    training_module = tpl.get('training_module', 'general-security-awareness')

    channels_attempted: list[str] = []
    channels_delivered: list[str] = []
    pending: list[str] = []

    if dry_run:
        return HumanFactorAction(
            action_id=str(uuid.uuid4()),
            disposition=str(disposition_result.disposition),
            user=user,
            event_description=disposition_result.evidence_sentence,
            user_nudge_sent=False,
            manager_notified=False,
            hr_notified=False,
            training_assigned=False,
            training_module=training_module,
            channels_attempted=[],
            channels_delivered=[],
            pending_delivery=['dry_run_no_send'],
            timestamp=time.time(),
            notes=f'DRY RUN — would send: subject="{subject}" body="{body[:80]}..."',
        )

    # -- User notification --
    if disposition_result.user_nudge_required:
        # Try Teams first, fall back to Slack, fall back to email
        teams_url = os.getenv('TEAMS_WEBHOOK_URL', '')
        slack_url = os.getenv('SLACK_WEBHOOK_URL', '')

        if teams_url:
            channels_attempted.append('teams')
            ok = await _post_teams(teams_url, subject, body, color='FFA500')
            if ok:
                channels_delivered.append('teams')
            else:
                pending.append('teams')

        if slack_url and 'teams' not in channels_delivered:
            channels_attempted.append('slack')
            ok = await _post_slack(slack_url, subject, body)
            if ok:
                channels_delivered.append('slack')
            else:
                pending.append('slack')

        if user_email and not channels_delivered:
            channels_attempted.append('email_user')
            ok = await _send_email(user_email, subject, body)
            if ok:
                channels_delivered.append('email_user')
            else:
                pending.append('email_user')

    user_nudge_sent = bool(channels_delivered)

    # -- Manager notification --
    manager_notified = False
    if disposition_result.manager_notify and manager_email:
        mgr_body = _fill_template(_MANAGER_TEMPLATE, context)
        mgr_subject = f'Security awareness: {user} — action may be needed'
        channels_attempted.append('email_manager')
        ok = await _send_email(manager_email, mgr_subject, mgr_body)
        if ok:
            channels_delivered.append('email_manager')
            manager_notified = True
        else:
            pending.append('email_manager')

    # -- HR notification (policy violations only) --
    hr_notified = False
    if disposition_result.hr_notify and hr_email:
        hr_subject = f'Policy violation record — {user}'
        hr_body = (
            f"Security team — formal notice.\n\n"
            f"User: {user}\n"
            f"Event: {disposition_result.evidence_sentence}\n"
            f"Time: {context['time']}\n\n"
            f"This event is being recorded. Manager has been notified separately. "
            f"A training module has been assigned. "
            f"Please note this in the conduct record per your standard procedure."
        )
        channels_attempted.append('email_hr')
        ok = await _send_email(hr_email, hr_subject, hr_body)
        if ok:
            channels_delivered.append('email_hr')
            hr_notified = True
        else:
            pending.append('email_hr')

    # -- Training assignment stub (webhook to LMS) --
    training_assigned = False
    lms_webhook = os.getenv('LMS_TRAINING_WEBHOOK', '')
    if lms_webhook and user:
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                payload = {
                    'user': user,
                    'module': training_module,
                    'due_days': 5 if disposition_result.hr_notify else 30,
                    'reason': disposition_result.evidence_sentence[:200],
                    'assigned_by': 'janusec-security-platform',
                }
                r = await client.post(lms_webhook, json=payload)
                training_assigned = r.status_code in (200, 201, 202)
        except Exception:
            pass

    return HumanFactorAction(
        action_id=str(uuid.uuid4()),
        disposition=str(disposition_result.disposition),
        user=user,
        event_description=disposition_result.evidence_sentence,
        user_nudge_sent=user_nudge_sent,
        manager_notified=manager_notified,
        hr_notified=hr_notified,
        training_assigned=training_assigned,
        training_module=training_module,
        channels_attempted=channels_attempted,
        channels_delivered=channels_delivered,
        pending_delivery=pending,
        timestamp=time.time(),
        notes=f'tone={tpl.get("tone","?")}',
    )


def run_sync(disposition_result, user: str, **kwargs) -> HumanFactorAction:
    """Synchronous wrapper for contexts without a running event loop."""
    return asyncio.run(run_human_factor_playbook(disposition_result, user, **kwargs))
