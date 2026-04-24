"""Chain-of-command escalation router.

Translates a DispositionResult and severity into a concrete contact list,
SLA clocks, and a next-action sentence. No ambiguity about who does what.

Chain of command:
  CONFIRMED_ATTACK (P1/critical)  → Page on-call SOC → CISO within 1h → Legal if data loss
  CONFIRMED_ATTACK (P2/high)      → SOC L1 (2h SLA)  → L2 if uncleared → CISO if breaches SLA
  CONFIRMED_ATTACK (P3/medium)    → SOC L1 queue (8h SLA) → L2 if escalated
  GRAY_AREA                       → SOC L1 review (4h) → close with notes or promote to P3
  HUMAN_BEHAVIOR                  → Direct user nudge → LM if repeat → HR if repeat+policy
  POLICY_VIOLATION                → LM + HR immediately → security awareness on record
  RED_TEAM                        → CISO acknowledge → close ticket → purple team debrief
  FALSE_POSITIVE                  → Analyst review → detection feedback → suppress or tune

All SLAs are configurable via env vars (ESCALATION_SLA_P1_MINUTES etc.).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from src.analysis.event_disposition import Disposition, DispositionResult


# ---------------------------------------------------------------------------
# SLA config (minutes) — override via environment for different shift patterns
# ---------------------------------------------------------------------------
_P1_PAGE_MINUTES    = int(os.getenv('ESCALATION_SLA_P1_MINUTES',    '15'))
_P2_L1_MINUTES      = int(os.getenv('ESCALATION_SLA_P2_MINUTES',   '120'))
_P3_L1_MINUTES      = int(os.getenv('ESCALATION_SLA_P3_MINUTES',   '480'))
_GRAY_MINUTES       = int(os.getenv('ESCALATION_SLA_GRAY_MINUTES',  '240'))
_HUMAN_NUDGE_HOURS  = int(os.getenv('ESCALATION_HUMAN_NUDGE_HOURS',   '4'))
_FP_REVIEW_DAYS     = int(os.getenv('ESCALATION_FP_REVIEW_DAYS',       '3'))


@dataclass
class EscalationPlan:
    priority: str                    # P1 / P2 / P3 / awareness / admin
    tier_1_contact: str              # first person/queue to contact
    tier_2_contact: str              # if tier 1 unresolved within SLA
    tier_3_contact: str              # board/legal/CISO escalation
    sla_minutes: int                 # time before auto-escalation to tier_2
    next_action: str                 # single sentence — what happens right now
    notification_channels: list[str] # ordered: pagerduty/teams/slack/email
    legal_hold: bool                 # preserve all evidence now
    public_disclosure_risk: bool     # GDPR/SEC/HIPAA clock may apply
    ciso_briefing_required: bool
    notes: str


# ---------------------------------------------------------------------------
# Contact directory — override per-org via env vars
# ---------------------------------------------------------------------------
def _contacts() -> dict[str, str]:
    return {
        'soc_oncall':      os.getenv('CONTACT_SOC_ONCALL',     'soc-oncall@company.invalid'),
        'soc_l1_queue':    os.getenv('CONTACT_SOC_L1_QUEUE',   '#soc-l1 on Teams'),
        'soc_l2':          os.getenv('CONTACT_SOC_L2',         'soc-l2@company.invalid'),
        'ciso':            os.getenv('CONTACT_CISO',           'ciso@company.invalid'),
        'legal':           os.getenv('CONTACT_LEGAL',          'legal@company.invalid'),
        'hr':              os.getenv('CONTACT_HR',             'hr@company.invalid'),
        'compliance':      os.getenv('CONTACT_COMPLIANCE',     'compliance@company.invalid'),
        'it_helpdesk':     os.getenv('CONTACT_IT_HELPDESK',    '#it-helpdesk on Teams'),
        'pagerduty':       os.getenv('PAGERDUTY_SERVICE_KEY',  ''),
    }


def _triage_score_to_priority(triage_score: float, disposition: Disposition) -> str:
    if disposition == Disposition.CONFIRMED_ATTACK:
        if triage_score >= 0.85:
            return 'P1'
        elif triage_score >= 0.65:
            return 'P2'
        else:
            return 'P3'
    if disposition == Disposition.GRAY_AREA:
        return 'P3'
    return 'awareness'


def build_escalation_plan(
    result: DispositionResult,
    triage_score: float = 0.0,
    mitre_tactics: list[str] | None = None,
    data_types: list[str] | None = None,   # e.g. ['pii', 'pci', 'phi'] for notification reqs
) -> EscalationPlan:
    """Return a concrete chain-of-command escalation plan for a disposition."""
    c = _contacts()
    disp = result.disposition
    priority = _triage_score_to_priority(triage_score, disp)

    has_pii   = bool(data_types and any(d in ('pii', 'gdpr', 'phi', 'hipaa') for d in (data_types or [])))
    has_pci   = bool(data_types and any(d in ('pci', 'card') for d in (data_types or [])))
    is_exfil  = any('exfil' in f or 'upload' in f or 'large_upload' in f for f in result.factors)

    # ---- CONFIRMED ATTACK ----
    if disp == Disposition.CONFIRMED_ATTACK:
        if priority == 'P1':
            return EscalationPlan(
                priority='P1',
                tier_1_contact=f"Page on-call SOC: {c['soc_oncall']}",
                tier_2_contact=f"CISO: {c['ciso']} (1h SLA — auto-notify if on-call unresponsive)",
                tier_3_contact=f"Legal: {c['legal']} (if data loss confirmed)",
                sla_minutes=_P1_PAGE_MINUTES,
                next_action=(
                    f"Page on-call SOC immediately. Open P1 incident. "
                    f"Preserve all logs and artefacts (legal hold). "
                    f"{'GDPR/HIPAA notification clock starts if PII confirmed exfiltrated.' if has_pii else ''}"
                    f"CISO briefing required within {_P1_PAGE_MINUTES}min."
                ),
                notification_channels=['pagerduty', 'teams', 'email'],
                legal_hold=True,
                public_disclosure_risk=has_pii or has_pci or is_exfil,
                ciso_briefing_required=True,
                notes='P1: Wake up the on-call. Do not wait to gather more evidence.',
            )

        if priority == 'P2':
            return EscalationPlan(
                priority='P2',
                tier_1_contact=f"SOC L1 queue: {c['soc_l1_queue']} (2h SLA)",
                tier_2_contact=f"SOC L2: {c['soc_l2']} (if L1 unresolved in {_P2_L1_MINUTES}min)",
                tier_3_contact=f"CISO: {c['ciso']} (if SLA breached)",
                sla_minutes=_P2_L1_MINUTES,
                next_action=(
                    f"Open SOC ticket assigned to L1. L1 must triage within {_P2_L1_MINUTES//60}h. "
                    f"Auto-escalate to L2 if not cleared. Do not auto-close."
                ),
                notification_channels=['teams', 'email'],
                legal_hold=has_pii or is_exfil,
                public_disclosure_risk=has_pii and is_exfil,
                ciso_briefing_required=triage_score >= 0.80,
                notes='P2: Assign immediately — track SLA clock.',
            )

        # P3
        return EscalationPlan(
            priority='P3',
            tier_1_contact=f"SOC L1 queue: {c['soc_l1_queue']} (8h SLA)",
            tier_2_contact=f"SOC L1 senior: {c['soc_l2']}",
            tier_3_contact=f"CISO: {c['ciso']} (if pattern persists)",
            sla_minutes=_P3_L1_MINUTES,
            next_action=(
                f"Add to SOC L1 review queue. Analyst should triage within {_P3_L1_MINUTES//60}h "
                f"during business hours. Can defer overnight if out-of-hours and score < 0.70."
            ),
            notification_channels=['teams'],
            legal_hold=False,
            public_disclosure_risk=False,
            ciso_briefing_required=False,
            notes='P3: Business-hours triage. Do not page on-call.',
        )

    # ---- RED TEAM ----
    if disp == Disposition.RED_TEAM:
        return EscalationPlan(
            priority='admin',
            tier_1_contact=f"CISO: {c['ciso']} — acknowledge and close",
            tier_2_contact='Red team lead — confirm scope and timing',
            tier_3_contact='N/A',
            sla_minutes=60,
            next_action=(
                "Tag this event as authorized-red-team. Notify CISO. "
                "Do NOT open a live incident. "
                "Add to the purple team debrief document for post-engagement lessons."
            ),
            notification_channels=['email'],
            legal_hold=False,
            public_disclosure_risk=False,
            ciso_briefing_required=True,
            notes=(
                "If you are NOT certain this is an authorized red team, treat it as CONFIRMED_ATTACK. "
                "Red team scope must be pre-confirmed in the change record."
            ),
        )

    # ---- HUMAN BEHAVIOR ----
    if disp == Disposition.HUMAN_BEHAVIOR:
        is_repeat = result.manager_notify
        return EscalationPlan(
            priority='awareness',
            tier_1_contact=(
                f"Direct user nudge via Teams/Slack/email (automated)"
                if not is_repeat else
                f"Line manager — quiet courtesy notification"
            ),
            tier_2_contact=(
                'Line manager — if user repeats within 30 days'
                if not is_repeat else
                f"HR: {c['hr']} — if behaviour continues after manager conversation"
            ),
            tier_3_contact=f"HR + Compliance: {c['hr']} (if 3+ occurrences within 90 days)",
            sla_minutes=_HUMAN_NUDGE_HOURS * 60,
            next_action=(
                f"{'Send line manager notification (repeat event). ' if is_repeat else ''}"
                f"Send user an education nudge within {_HUMAN_NUDGE_HOURS}h. "
                f"No SOC ticket. No disciplinary action unless repeat occurs."
            ),
            notification_channels=['teams', 'slack', 'email'],
            legal_hold=False,
            public_disclosure_risk=False,
            ciso_briefing_required=False,
            notes='Do not create a SOC ticket for this. The SOC should not be your HR department.',
        )

    # ---- POLICY VIOLATION ----
    if disp == Disposition.POLICY_VIOLATION:
        return EscalationPlan(
            priority='P3',
            tier_1_contact=f"Line manager + HR: {c['hr']} (simultaneous, formal notice)",
            tier_2_contact=f"Compliance: {c['compliance']} (if regulatory data involved)",
            tier_3_contact=f"Legal: {c['legal']} (if intentional exfiltration suspected)",
            sla_minutes=120,
            next_action=(
                "Notify line manager and HR simultaneously within 2h. "
                "Assign mandatory policy training. "
                "Document in conduct record. "
                "Do NOT treat as a SOC security incident unless intentionality confirmed."
            ),
            notification_channels=['email', 'teams'],
            legal_hold=is_exfil,
            public_disclosure_risk=has_pii and is_exfil,
            ciso_briefing_required=is_exfil and (has_pii or has_pci),
            notes='Policy violations are HR matters unless exfil or malicious intent is confirmed.',
        )

    # ---- FALSE POSITIVE ----
    if disp == Disposition.FALSE_POSITIVE:
        return EscalationPlan(
            priority='admin',
            tier_1_contact=f"Detection tuning queue (no human escalation required)",
            tier_2_contact=f"SOC analyst — review suppression scope within {_FP_REVIEW_DAYS} days",
            tier_3_contact='N/A',
            sla_minutes=_FP_REVIEW_DAYS * 24 * 60,
            next_action=(
                f"Log to false-positive feedback store. "
                f"Analyst reviews suppression scope within {_FP_REVIEW_DAYS} business days. "
                f"Do not page anyone. Do not open a SOC ticket."
            ),
            notification_channels=[],
            legal_hold=False,
            public_disclosure_risk=False,
            ciso_briefing_required=False,
            notes='Accumulate FP feedback before suppressing — confirm pattern across 3+ events.',
        )

    # ---- GRAY AREA (default) ----
    return EscalationPlan(
        priority='P3',
        tier_1_contact=f"SOC L1 review queue: {c['soc_l1_queue']} (4h SLA)",
        tier_2_contact=f"SOC L2: {c['soc_l2']} (if L1 cannot clearly close)",
        tier_3_contact=f"CISO: {c['ciso']} (if unresolved > 8h)",
        sla_minutes=_GRAY_MINUTES,
        next_action=(
            f"Soft hold — do not auto-close or auto-escalate. "
            f"SOC analyst reviews within {_GRAY_MINUTES//60}h and chooses: "
            f"close with notes, promote to P2, or send user education nudge."
        ),
        notification_channels=['teams'],
        legal_hold=False,
        public_disclosure_risk=False,
        ciso_briefing_required=False,
        notes=(
            "Gray area events are the most common analyst time sink. "
            "The analyst has exactly three choices: CLOSE (with notes explaining why), "
            "PROMOTE (change to confirmed_attack), or EDUCATE (change to human_behavior). "
            "There is no 'leave open indefinitely' option."
        ),
    )


def to_dict(plan: EscalationPlan) -> dict[str, Any]:
    """Serialise for API responses."""
    return {
        'priority': plan.priority,
        'contacts': {
            'tier_1': plan.tier_1_contact,
            'tier_2': plan.tier_2_contact,
            'tier_3': plan.tier_3_contact,
        },
        'sla_minutes': plan.sla_minutes,
        'next_action': plan.next_action,
        'notification_channels': plan.notification_channels,
        'flags': {
            'legal_hold': plan.legal_hold,
            'public_disclosure_risk': plan.public_disclosure_risk,
            'ciso_briefing_required': plan.ciso_briefing_required,
        },
        'notes': plan.notes,
    }
