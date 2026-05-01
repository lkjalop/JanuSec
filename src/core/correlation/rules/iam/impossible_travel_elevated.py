from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(
    name='iam_impossible_travel_elevated_creds',
    mitre=['T1078', 'T1550.001', 'T1556'],
    factors_required=['impossible_travel', 'identity:priv_escalation'],
    window_seconds=7200,
    severity='high',
    confidence_boost=0.60,
)
def iam_impossible_travel_elevated_creds(event: Dict[str, Any]) -> bool:
    """Detect impossible travel combined with elevated or temporary credentials.

    Fires when a single event carries both:
      - An impossible-travel signal (flagged by upstream enrichment or
        identity-context extraction from the description), AND
      - Elevated / temporary credential context (JIT, PIM, AssumeRole, token reuse,
        or any priv_escalation factor)

    This combination indicates either:
      a) Credential theft where the attacker is operating from a different location
         than the legitimate user, OR
      b) A session token / refresh token that has been replayed from a new location.

    Both scenarios require SOC or Threat Hunter investigation to deny or confirm.

    The rule emits `correlation_emission` metadata so the cluster builder can
    include it in investigation tasks for soc_analyst and threat_hunter personas.
    """
    identity = event.get('identity_context') or {}
    impossible_travel = (
        bool(event.get('impossible_travel'))
        or bool(identity.get('impossible_travel'))
        or any(t in (event.get('description') or '').lower()
               for t in ('impossible travel', 'atypical travel', 'geo-velocity', 'geovelocity'))
    )
    elevated = (
        identity.get('privilege_state') in ('elevated', 'suspicious')
        or identity.get('privilege_type') in ('temporary', 'escalated', 'session_reuse')
        or 'identity:priv_escalation' in (event.get('factors') or [])
        or any(t in (event.get('description') or '').lower()
               for t in ('pim activated', 'just in time', 'jit', 'assume role',
                         'sts:assumerole', 'temporary elevated', 'refresh token',
                         'token reuse', 'session replay', 'legacy auth'))
    )

    fired = impossible_travel and elevated

    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'iam_impossible_travel_elevated_creds',
            'mitre': ['T1078', 'T1550.001', 'T1556'],
            'severity': 'high',
            'confidence_boost': 0.60,
            'investigation_required': True,
            'verdict': 'pending_soc_review',
            'evidence': {
                'impossible_travel': impossible_travel,
                'privilege_state': identity.get('privilege_state'),
                'privilege_type': identity.get('privilege_type'),
                'privilege_source': identity.get('privilege_source'),
                'principal': identity.get('principal') or event.get('user') or event.get('username'),
            },
            'tasks': {
                'soc_analyst': (
                    'Verify whether this is a VPN exit-node, shared NAT, or cloud provider IP rotation. '
                    'Pull sign-in logs for the principal and check device compliance, MFA method, '
                    'and session age before marking benign.'
                ),
                'threat_hunter': (
                    'Hunt for token replay: compare session IDs, refresh token families, and '
                    'device fingerprints across both source IPs. Check if a valid credential was '
                    'exfiltrated or if the same refresh token was presented from two locations. '
                    'Pivot to any AssumeRole / PIM activation chains in the same 2-hour window.'
                ),
            },
        })
    except Exception:
        pass

    return fired
