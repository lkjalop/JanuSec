"""Pre-LLM verdict seeding and HVR (Human Validation Required) gating.

Deterministic verdicts derived from observed impact fields before any LLM
enrichment runs. backfill_cluster_verdicts() in verdict_rules.py will
upgrade these once Tier-1 CoT data is available.

Compliance anchors in _VERDICT_HVR_MAP:
  GDPR Art.33, APRA CPS 234, HIPAA, and US state breach-notification laws
  require human sign-off before containment actions are treated as
  authoritative incident response.
"""
from __future__ import annotations

from typing import List

from src.api.deep_analyze.helpers import _safe_text, _collect_strings_from_row


def _derive_human_validation_required(row: dict, policy_ctx: dict, guest_ctx: dict) -> bool:
    review_state = _safe_text(row.get('review_state')).lower()
    severity = _safe_text(row.get('severity') or row.get('alert_severity')).lower()
    if guest_ctx:
        return True
    if policy_ctx and policy_ctx.get('approved_change'):
        return True
    if review_state in {'review', 'benign', 'needs_review'}:
        return True
    if severity in {'low', 'medium', 'review'}:
        return True
    return False


# Verdict → (urgency_label, hvr_override, playbook_status)
# hvr_override=None means fall through to row-evidence vote.
_VERDICT_HVR_MAP: dict = {
    'VALIDATED_BREACH':      ('URGENT',  True,  'awaiting_urgent_signoff'),
    'CONFIRMED_INTRUSION':   ('URGENT',  True,  'awaiting_urgent_signoff'),
    'LIKELY_COMPROMISE':     ('HIGH',    True,  'awaiting_signoff'),
    'SUSPICIOUS_ACTIVITY':   ('NORMAL',  None,  None),
    'INSUFFICIENT_TELEMETRY':('NORMAL',  None,  None),
    'BENIGN_EXPECTED':       ('LOW',     False, 'auto_triaged'),
}


def _apply_hvr_gating(cluster: dict, component_rows: list | None = None) -> None:
    """Attach verdict-aware human_validation_required, gate_urgency, playbook_status.

    Called twice:
    1. In _build_correlation_clusters (pre-verdict) — uses severity + row-evidence vote.
    2. In get_assessment after backfill_cluster_verdicts — upgrades to verdict-aware state.
    """
    verdict = str(cluster.get('verdict') or 'UNCERTAIN')
    severity = str(cluster.get('severity') or 'medium').lower()

    urgency, hvr_override, status_override = _VERDICT_HVR_MAP.get(
        verdict, ('NORMAL', None, None)
    )

    if hvr_override is not None:
        cluster['human_validation_required'] = hvr_override
        cluster['gate_urgency'] = urgency
        cluster['playbook_status'] = status_override
        return

    cluster['gate_urgency'] = urgency if urgency != 'NORMAL' else (
        'HIGH' if severity in ('critical', 'high') else 'NORMAL'
    )
    if component_rows:
        hvr_votes = [
            _derive_human_validation_required(
                row,
                policy_ctx=row.get('policy_change_context') or {},
                guest_ctx=row.get('guest_onboarding_context') or {},
            )
            for row in component_rows
        ]
        hvr = any(hvr_votes)
    else:
        hvr = bool(cluster.get('human_validation_required', True))

    cluster['human_validation_required'] = hvr
    cluster['playbook_status'] = 'human_gated' if hvr else 'auto_triaged'


def _initial_cluster_verdict(component_rows: List[dict], severity: str) -> dict:
    """Deterministic pre-LLM verdict from observed impact fields."""
    joined = ' '.join(_collect_strings_from_row(row).lower() for row in component_rows[:80])
    payment_impact = any(
        row.get('wire_transfer_amount_aud') not in (None, '')
        and (
            bool(row.get('bec_approval'))
            or bool(row.get('attacker_reads_approval'))
            or bool(row.get('beneficiary_account'))
            or any(token in _collect_strings_from_row(row).lower() for token in ('approval', 'beneficiary', 'payment'))
        )
        for row in component_rows
    )
    high_impact_action = any(
        bool(row.get('attacker_reads_approval'))
        or any(
            token in _collect_strings_from_row(row).lower()
            for token in (
                'ransomware staged',
                'ransomware executed',
                'malware executed',
                'confirmed exfiltration',
                'data exfiltration confirmed',
                'attacker reads approval',
            )
        )
        for row in component_rows
    )
    intrusion_observed = any(
        bool(row.get('rule_destination') and row.get('rule_name'))
        or any(
            token in _collect_strings_from_row(row).lower()
            for token in ('bcc forwarding', 'legacy imap', 'session token hijacked', 'c2 beacon', 'dns tunnel')
        )
        for row in component_rows
    )
    if payment_impact or high_impact_action:
        return {
            'verdict': 'VALIDATED_BREACH',
            'verdict_confidence': 0.88,
            'verdict_rationale': 'Deterministic evidence shows attacker action against a protected business process.',
        }
    if intrusion_observed:
        return {
            'verdict': 'CONFIRMED_INTRUSION',
            'verdict_confidence': 0.72,
            'verdict_rationale': 'Deterministic evidence shows attacker control or persistence, but no observed business impact field crossed the validated-breach threshold.',
        }
    all_rows_have_approved_change = (
        component_rows
        and all(
            (row.get('policy_change_context') or {}).get('approved_change')
            or row.get('approved_change')
            or row.get('change_ticket')
            for row in component_rows
        )
    )
    if all_rows_have_approved_change:
        return {
            'verdict': 'BENIGN_EXPECTED',
            'verdict_confidence': 0.75,
            'verdict_rationale': 'All correlated rows are linked to an approved change window.',
        }
    external_ips = [
        ip for row in component_rows
        for ip in (row.get('external_ips') or [])
    ]
    all_accounts_empty = not any(row.get('accounts') for row in component_rows)
    all_ips_internal = not external_ips
    if all_ips_internal and all_accounts_empty and len(component_rows) < 5:
        return {
            'verdict': 'INSUFFICIENT_TELEMETRY',
            'verdict_confidence': 0.60,
            'verdict_rationale': 'Cluster contains only internal IPs with no account or external pivot — insufficient telemetry to assess.',
        }
    return {
        'verdict': 'LIKELY_COMPROMISE' if severity in {'critical', 'high'} else 'SUSPICIOUS_ACTIVITY',
        'verdict_confidence': 0.55 if severity in {'critical', 'high'} else 0.35,
        'verdict_rationale': 'Correlated evidence requires investigation; no observed impact field crossed the validated-breach threshold.',
        'verdict_provisional': True,
    }
