"""Event Disposition Classifier.

Answers the question an analyst actually needs before they do anything else:
    "Is this a real attack, authorized testing, a human doing something dumb,
     a policy violation, or a false positive I should tune out?"

That single answer determines the entire response track:

  CONFIRMED_ATTACK     → SOC triage → escalation → incident                   
  RED_TEAM             → inform CISO, tag authorized, close ticket             
  HUMAN_BEHAVIOR       → nudge user directly (Teams/Slack/email) + optional LM 
  POLICY_VIOLATION     → line manager + HR, no SOC ticket                     
  GRAY_AREA            → analyst review queue, soft hold                       
  FALSE_POSITIVE       → feedback store, detection tuning candidate            

The classifier is rule-first (cheap, fast, deterministic) with a scoring
layer on top. No LLM in the hot path — the LLM is called only if you
want an explanation string, not for the routing decision itself.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Disposition enumeration
# ---------------------------------------------------------------------------

class Disposition(str, Enum):
    CONFIRMED_ATTACK    = 'confirmed_attack'    # escalate to SOC
    RED_TEAM            = 'red_team'            # authorized test — acknowledge and close
    HUMAN_BEHAVIOR      = 'human_behavior'      # user did something risky/dumb — educate
    POLICY_VIOLATION    = 'policy_violation'    # policy breach — HR/manager track
    GRAY_AREA           = 'gray_area'           # borderline — human analyst must decide
    FALSE_POSITIVE      = 'false_positive'      # tuning candidate — suppress + learn


@dataclass
class DispositionResult:
    disposition: Disposition
    confidence: float           # 0.0–1.0
    evidence_sentence: str      # one plain sentence for any audience
    response_track: str         # who acts next
    user_nudge_required: bool   # should we send the user a direct message?
    manager_notify: bool        # should the line manager hear about it?
    hr_notify: bool             # should HR hear about it?
    soc_ticket: bool            # should a SOC ticket be created?
    tuning_candidate: bool      # add to FP feedback for detection improvement?
    raw_signals: dict           # explains which signals drove the decision
    factors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Signal factor lists
# ---------------------------------------------------------------------------

# Factors that strongly point to automated/external attacks — not human behaviour
_ATTACK_SIGNALS: frozenset[str] = frozenset({
    'network:c2_beacon', 'network:c2_dns_tunnel', 'network:c2_http_beacon',
    'network:nxdomain_spike', 'network:port_scan', 'network:lateral_movement',
    'endpoint:persistence_reg_run', 'endpoint:living_off_the_land',
    'endpoint:unsigned_process', 'endpoint:privilege_escalation',
    'endpoint:process_injection', 'endpoint:ransomware_extension',
    'endpoint:shadow_copy_delete', 'endpoint:lolbin_abuse',
    'identity:privilege_escalation', 'identity:lateral_movement',
    'email:bec_replyto_mismatch', 'email:dkim_failure',
    'email:url_entropy_high', 'email:payload_dropped',
    'supply_chain:unsigned_package', 'supply_chain:vuln_cve_critical',
    'data:large_upload_untrusted_asn',
})

# Factors that are typically human mistakes, risky behaviour, or policy slip
_HUMAN_SIGNALS: frozenset[str] = frozenset({
    'email:personal_account_forwarding', 'email:sensitive_data_in_body',
    'email:external_share_sensitive', 'email:reply_all_pii',
    'identity:mfa_bypass',           # user skipped MFA pop-up
    'identity:impossible_travel',    # logged in from two far-apart locations (VPN?)
    'identity:off_hours_login',      # late night login — likely themselves
    'identity:shared_account_usage', # using a team account they shouldn't
    'data:sensitive_file_access',    # accessed a file they maybe shouldn't
    'data:personal_cloud_upload',    # uploaded work file to personal Dropbox
    'endpoint:browser_password_export',  # exported browser passwords
    'endpoint:unapproved_software_install',
    'policy:usb_storage_connected',
    'policy:screen_recording_sensitive_context',
    'policy:unapproved_ai_tool_upload',
})

# Factors that are explicit policy violations (HR track, not IT track)
_POLICY_SIGNALS: frozenset[str] = frozenset({
    'policy:data_exfil_personal_device',
    'policy:sharing_credentials',
    'policy:bypassing_dlp',
    'policy:unauthorized_external_transfer',
    'policy:removed_dlp_label',
    'policy:disclosed_confidential_externally',
})

# Factors planted during authorized red/purple team exercises
_REDTEAM_SIGNALS: frozenset[str] = frozenset({
    'redteam:authorized_simulation',
    'redteam:purple_team_exercise',
    'redteam:pentest_source_ip',
    'redteam:known_c2_framework_test',   # Cobalt Strike beacon from approved IP
})

# Factors that historically produce high FP rates (known noisy detectors)
_NOISY_SIGNALS: frozenset[str] = frozenset({
    'email:url_fresh_domain',       # marketing tools use these constantly
    'identity:new_device_login',    # most are legit — new laptop / phone
    'identity:off_hours_login',     # legitimate for global/remote teams
    'network:large_upload',         # backup jobs, video calls, CI/CD pipelines
    'endpoint:powershell_script',   # IT admin work
    'endpoint:admin_tool_run',      # IT admin work
})


# ---------------------------------------------------------------------------
# Core classifier
# ---------------------------------------------------------------------------

def classify(
    factors: list[str],
    verdict: str = '',
    triage_score: float = 0.0,
    user: str = '',
    source_ip: str = '',
    redteam_scope: list[str] | None = None,
    analyst_notes: str = '',
) -> DispositionResult:
    """Classify a set of factors into a Disposition.

    Parameters
    ----------
    factors           : list of factor strings from JanuSec analysis
    verdict           : machine verdict string ('malicious', 'suspicious', 'benign'…)
    triage_score      : 0.0–1.0 JanuSec triage score
    user              : user principal linked to the event (helps human track)
    source_ip         : originating IP (used for red team scope check)
    redteam_scope     : list of IPs / CIDRs currently in authorized red team scope
    analyst_notes     : any free-text context provided at review time
    """
    factor_set = frozenset(f.lower() for f in (factors or []))

    # -- Signals intersection --
    attack_hits   = factor_set & _ATTACK_SIGNALS
    human_hits    = factor_set & _HUMAN_SIGNALS
    policy_hits   = factor_set & _POLICY_SIGNALS
    redteam_hits  = factor_set & _REDTEAM_SIGNALS
    noisy_hits    = factor_set & _NOISY_SIGNALS

    raw_signals = {
        'attack': sorted(attack_hits),
        'human':  sorted(human_hits),
        'policy': sorted(policy_hits),
        'redteam': sorted(redteam_hits),
        'noisy':  sorted(noisy_hits),
    }

    # ------------------------------------------------------------------
    # Check 1: Authorized red team
    # ------------------------------------------------------------------
    ip_in_scope = source_ip and redteam_scope and any(
        source_ip.startswith(s.rstrip('0/').rstrip('.'))
        for s in (redteam_scope or [])
    )
    if redteam_hits or ip_in_scope:
        return DispositionResult(
            disposition=Disposition.RED_TEAM,
            confidence=0.95,
            evidence_sentence=(
                f"Activity matches {'authorized red/purple team signals' if redteam_hits else 'a currently active red team source IP'}. "
                "Do NOT create a live incident. Tag this event, notify the CISO, and archive for the purple team report."
            ),
            response_track='Notify CISO + tag authorized → close ticket → add to purple team debrief',
            user_nudge_required=False,
            manager_notify=False,
            hr_notify=False,
            soc_ticket=False,
            tuning_candidate=False,
            raw_signals=raw_signals,
            factors=list(factor_set),
        )

    # ------------------------------------------------------------------
    # Check 2: Explicit policy violation (HR track)
    # ------------------------------------------------------------------
    if policy_hits and not attack_hits:
        n = len(policy_hits)
        return DispositionResult(
            disposition=Disposition.POLICY_VIOLATION,
            confidence=0.85,
            evidence_sentence=(
                f"User {user or 'unknown'} triggered {n} policy control{'s' if n > 1 else ''} "
                f"({', '.join(sorted(policy_hits)[:2])}). "
                "This is a policy and HR matter, not a security incident requiring SOC response."
            ),
            response_track='Notify line manager + HR → assign mandatory training → document for conduct record',
            user_nudge_required=True,
            manager_notify=True,
            hr_notify=True,
            soc_ticket=False,
            tuning_candidate=False,
            raw_signals=raw_signals,
            factors=list(factor_set),
        )

    # ------------------------------------------------------------------
    # Check 3: Confirmed attack signals with high triage score
    # ------------------------------------------------------------------
    attack_score = len(attack_hits) * 0.2 + min(triage_score, 1.0)
    if attack_hits and (triage_score >= 0.65 or len(attack_hits) >= 3):
        confidence = min(0.99, 0.55 + attack_score * 0.25)
        v = verdict.lower() if verdict else ''
        is_critical = triage_score >= 0.85 or len(attack_hits) >= 4 or v in ('malicious', 'block')
        return DispositionResult(
            disposition=Disposition.CONFIRMED_ATTACK,
            confidence=round(confidence, 2),
            evidence_sentence=(
                f"{len(attack_hits)} attack signal{'s' if len(attack_hits) > 1 else ''} confirmed "
                f"({', '.join(sorted(attack_hits)[:3])}). "
                f"Triage score {triage_score:.0%}. "
                f"{'Critical severity — page on-call now.' if is_critical else 'Escalate to SOC L2 within SLA.'}"
            ),
            response_track=(
                'Page on-call SOC → open P1 incident → notify CISO + legal hold'
                if is_critical else
                'Open SOC ticket → L1 triage → L2 if not cleared in 2h → CISO if breaches SLA'
            ),
            user_nudge_required=False,
            manager_notify=False,
            hr_notify=False,
            soc_ticket=True,
            tuning_candidate=False,
            raw_signals=raw_signals,
            factors=list(factor_set),
        )

    # ------------------------------------------------------------------
    # Check 4: Human behaviour — user did something risky but probably not malicious
    # ------------------------------------------------------------------
    if human_hits and not attack_hits:
        # Pure noisy signals with no human context is a FP candidate
        only_noisy = factor_set <= (noisy_hits | human_hits) and triage_score < 0.4
        if only_noisy and not human_hits - noisy_hits:
            return DispositionResult(
                disposition=Disposition.FALSE_POSITIVE,
                confidence=0.75,
                evidence_sentence=(
                    f"All {len(factor_set)} signal(s) are from historically noisy detectors "
                    f"with a low triage score ({triage_score:.0%}). "
                    "Strong false positive candidate — consider tuning these rules."
                ),
                response_track='Add to FP feedback queue → analyst reviews suppression scope → update detector threshold',
                user_nudge_required=False,
                manager_notify=False,
                hr_notify=False,
                soc_ticket=False,
                tuning_candidate=True,
                raw_signals=raw_signals,
                factors=list(factor_set),
            )
        n = len(human_hits)
        is_repeated = 'repeated' in analyst_notes.lower() or 'again' in analyst_notes.lower()
        return DispositionResult(
            disposition=Disposition.HUMAN_BEHAVIOR,
            confidence=0.80,
            evidence_sentence=(
                f"User {user or 'unknown'} triggered {n} risky-behaviour signal{'s' if n > 1 else ''} "
                f"({', '.join(sorted(human_hits)[:2])}). "
                f"{'This is a repeat occurrence — escalate to line manager.' if is_repeated else 'First/isolated occurrence — send user a direct education nudge.'}"
            ),
            response_track=(
                'Send line manager notification + assign targeted training (repeat behaviour)'
                if is_repeated else
                'Send user a direct education nudge via Teams/Slack/email — no SOC ticket required'
            ),
            user_nudge_required=True,
            manager_notify=is_repeated,
            hr_notify=False,
            soc_ticket=False,
            tuning_candidate=False,
            raw_signals=raw_signals,
            factors=list(factor_set),
        )

    # ------------------------------------------------------------------
    # Check 5: Mixed signals — attack + human or low-confidence soup
    # ------------------------------------------------------------------
    if attack_hits and triage_score < 0.65:
        return DispositionResult(
            disposition=Disposition.GRAY_AREA,
            confidence=0.55,
            evidence_sentence=(
                f"Mixed signals: {len(attack_hits)} attack indicator(s) but low triage score ({triage_score:.0%}). "
                "Could be user activity coinciding with legitimate admin work, a misconfiguration alert, "
                "or an early-stage threat. An analyst must decide."
            ),
            response_track='Queue for analyst review within 4h → if analyst unavailable escalate to L2 → do NOT auto-close',
            user_nudge_required=False,
            manager_notify=False,
            hr_notify=False,
            soc_ticket=True,
            tuning_candidate=False,
            raw_signals=raw_signals,
            factors=list(factor_set),
        )

    # ------------------------------------------------------------------
    # Check 6: Noisy signals only — FP candidate
    # ------------------------------------------------------------------
    if noisy_hits and not attack_hits and not human_hits and triage_score < 0.45:
        return DispositionResult(
            disposition=Disposition.FALSE_POSITIVE,
            confidence=0.70,
            evidence_sentence=(
                f"Signal set consists entirely of high-noise detectors ({', '.join(sorted(noisy_hits)[:3])}). "
                f"Triage score {triage_score:.0%}. Likely a false positive — suppression recommended."
            ),
            response_track='Log FP → review suppression scope → tune detector or adjust threshold',
            user_nudge_required=False,
            manager_notify=False,
            hr_notify=False,
            soc_ticket=False,
            tuning_candidate=True,
            raw_signals=raw_signals,
            factors=list(factor_set),
        )

    # ------------------------------------------------------------------
    # Default: not enough signal to decide — gray area
    # ------------------------------------------------------------------
    return DispositionResult(
        disposition=Disposition.GRAY_AREA,
        confidence=0.40,
        evidence_sentence=(
            f"Insufficient signal to classify ({len(factor_set)} factor(s), score {triage_score:.0%}). "
            "Place in analyst review queue. Do not auto-close or auto-escalate."
        ),
        response_track='Analyst review queue → 4h hold → close with notes or escalate',
        user_nudge_required=False,
        manager_notify=False,
        hr_notify=False,
        soc_ticket=False,
        tuning_candidate=True,
        raw_signals=raw_signals,
        factors=list(factor_set),
    )


def to_dict(result: DispositionResult) -> dict[str, Any]:
    """Serialise a DispositionResult for API responses."""
    return {
        'disposition': result.disposition.value,
        'confidence': result.confidence,
        'evidence_sentence': result.evidence_sentence,
        'response_track': result.response_track,
        'actions': {
            'user_nudge': result.user_nudge_required,
            'manager_notify': result.manager_notify,
            'hr_notify': result.hr_notify,
            'soc_ticket': result.soc_ticket,
            'tuning_candidate': result.tuning_candidate,
        },
        'raw_signals': result.raw_signals,
    }
