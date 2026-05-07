"""Executive summary endpoints — all shared helpers plus the /executive-summary route.

Routes:
  POST /api/v1/assessments/{aid}/executive-summary
      Hybrid deterministic + LLM colour sentence for the home page.

All shared helper functions used by cluster_endpoints and dispatch_endpoints
are defined here and re-exported for convenience.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix='/api/v1/assessments', tags=['breach'])


def _legacy_helper(name: str, fallback):
    mod = sys.modules.get('src.api.breach_endpoints') or sys.modules.get('api.breach_endpoints')
    value = getattr(mod, name, None) if mod is not None else None
    return value if callable(value) else fallback


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_tenant(request: Request) -> str:
    return (request.headers.get('X-Tenant-ID') or
            request.headers.get('x-tenant-id') or 'default')


def _get_assessment(assessment_id: str) -> Optional[dict]:
    try:
        from src.api.deep_analyze_endpoints import _get_assessment_cached
        result = _get_assessment_cached(assessment_id)
        if result:
            _repair_assessment_runtime_fields(result)
            return result
    except Exception as _e:
        logger.debug('_get_assessment via cache failed: %s', _e)
    try:
        from src.api.deep_analyze_endpoints import REPORT_STORE
        result = REPORT_STORE.get(assessment_id)
        if result:
            _repair_assessment_runtime_fields(result)
        return result
    except Exception as _e:
        logger.warning('_get_assessment fallback failed: %s', _e)
        return None


def _persist(assessment_id: str, assessment: dict) -> None:
    try:
        from src.api.deep_analyze_endpoints import _persist_assessment_state
        _persist_assessment_state(assessment_id, assessment)
    except Exception as _e:
        logger.warning('exec_summary _persist failed for %s: %s', assessment_id, _e)


def _get_llm(model: str = 'qwen3:14b'):
    try:
        from src.integrations.llm_client import DEFAULT_CLIENT
        return DEFAULT_CLIENT
    except Exception:
        return None


def _safe_text(v: Any) -> str:
    if v is None:
        return ''
    if isinstance(v, dict):
        if v.get('username'):
            return str(v.get('username'))
        if v.get('resource') or v.get('namespace') or v.get('subresource'):
            return '/'.join(
                str(v.get(k))
                for k in ('resource', 'subresource', 'namespace', 'name')
                if v.get(k)
            )
        try:
            return json.dumps(v, sort_keys=True)
        except Exception:
            return str(v)
    return str(v)


def _display_verdict_label(verdict: Any) -> str:
    raw = _safe_text(verdict).strip().upper()
    if raw in {'VALIDATED_BREACH', 'CONFIRMED_INTRUSION', 'CONFIRMED_BREACH'}:
        return 'CONFIRMED BREACH'
    if raw == 'NO_VALIDATED_BREACH':
        return 'NO CONFIRMED BREACH'
    return raw.replace('_', ' ') if raw else 'UNCERTAIN'


_DREAD_ORDER = ('damage', 'reproducibility', 'exploitability', 'affected_users', 'discoverability')
_ROW_REF_RE = re.compile(r'\brows?\s+([0-9][0-9,\s+]*(?:\+ ?\d+ more)?)', re.I)


def _extract_row_refs_from_text(text: str, limit: int = 24) -> list[int]:
    refs: list[int] = []
    seen: set[int] = set()
    for match in _ROW_REF_RE.finditer(text or ''):
        for n in re.findall(r'\d+', match.group(1) or ''):
            try:
                value = int(n)
            except Exception:
                continue
            if value in seen:
                continue
            seen.add(value)
            refs.append(value)
            if len(refs) >= limit:
                return refs
    return refs


def _lead_dread(cluster: dict) -> tuple[dict, dict, bool]:
    prefill = cluster.get('tier1_prefill') or {}
    dn = prefill.get('dread_narrative') or {}
    frags = dn.get('fragments') or {}
    has_dread = any(_safe_text(frags.get(k)).strip() for k in _DREAD_ORDER) or bool(_safe_text(dn.get('rendered')).strip())
    return dn, frags, has_dread


def _resolve_full_cluster(cluster: dict, assessment: dict) -> dict:
    """
    Return the full correlation_cluster entry that corresponds to *cluster*.
    threat_cases are shallow copies without tier1_prefill; cross-reference using cluster_id so
    we always build the exec summary from the version that was fully enriched during ingest.
    """
    cid = cluster.get('cluster_id') or cluster.get('id')
    if not cid:
        return cluster
    for c in (assessment.get('correlation_clusters') or []):
        if (c.get('cluster_id') or c.get('id')) == cid:
            # Prefer the correlation_cluster if it has richer prefill data
            if c.get('tier1_prefill') and not cluster.get('tier1_prefill'):
                return c
            if c.get('tier1_prefill') and c.get('tier1_prefill') != cluster.get('tier1_prefill'):
                # Use whichever has the dread_narrative fragments
                dn_c = (c.get('tier1_prefill') or {}).get('dread_narrative') or {}
                dn_cl = (cluster.get('tier1_prefill') or {}).get('dread_narrative') or {}
                if dn_c.get('fragments') and not dn_cl.get('fragments'):
                    return c
            return cluster
    return cluster


# Keys that indicate the exec summary was generated with the legacy generic template.
_LEGACY_EXEC_PATTERNS = (
    'janusec found observed attacker action',
    'janusec grouped',
    'janusec identified',
    'janusec confirmed a breach in the supplied telemetry',
    'observed attacker action against a protected business process',
    'highest finding:',
)

# Verbs used in the Diamond capability chain to mark tool-pivot boundaries.
_CHAIN_ARROW = ' → '


# ── Nation-state / cross-border nexus classification ─────────────────────────
# Maps observable signals (domain TLD, naming patterns, ASN) to jurisdictions.
# Confidence is always LOW or LOW-MEDIUM from automated signals alone;
# MEDIUM / HIGH require human analyst and intelligence corroboration.
# NOTE: These are *indicators only* — never assert attribution without analyst sign-off.
_NEXUS_PROFILES: dict[str, dict] = {
    'CN': {
        'tlds': ('.cn', '.com.cn', '.gov.cn', '.net.cn'),
        'domain_keywords': ('sino', 'cnlink', 'huawei', 'alibaba', 'tencent', 'baidu'),
        # Singapore-registered front-company naming patterns associated with PRC data relay
        'sg_proxy_keywords': ('sino', 'nova', 'orient', 'dragon', 'bright'),
        'asns': frozenset({'AS4134', 'AS4837', 'AS9808', 'AS17816', 'AS58461', 'AS37963'}),
        'actor_prefixes': ('wei.', 'zhang.', 'li.', 'wang.', 'chen.', 'liu.',
                           'zhao.', 'xu.', 'sun.', 'ma.', 'hu.', 'guo.'),
        'jurisdiction': 'China (PRC)',
        'relay_jurisdiction': 'Singapore',
        'relay_note': ('Singapore-registered intermediaries are a documented PRC data-relay pattern; '
                       'does not confirm state direction without further intelligence'),
        'law_ref': 'PRC National Intelligence Law 2017 (Art. 7)',
        'regulator_action': 'ASIO/AFP',
        'authorised_possible': False,
    },
    'RU': {
        'tlds': ('.ru', '.su'),
        'domain_keywords': ('runet', 'gazprom', 'sberbank', 'vkontakte'),
        'sg_proxy_keywords': (),
        'asns': frozenset({'AS8359', 'AS12389', 'AS25478', 'AS3216', 'AS31133'}),
        'actor_prefixes': (),
        'jurisdiction': 'Russia (RF)',
        'relay_jurisdiction': None,
        'relay_note': None,
        'law_ref': 'RF Federal Law 187-FZ (Critical Information Infrastructure)',
        'regulator_action': 'ASD/AFP',
        'authorised_possible': False,
    },
    'IR': {
        'tlds': ('.ir',),
        'domain_keywords': (),
        'sg_proxy_keywords': (),
        'asns': frozenset({'AS48159', 'AS44244', 'AS197207'}),
        'actor_prefixes': (),
        'jurisdiction': 'Iran',
        'relay_jurisdiction': None,
        'relay_note': None,
        'law_ref': None,
        'regulator_action': 'ASIO/AFP',
        'authorised_possible': False,
    },
    'KP': {
        'tlds': ('.kp',),
        'domain_keywords': (),
        'sg_proxy_keywords': (),
        'asns': frozenset({'AS131279'}),
        'actor_prefixes': (),
        'jurisdiction': 'DPRK',
        'relay_jurisdiction': None,
        'relay_note': None,
        'law_ref': None,
        'regulator_action': 'ASIO/AFP',
        'authorised_possible': False,
    },
    'US_GOV': {
        'tlds': ('.gov', '.mil'),
        'domain_keywords': ('nsa.gov', 'fbi.gov', 'dhs.gov', 'cia.gov', 'cisa.gov'),
        'sg_proxy_keywords': (),
        'asns': frozenset(),
        'actor_prefixes': (),
        'jurisdiction': 'United States (Federal)',
        'relay_jurisdiction': None,
        'relay_note': ('May represent a lawful CLOUD Act order or authorised law-enforcement request; '
                       'verify with legal counsel before classifying as exfiltration'),
        'law_ref': 'CLOUD Act (18 U.S.C. § 2713)',
        'regulator_action': 'Legal counsel review',
        'authorised_possible': True,
    },
}


def _classify_nexus(
    exfil_domains: list,
    actor_names: list,
    asn_strings: list,
) -> dict:
    """
    Classify cross-border data movement signals into jurisdiction indicators.
    Returns:
      detected           — list of (state_code, profile, signals_dict) for matching states
      confidence         — 'NONE' | 'LOW' | 'LOW-MEDIUM'
      authorised_possible— True if any matched state could have lawful access (e.g. CLOUD Act)
      sg_plain_domains   — .sg domains without CN proxy naming
      sg_relay_domains   — .sg domains with CN proxy naming patterns
    Never returns HIGH confidence; that requires human analyst corroboration.
    """
    asn_set = {a.upper().strip() for a in asn_strings if a}
    cn_sg_keywords = _NEXUS_PROFILES['CN']['sg_proxy_keywords']
    sg_plain_domains: list = []
    sg_relay_domains: list = []
    for d in exfil_domains:
        if d.endswith('.sg') or '.sg.' in d:
            if any(kw in d.lower() for kw in cn_sg_keywords):
                sg_relay_domains.append(d)
            else:
                sg_plain_domains.append(d)

    detected = []
    for state_code, profile in _NEXUS_PROFILES.items():
        signals: dict[str, list] = {}
        matched_tld = [
            d for d in exfil_domains
            if any(d.endswith(t) or f'.{t.lstrip(".")}.' in d for t in profile['tlds'])
        ]
        if matched_tld:
            signals['tld'] = matched_tld
        matched_kw = [
            d for d in exfil_domains
            if any(kw in d.lower() for kw in profile.get('domain_keywords', ()))
        ]
        if matched_kw:
            signals['keyword'] = matched_kw
        if state_code == 'CN' and sg_relay_domains:
            signals['sg_relay'] = sg_relay_domains
        matched_asns = list(asn_set & profile.get('asns', frozenset()))
        if matched_asns:
            signals['asn'] = matched_asns
        matched_actors = [
            a for a in actor_names
            if any(
                a.lower().startswith(pfx) or a.lower() == pfx.rstrip('.')
                for pfx in profile.get('actor_prefixes', ())
            )
        ]
        if matched_actors:
            signals['actor'] = matched_actors
        if signals:
            detected.append((state_code, profile, signals))

    max_sig_types = max((len(s) for _, _, s in detected), default=0)
    confidence = 'LOW-MEDIUM' if max_sig_types >= 2 else ('LOW' if detected else 'NONE')
    authorised_possible = any(p.get('authorised_possible') for _, p, _ in detected)
    return {
        'detected': detected,
        'confidence': confidence,
        'authorised_possible': authorised_possible,
        'sg_plain_domains': sg_plain_domains,
        'sg_relay_domains': sg_relay_domains,
    }


def _nexus_sentence(nexus: dict, persona: str = 'ir', org_context: str = '') -> str:
    """
    Build a state-nexus indicator sentence calibrated to the audience persona and org context.

    persona:
      'ir'         — IR team: full technical indicators, regulator referral language
      'ciso'/'board'— Risk framing only, no specific state assertion
      'legal'/'gc' — Factual only: transfer observed, legal review required, no inference
      'regulator'  — Observed facts, no speculation or state attribution
    org_context:
      'merger'     — Suppress nexus assertion; substitute M&A authorisation language
      'pentest'    — Suppress entirely (authorised test context)
      ''           — Normal operation

    Returns '' if there is nothing to report.
    """
    detected = nexus.get('detected', [])
    sg_relay = nexus.get('sg_relay_domains', [])
    sg_plain = nexus.get('sg_plain_domains', [])
    confidence = nexus.get('confidence', 'NONE')

    if not detected and not sg_plain and not sg_relay:
        return ''

    # Collect all foreign domain evidence
    all_evidence_domains: list = []
    for _, _, sigs in detected:
        for stype in ('tld', 'keyword', 'sg_relay'):
            all_evidence_domains.extend(sigs.get(stype, []))
    all_evidence_domains.extend(sg_plain)
    all_evidence_domains = list(dict.fromkeys(all_evidence_domains))[:4]

    # ── M&A / merger context: suppress state attribution ──────────────────────
    if org_context == 'merger':
        dest_str = ', '.join(all_evidence_domains[:3]) or 'external destinations'
        return (
            f"Cross-border data movement detected to external destinations ({dest_str}). "
            f"If an active acquisition, merger, or due diligence process is in scope, "
            f"confirm transfer authorisation with legal counsel before classifying as exfiltration."
        )

    # ── Authorised pentest / red team context ─────────────────────────────────
    if org_context == 'pentest':
        return ''

    # ── Legal / GC persona: factual, no inference ─────────────────────────────
    if persona in ('legal', 'gc'):
        parts = []
        for _, profile, sigs in detected:
            ev = list(dict.fromkeys(d for st in ('tld', 'keyword', 'sg_relay') for d in sigs.get(st, [])))[:3]
            if ev:
                auth_note = (
                    f" Note: {profile['law_ref']} may apply if transfer originates from a government authority."
                    if profile.get('authorised_possible') and profile.get('law_ref') else ''
                )
                parts.append(
                    f"observed outbound data transfer to {', '.join(ev)} "
                    f"(destination jurisdiction indicator: {profile['jurisdiction']})"
                    f"{auth_note}"
                )
        if not parts and all_evidence_domains:
            parts.append(f"observed outbound data transfer to {', '.join(all_evidence_domains[:3])}")
        if not parts:
            return ''
        return (
            f"Legal review required: {'; '.join(parts)}. "
            f"Transfer authorisation status is unverified. "
            f"Do not assert attribution or disclose externally without legal and regulatory counsel review."
        )

    # ── Regulator persona: factual events only ────────────────────────────────
    if persona == 'regulator':
        parts = []
        for _, profile, sigs in detected:
            ev = list(dict.fromkeys(d for st in ('tld', 'keyword', 'sg_relay') for d in sigs.get(st, [])))[:3]
            if ev:
                parts.append(
                    f"outbound data transfer observed to {', '.join(ev)} "
                    f"(destination jurisdiction: {profile['jurisdiction']})"
                )
        if not parts and all_evidence_domains:
            parts.append(f"outbound data transfer observed to {', '.join(all_evidence_domains[:3])}")
        return (f"Observed: {'; '.join(parts)}." if parts else '')

    # ── CISO / Board persona: risk framing, no specific state assertion ────────
    if persona in ('ciso', 'board'):
        dest_str = ', '.join(all_evidence_domains[:3]) or 'external third-party destinations'
        return (
            f"Foreign data movement indicator: outbound transfers to unverified third-party infrastructure "
            f"({dest_str}) detected. "
            f"State-nexus assessment required — do not assert attribution in external communications "
            f"without analyst sign-off (confidence: {confidence})."
        )

    # ── IR persona (default): full technical detail ────────────────────────────
    state_blocks = []
    for state_code, profile, sigs in detected:
        ev_domains = list(dict.fromkeys(d for st in ('tld', 'keyword', 'sg_relay') for d in sigs.get(st, [])))[:3]
        actor_list = sigs.get('actor', [])
        asn_list = sigs.get('asn', [])
        jurisdiction = profile['jurisdiction']
        block_parts = [f"cross-border data movement to {jurisdiction}-associated infrastructure"]
        if ev_domains:
            block_parts.append(f"destination(s): {', '.join(ev_domains)}")
        if actor_list:
            block_parts.append(f"actor(s) with {jurisdiction}-pattern naming: {', '.join(actor_list[:2])}")
        if asn_list:
            block_parts.append(f"ASN overlap: {', '.join(asn_list[:2])}")
        if profile.get('relay_note'):
            block_parts.append(profile['relay_note'])
        if profile.get('law_ref'):
            block_parts.append(f"relevant instrument: {profile['law_ref']}")
        state_blocks.append('; '.join(block_parts))

    if not state_blocks and all_evidence_domains:
        state_blocks = [f"cross-border movement to {', '.join(all_evidence_domains[:3])} — jurisdiction unclassified"]
    if not state_blocks:
        return ''

    regulator_actions = list(dict.fromkeys(
        p.get('regulator_action', '') for _, p, _ in detected if p.get('regulator_action')
    ))
    referral_str = (
        f" {' / '.join(r for r in regulator_actions if r)} referral warranted pending analyst sign-off."
        if regulator_actions else ''
    )
    return (
        f"State-nexus risk indicator: {'; '.join(state_blocks)}. "
        f"Attribution confidence: {confidence} (automated signals only — "
        f"human analyst review required before any external disclosure or referral).{referral_str}"
    )


# ── Plain-language humanisation helpers ───────────────────────────────────
# Maps technical jargon keywords → (plain description, tech label for parens).
# Checked in order; first match wins.
_TECHNIQUE_PLAIN: list[tuple[str, str, str]] = [
    ('comsvcs',           'stole employee login credentials directly from server memory',                   'comsvcs.dll / LSASS dump'),
    ('lsass',             'stole employee login credentials directly from server memory',                   'LSASS credential dump'),
    ('pass-the-hash',     'used stolen password data to impersonate staff without knowing their real password', 'pass-the-hash relay'),
    ('ntlm',              'captured password hashes that can be used to impersonate accounts',               'NTLM hash theft'),
    ('kerberos',          'obtained authentication tokens that grant access to other systems',               'Kerberos ticket theft'),
    ('rclone',            'copied large volumes of data to external cloud storage using a sync tool',        'Rclone exfiltration'),
    ('certutil',          'installed malicious software via a trusted Windows built-in utility to avoid detection', 'certutil / LOLBin'),
    ('lolbin',            'misused built-in OS tools to evade security monitoring',                         'Living-off-the-land technique'),
    ('daemonset',         'escaped from an isolated application container to reach broader server infrastructure', 'Kubernetes privileged DaemonSet escape'),
    ('k8s',               'escaped from an isolated application container to reach broader server infrastructure', 'Kubernetes container escape'),
    ('container escape',  'escaped from an isolated application container to reach broader server infrastructure', 'container escape'),
    ('snowflake',         'bulk-exported records from the company\'s cloud analytics database',             'Snowflake COPY INTO'),
    ('bulk data unload',  'extracted a large volume of database records in a single automated operation',   'bulk data unload'),
    ('cloud sync exfil',  'transferred data to an external cloud storage service outside company control',  'cloud sync exfiltration'),
    ('assumerole',        'escalated cloud privileges by assuming another account\'s identity',              'AWS AssumeRole abuse'),
    ('privilege escalat', 'gained elevated system access beyond what their account should allow',           'privilege escalation'),
    ('lateral movement',  'moved between internal systems using stolen credentials',                        'lateral movement'),
    ('credential harvest','collected employee usernames, passwords, or session tokens',                     'credential harvesting'),
    ('payload delivery',  'delivered and installed malicious tools onto company systems',                   'payload delivery'),
    ('scheduled task',    'set up an automated task to restore attacker access after system reboots',       'scheduled task persistence'),
    ('persistence',       'established a mechanism to keep access even after the systems were restarted',   'persistence mechanism'),
    ('exfil',             'transferred company data to an external location outside company control',       'data exfiltration'),
]


def _humanize_chain_step(step: str) -> str:
    """Rewrite one arrow-chain step as plain English with the technical term in ().
    'LSASS memory access (credential harvest)' →
    'stole employee login credentials directly from server memory (LSASS credential dump)'
    """
    step_lower = step.lower()
    for match_kw, plain_text, tech_label in _TECHNIQUE_PLAIN:
        if match_kw in step_lower:
            # Capture any existing parenthesised content so we don't lose it
            paren_m = re.search(r'\(([^)]+)\)', step)
            existing_paren = (paren_m.group(1).strip() if paren_m else '')
            # If there's an existing paren, prefer it as the tech label
            # (avoids redundant "Rclone exfiltration: cloud sync exfil" duplication)
            if existing_paren:
                combined = existing_paren
            else:
                combined = tech_label
            return f'{plain_text} ({combined})'
    # No translation found — return original
    return step


def _clean_damage_text(damage: str) -> str:
    """Strip Python dict/JSON artifacts, service-account tokens, and bare email addresses
    from the raw DREAD damage fragment before display to non-technical audiences."""
    import re as _re_d
    # Strip Python dict literals  e.g. {'id': '...', 'type': 'User', ...}
    damage = _re_d.sub(r'\{[^}]{0,400}\}', '', damage)
    # Strip service-account tokens like SVC_SFL_ANALYTICS_FED
    damage = _re_d.sub(r'\bSVC_\w+\b,?\s*', '', damage)
    # Strip bare email addresses (user display names are kept via shared_users later)
    damage = _re_d.sub(r'\b[\w.+%-]+@[\w.-]+\.[a-z]{2,}\b,?\s*', '', damage)
    # Collapse leftover punctuation artefacts
    damage = _re_d.sub(r',(\s*,)+', ',', damage)
    damage = _re_d.sub(r'\bfor\s*,', 'involving', damage)  # "material for ," → "material involving"
    damage = _re_d.sub(r'\bfor\s*\.', '.', damage)
    damage = _re_d.sub(r'\s{2,}', ' ', damage).strip().strip(',').strip()
    return damage


def _humanize_intro_damage(damage: str) -> str:
    """Rewrite the technical intro damage sentence into plain English.
    Keeps all technical detail in () for analysts.
    """
    import re as _re_h
    d_lower = damage.lower()

    # Pattern: "Credential material ... was harvested via <tool>" → plain opener
    if 'credential material' in d_lower or ('credential' in d_lower and ('lsass' in d_lower or 'comsvcs' in d_lower or 'harvested' in d_lower)):
        # Extract the date range if present
        date_m = _re_h.search(r'(Between[\s\S]{0,80}?),\s+[Cc]redential', damage)
        date_prefix = date_m.group(1).strip() if date_m else ''
        # Extract the tool/method
        tool_m = _re_h.search(r'via\s+([\w./]+(?:\s+\([^)]+\))?)', damage)
        tool = tool_m.group(1).strip() if tool_m else 'a memory-extraction technique'
        # Extract risk consequence sentence if present (NTLM/pass-the-hash)
        risk_sent = ''
        if 'pass-the-hash' in d_lower or 'offline crack' in d_lower:
            risk_sent = ' These stolen credentials can be used to impersonate staff accounts without knowing their actual passwords (pass-the-hash / offline cracking attack).'
        elif 'ntlm' in d_lower:
            risk_sent = ' The stolen credential data can be used to impersonate those staff accounts (NTLM hash relay).'
        plain = (
            f"{date_prefix + ', an' if date_prefix else 'An'}"
            f" attacker stole login credentials belonging to company staff accounts"
            f" (method: {tool}).{risk_sent}"
        )
        # Clean up any residual double-article artefacts
        plain = _re_h.sub(r'\ba\s+an\b', 'an', plain)
        return plain.strip()

    # Pattern: ransomware / encryption
    if 'encrypt' in d_lower or 'ransomware' in d_lower:
        return damage  # already reasonably plain

    # Pattern: "an actor transferred data" / cloud exfil without credential context
    if re.search(r'\b(actor|attacker)\b.*\btransferred\b', d_lower) or re.search(r'\bdata.*\bexfil', d_lower):
        # Extract date range
        date_m = re.search(r'(Between\s+[\d\-]+\s+and\s+[\d\-]+)', damage)
        date_prefix = date_m.group(1) if date_m else ''
        opener = f'{date_prefix}, an' if date_prefix else 'An'
        return (
            f'{opener} attacker used compromised cloud credentials to access company systems '
            f'and transfer sensitive data outside the organisation.'
        )

    # Fallback: apply technique humanisation to each clause
    sentences = damage.split('. ')
    result = []
    for sent in sentences:
        rewritten = _humanize_chain_step(sent) if any(kw in sent.lower() for kw, *_ in _TECHNIQUE_PLAIN) else sent
        result.append(rewritten)
    return '. '.join(result)


def _build_attack_chain_exec_summary(
    cluster: dict,
    assessment: dict,
    *,
    persona: str = 'ir',
    org_context: str = '',
) -> tuple[str, str, str]:
    """
    Build a concise, evidence-specific executive summary from the attack chain.
    Prioritises enriched llm_narrative (Stage 5d) for infra/geo/cloud detail;
    falls back to DREAD/PASTA/Diamond from tier1_prefill.
    Returns (summary_text, provenance_label, attribution_confidence).
    persona:     'ir' | 'ciso' | 'board' | 'legal' | 'gc' | 'regulator'
    org_context: '' | 'merger' | 'pentest'
    """
    full = _resolve_full_cluster(cluster, assessment)
    prefill = full.get('tier1_prefill') or {}
    dn = prefill.get('dread_narrative') or {}
    frags = dn.get('fragments') or {}
    pasta = prefill.get('pasta_summary') or {}
    diamond = prefill.get('diamond_model') or {}

    # Pull enriched narrative (populated by assessment_worker Stage 5d)
    enriched = full.get('llm_narrative') or {}
    e_infra = enriched.get('attacker_infrastructure') or {}
    e_data = enriched.get('affected_data') or {}
    e_principals = enriched.get('affected_principals') or {}
    e_discovery = enriched.get('discovery') or {}

    # Extract external domains / IPs / principal actors / compliance counts from
    # assessment-level executive_summary text
    _assess_exec_text = _safe_text(assessment.get('executive_summary', '')).strip()
    _assess_ext_domains: list[str] = []
    _assess_ext_ips: list[str] = []
    _assess_principal_actors: list[str] = []
    _assess_compliance_map: dict[str, int] = {}
    if _assess_exec_text:
        import re as _re
        _dom_m = _re.search(r'External destinations?:\s*([^;\n]+?)(?:\.\s+[A-Z]|\.$|\n|$)', _assess_exec_text)
        if _dom_m:
            _assess_ext_domains = [d.strip().rstrip('.') for d in _dom_m.group(1).split(',') if d.strip()][:4]
        _ip_m = _re.search(r'external infra:\s*([0-9\., ]+)', _assess_exec_text)
        if _ip_m:
            _assess_ext_ips = [ip.strip() for ip in _ip_m.group(1).split(',') if ip.strip()][:4]
        _actor_m = _re.search(r'Principal actors?:\s*([^\.]+?)(?:\.\s+[A-Z]|\.$|Source infra|External)', _assess_exec_text)
        if _actor_m:
            _assess_principal_actors = [a.strip() for a in _actor_m.group(1).split(',') if a.strip()][:8]
        for _cnt, _fw in _re.findall(r'(\d+)\s+(apra_cps234|asd_ism|essential_eight|iso27001|nist_800_53|nist_csf)\s+control', _assess_exec_text):
            _assess_compliance_map[_fw] = int(_cnt)

    # ── Sentence 1: Initial compromise — who, how, when
    damage = _safe_text(frags.get('damage')).strip()
    intro_sentence = ''
    if damage:
        # Strip row-number references, Python dict artifacts, service accounts, raw emails
        import re as _re_row
        damage = _re_row.sub(r'\s*\(rows?\s+[\d,\s]+\)', '', damage).strip()
        damage = _clean_damage_text(damage)
        # Rewrite into plain English with technical terms in ()
        damage = _humanize_intro_damage(damage)
        clip = damage[:500]
        last_dot = clip.rfind('.')
        if last_dot > 50:
            intro_sentence = clip[:last_dot + 1]
        else:
            intro_sentence = clip[:400].rsplit(' ', 1)[0] + ('…' if len(damage) > 400 else '')

    # Inject affected accounts: merge cluster shared_users + assessment principal actors,
    # deduplicated, preserving order. Wei.zhang-pattern names appear at front if present.
    _shared_users = full.get('shared_users') or []
    _all_actors: list[str] = []
    _seen_actors: set[str] = set()
    for _u in _shared_users + _assess_principal_actors:
        _k = str(_u).lower().strip()
        if _k and _k not in _seen_actors:
            _seen_actors.add(_k)
            _all_actors.append(str(_u))
    _users_str = ', '.join(_all_actors[:8])
    if _users_str:
        if intro_sentence:
            intro_sentence = intro_sentence.rstrip('.') + f'. Compromised employee accounts: {_users_str}.'
        else:
            intro_sentence = f'Compromised employee accounts: {_users_str}.'

    # Supplement intro with specific attacker IPs + geo attribution from enriched narrative
    attacker_ips = e_infra.get('external_ips') or []
    attacker_countries = e_infra.get('countries') or []
    attacker_asns = e_infra.get('asns') or []
    # Fall back to assessment-level external IPs when enriched narrative is empty
    if not attacker_ips and _assess_ext_ips:
        attacker_ips = _assess_ext_ips
    if attacker_ips and intro_sentence:
        geo_parts = []
        if attacker_ips[:2]:
            geo_parts.append(f"attacker source IPs: {', '.join(attacker_ips[:2])}")
        if attacker_countries:
            geo_parts.append(f"origin: {', '.join(attacker_countries[:2])}")
        if attacker_asns:
            geo_parts.append(f"ASN: {attacker_asns[0]}")
        if geo_parts:
            intro_sentence = intro_sentence.rstrip('.') + f' ({"; ".join(geo_parts)}).'
    elif attacker_ips and not intro_sentence:
        geo_parts = [f"attacker IPs {', '.join(attacker_ips[:3])}"]
        if attacker_countries:
            geo_parts.append(f"origin {', '.join(attacker_countries[:2])}")
        intro_sentence = f"Attacker infrastructure observed: {'; '.join(geo_parts)}."

    # ── Sentence 2: Pivot chain — prefer enriched cloud services if present
    capability = diamond.get('capability') or []
    pivot_sentence = ''
    # Build cloud-service pivot from enriched principals / infra if richer than Diamond
    cloud_roles = e_principals.get('cloud_roles') or []
    cloud_keys = e_principals.get('cloud_access_keys') or []
    svc_accts = e_principals.get('service_accounts') or []
    staging = e_infra.get('staging_resources') or []
    cloud_pivot_parts = []
    if cloud_roles:
        _role_plain = cloud_roles[0].split('assumed-role/')[-1] if 'assumed-role/' in cloud_roles[0] else cloud_roles[0]
        cloud_pivot_parts.append(f"assumed a higher-privilege cloud identity ({_role_plain})")
    if cloud_keys:
        cloud_pivot_parts.append(f"used cloud access credentials ({cloud_keys[0]})")
    if svc_accts:
        cloud_pivot_parts.append(f"operated as a service account ({svc_accts[0]})")
    if e_data.get('tables'):
        cloud_pivot_parts.append(f"accessed database tables ({', '.join(e_data['tables'][:2])})")

    if isinstance(capability, list) and capability:
        chain_steps = [str(c).strip() for c in capability[:8] if c]
        if chain_steps:
            # Humanise each step: plain English with technical detail in ()
            plain_steps = [_humanize_chain_step(s) for s in chain_steps]
            count = len(plain_steps)
            stage_word = 'stage' if count == 1 else 'stages'
            step_list = '; '.join(f'({i+1}) {s}' for i, s in enumerate(plain_steps))
            pivot_sentence = (
                f"The attacker moved through company systems in {count} {stage_word}: {step_list}."
            )
    elif isinstance(capability, str) and capability.strip():
        # Inline arrow-chain string — split and humanise
        raw_steps = [s.strip() for s in re.split(r'\s*[→>]\s*', capability.strip()) if s.strip()]
        if raw_steps:
            plain_steps = [_humanize_chain_step(s) for s in raw_steps[:8]]
            count = len(plain_steps)
            stage_word = 'stage' if count == 1 else 'stages'
            step_list = '; '.join(f'({i+1}) {s}' for i, s in enumerate(plain_steps))
            pivot_sentence = (
                f"The attacker moved through company systems in {count} {stage_word}: {step_list}."
            )
        else:
            pivot_sentence = 'Attack path: ' + capability.strip()[:350] + '.'
    if not pivot_sentence:
        exploit = _safe_text(pasta.get('exploitation_path')).strip()
        if exploit:
            pivot_sentence = 'Attack path: ' + exploit[:300] + '.'
    if not pivot_sentence and cloud_pivot_parts:
        pivot_sentence = 'The attacker used cloud access to: ' + '; '.join(cloud_pivot_parts) + '.'
    elif pivot_sentence and cloud_pivot_parts:
        # Only append cloud detail when pivot doesn't already describe it
        _piv_low = pivot_sentence.lower()
        _already_covered = (
            'privilege escalation' in _piv_low
            or 'assumed' in _piv_low
            or 'cloud credentials' in _piv_low
        )
        if not _already_covered:
            pivot_sentence = pivot_sentence.rstrip('.') + f' Cloud access used: {"; ".join(cloud_pivot_parts[:2])}.'

    # ── Sentence 3: Data impact + exfil
    victim_data = diamond.get('victim_data') or []
    infra_raw = diamond.get('infrastructure') or []
    _EXFIL_KW = ('mega.nz', 's3://', 'backblaze', 'dropbox', 'gdrive', '.b2.', 'exfil',
                 'onedrive', 'pastebin', 'transfer.sh', 'wetransfer', 'rclone', 'hetzner')
    exfil_infra = [str(x) for x in infra_raw if any(kw in str(x).lower() for kw in _EXFIL_KW)][:3]
    # Prefer enriched exfil destinations; fall back to assessment-level external domains
    enriched_exfil = e_infra.get('exfil_destinations') or []
    all_exfil = list(dict.fromkeys(enriched_exfil[:3] + exfil_infra + _assess_ext_domains))[:4]

    data_sentence = ''
    e_tables = e_data.get('tables') or []
    e_classes = e_data.get('classes') or []
    e_records = e_data.get('record_count_estimate')
    # Filter out internal sentinel values from victim_data before display
    _JUNK_DATA = {'unknown', 'n/a', 'none', '', '-'}
    victim_data_clean = [
        d for d in (victim_data or [])
        if str(d).strip().lower().split(' ')[0] not in _JUNK_DATA
        and 'insufficient' not in str(d).lower()
        and 'metadata' not in str(d).lower()
        and len(str(d).strip()) > 2
    ]
    crown_jewel = e_data.get('crown_jewel_touched', False)

    if e_tables or victim_data_clean or e_classes:
        data_parts = []
        if crown_jewel and e_tables:
            data_parts.append(f"The organisation's most sensitive data was accessed (crown-jewel datasets: {', '.join(e_tables[:2])})")
        elif e_tables:
            data_parts.append(f"Company database records were accessed ({', '.join(e_tables[:2])})")
        elif victim_data_clean and e_classes:
            data_parts.append(f"Company data stolen: {', '.join(e_classes[:3])}")
        elif victim_data_clean:
            data_parts.append(f"Company data stolen: {', '.join(str(d) for d in victim_data_clean[:4])}")
        elif e_classes:
            data_parts.append(f"Company data stolen: {', '.join(e_classes[:3])}")
        if e_records:
            data_parts.append(f"approximately {e_records:,} records were affected")
        # Fold exfil destinations into the data sentence as a continuation, not a separate fragment
        if all_exfil:
            # Plain-language destination description
            _dest_plain = ', '.join(
                d.replace('mega.nz', 'Mega.nz (public cloud storage)')
                 .replace('backblaze', 'Backblaze (cloud backup service)')
                 .replace('dropbox', 'Dropbox')
                 .replace('onedrive', 'OneDrive')
                for d in all_exfil[:2]
            )
            if data_parts:
                data_parts[-1] = data_parts[-1] + f" — copied outside the organisation to {_dest_plain}"
            else:
                data_parts.append(f"Data was transferred outside the organisation to {_dest_plain}")
        data_sentence = '. '.join(data_parts) + '.'
    elif pasta.get('business_impact'):
        _bi = _safe_text(pasta.get('business_impact')).strip()
        # Suppress internal risk-rating placeholders (e.g. "MEDIUM risk rating — business impact requires analyst investigation")
        _bi_low = _bi.lower()
        if not ('risk rating' in _bi_low or 'requires analyst' in _bi_low or 'insufficient' in _bi_low or len(_bi) < 20):
            data_sentence = _bi[:200] + '.'

    # ── Sentence 4: Discovery + regulatory
    disc_source = e_discovery.get('source') or ''
    disc_who = e_discovery.get('who') or ''
    disc_lag = e_discovery.get('lag_seconds_from_first_evidence')
    disc_sentence = ''

    if disc_source and disc_source != 'unknown':
        _disc_labels = {
            'external_pentest': 'external penetration test',
            'edr_detection': 'EDR detection',
            'analyst': 'SOC analyst',
            'deterministic_pipeline': 'automated detection pipeline',
        }
        disc_label = _disc_labels.get(disc_source, disc_source)
        disc_sentence = f'Breach identified by {disc_label}'
        if disc_who and disc_who != 'unknown':
            disc_sentence += f' ({disc_who})'
        if disc_lag and disc_lag > 0:
            dwell_days = round(disc_lag / 86400, 1)
            disc_sentence += f'; the attacker was active for {dwell_days} days before detection (dwell time)'
        disc_sentence += '.'
    else:
        # Fall back to DREAD discoverability fragment
        disc_text = _safe_text(frags.get('discoverability')).strip()
        if disc_text:
            m_window = re.search(r'[Aa]ctivity window[:\s]+([^\.\n]+)', disc_text)
            m_who = re.search(
                r'(external[^\.\n]+|red.?team[^\.\n]+|pentest[^\.\n]+|siem[^\.\n]+|'
                r'hunt[^\.\n]+|cross-source correlation[^\.\n]+)',
                disc_text, re.IGNORECASE,
            )
            if m_window and m_who:
                disc_sentence = f'Active {m_window.group(1).strip()}; {m_who.group(1).strip()}.'
            elif m_window:
                disc_sentence = f'Activity window: {m_window.group(1).strip()}.'

    parts = [p for p in [intro_sentence, pivot_sentence, data_sentence, disc_sentence] if p]
    if not parts:
        return '', 'attack_chain_fallback', 'NONE'

    # ── Sentence 5: State-nexus / cross-border movement indicator
    # Generalised to any nation-state jurisdiction; language calibrated to persona.
    _nexus = _classify_nexus(all_exfil, _all_actors, attacker_asns or [])
    _nexus_sent = _nexus_sentence(_nexus, persona=persona, org_context=org_context)
    if _nexus_sent:
        parts.append(_nexus_sent)

    # ── Sentence 6: Business consequence + control gaps
    _control_gaps_plain = []
    _control_gaps_tech = []
    if pivot_sentence and ('assumerole' in pivot_sentence.lower() or 'assumed a higher-privilege' in pivot_sentence.lower()):
        _control_gaps_plain.append('cloud accounts were not restricted to minimum required permissions')
        _control_gaps_tech.append('AWS least-privilege / AssumeRole boundary absent')
    _combined_text = (disc_sentence + data_sentence + pivot_sentence).lower()
    if 'smb' in _combined_text or 'rdp' in _combined_text or not disc_sentence:
        _control_gaps_plain.append('systems were not isolated from each other, allowing the attacker to move freely')
        _control_gaps_tech.append('no network micro-segmentation or jump-server controls (SMB/RDP lateral movement)')
    if _assess_ext_domains:
        _control_gaps_plain.append('outbound data transfers to external services were not monitored or blocked')
        _control_gaps_tech.append('DLP not blocking outbound transfers to external domains')
    if not _control_gaps_plain:
        _control_gaps_plain.append('the attacker was able to escalate privileges and move between systems without restriction')
        _control_gaps_tech.append('privilege escalation and lateral movement controls absent')
    # Format as plain sentences with technical detail in ()
    gap_sentences = [
        f'{plain} ({tech})'
        for plain, tech in zip(_control_gaps_plain, _control_gaps_tech)
    ]
    gap_str = '; '.join(gap_sentences)
    parts.append(
        f"What this means for the organisation: The attacker gained and maintained access across multiple systems "
        f"without being detected or stopped. "
        f"Security controls that should have prevented this were missing or bypassed: {gap_str}."
    )

    # ── Sentence 7: Compliance control failures
    if _assess_compliance_map:
        _fw_labels = {
            'apra_cps234': 'APRA CPS234',
            'asd_ism': 'ASD ISM',
            'essential_eight': 'ASD Essential Eight',
            'iso27001': 'ISO 27001',
            'nist_800_53': 'NIST 800-53',
            'nist_csf': 'NIST CSF',
        }
        _fw_parts = [f"{_fw_labels.get(fw, fw)} ({cnt} control{'s' if cnt > 1 else ''})"
                     for fw, cnt in sorted(_assess_compliance_map.items(), key=lambda x: -x[1])]
        # Check proposed actions for NDB
        _proposed = assessment.get('proposed_actions') or []
        _has_ndb = any('NDB' in str(a.get('description', '')) or 'ndb' in str(a.get('action_type', '')) for a in _proposed)
        _ndb_str = ' The NDB Scheme 72-hour mandatory breach notification clock is running.' if _has_ndb else ''
        parts.append(
            f"Regulatory impact: This breach has triggered failures against {', '.join(_fw_parts)}.{_ndb_str}"
        )

    provenance = 'attack_chain_narrative+enriched' if (e_infra or e_data or _assess_compliance_map) else 'attack_chain_narrative'
    return ' '.join(parts), provenance, _nexus.get('confidence', 'NONE')


def _dread_summary_for_cluster(cluster: dict, assessment: dict, *, total_rows: int, total_sources: int, ruled_out_rows: int = 0) -> Optional[dict]:
    dn, frags, has_dread = _lead_dread(cluster)
    prefill = cluster.get('tier1_prefill') or {}
    pasta = prefill.get('pasta_summary') or {}
    diamond = prefill.get('diamond_model') or {}
    has_pasta = bool(pasta.get('threat_profile') or pasta.get('exploitation_path') or pasta.get('business_impact'))
    has_diamond = bool(diamond.get('adversary') or diamond.get('capability'))

    # Return None only when there is truly no threat-model data of any kind.
    if not has_dread and not has_pasta and not has_diamond:
        return None

    verdict = str(cluster.get('verdict') or cluster.get('final_verdict') or '').upper()
    title = _cluster_name(cluster)
    rows = len(cluster.get('row_refs') or [])
    rendered = _safe_text(dn.get('rendered')).strip()
    sabsa = _safe_text(dn.get('sabsa_coda_draft')).strip()
    body_parts: list[str] = []
    render_warning = ''

    if has_dread:
        provenance = 'dread_llm_rendered' if rendered else 'dread_deterministic_fragments'
        if rendered:
            body_parts.append(rendered)
        else:
            for key in _DREAD_ORDER:
                txt = _safe_text(frags.get(key)).strip()
                if txt:
                    body_parts.append(txt)
            if sabsa:
                body_parts.append(sabsa)
            render_warning = 'LLM render unavailable; deterministic evidence summary shown.'
    elif has_pasta:
        # PASTA fallback: stages 4 (threat profile), 5 (exploitation path), 7 (business impact)
        provenance = 'pasta_deterministic'
        if pasta.get('threat_profile'):
            body_parts.append(f"Threat actor: {pasta['threat_profile']}")
        if pasta.get('exploitation_path'):
            body_parts.append(f"Exploitation: {pasta['exploitation_path']}")
        if pasta.get('business_impact'):
            body_parts.append(f"Business impact: {pasta['business_impact']}")
        render_warning = 'DREAD narrative unavailable; PASTA threat model shown.'
    else:
        # Diamond fallback: adversary, capability, victim
        provenance = 'diamond_deterministic'
        if diamond.get('adversary'):
            body_parts.append(f"Adversary: {diamond['adversary']}")
        caps = diamond.get('capability') or []
        if caps:
            body_parts.append(f"Capabilities observed: {', '.join(caps[:5])}.")
        victims = (diamond.get('victim_users') or []) + (diamond.get('victim_data') or [])
        if victims:
            body_parts.append(f"Victim scope: {', '.join(victims[:4])}.")
        render_warning = 'DREAD/PASTA unavailable; Diamond threat model shown.'

    if ruled_out_rows:
        body_parts.append(
            f'{ruled_out_rows:,} rows were separately ruled out as authorized security test or benign context; they are excluded from the confirmed breach scope.'
        )

    joined = ' '.join(body_parts).strip()
    refs = _extract_row_refs_from_text(joined)
    why = _why_confirmed_for_cluster(cluster)
    headline_prefix = 'Likely breach - human review required' if verdict == 'LIKELY_BREACH' else 'Confirmed breach'
    _model_label = (
        'DREAD+SABSA' if has_dread else
        'PASTA threat model' if has_pasta else
        'Diamond threat model'
    )
    _subline_suffix = (
        'DREAD/SABSA evidence narrative' if has_dread else
        'PASTA threat model narrative' if has_pasta else
        'Diamond threat model narrative'
    )
    return {
        'headline': f'{headline_prefix}: {title}',
        'subline': f'{rows} evidence rows across {total_sources or 1} source{"s" if (total_sources or 1) != 1 else ""} — {_subline_suffix}',
        'executive_summary': joined,
        'deterministic': '\n'.join([f'{headline_prefix}: {title}', joined]),
        'narrative_provenance': provenance,
        'narrative_source': _model_label,
        'render_warning': render_warning,
        'evidence_refs': refs,
        'dread_fragments': frags,
        'sabsa_attributes': dn.get('sabsa_attributes') or [],
        'sabsa_coda_draft': sabsa,
        'why_confirmed': why,
        'scope': {
            'breach_rows': rows,
            'ruled_out_rows': ruled_out_rows,
            'background_rows': max(0, int(total_rows or 0) - rows - ruled_out_rows),
        },
    }


def _why_confirmed_for_cluster(cluster: dict) -> list[dict]:
    prefill = cluster.get('tier1_prefill') or {}
    dn, frags, _ = _lead_dread(cluster)
    text = ' '.join(_safe_text(frags.get(k)) for k in _DREAD_ORDER).lower()
    impact = _safe_text(prefill.get('observed_impact')).lower()
    full = text + ' ' + impact + ' ' + _safe_text(prefill.get('verdict_reasoning')).lower()
    gates = [
        ('Data movement', bool(re.search(r'exfil|copy into|unload|rclone|cloud sync|transferred data|backblaze|mega', full))),
        ('Repeated activity', bool(re.search(r'recurred|distinct days|same command|reproduc', full))),
        ('Affected users', bool(re.search(r'account|user|service_account|privileged|affected users', full))),
        ('Control gap', bool(re.search(r'no dlp|no pam|control gap|unconstrained|no inspection|no gate', full))),
        ('Crown jewel', bool(re.search(r'crown jewel|sfl_data|finance_wh|ndb|cps234', full))),
        ('Multi-source correlation', bool(re.search(r'cross-source|source types|multiple sources|correlation', full))),
    ]
    return [{'gate': name, 'confirmed': confirmed} for name, confirmed in gates]


def _cached_summary_is_stale(cached: dict, lead: dict) -> bool:
    if not cached:
        return False
    provenance = _safe_text(cached.get('narrative_provenance') or cached.get('narrative_source')).lower()
    # LLM-generated results are never considered stale — only an explicit regenerate should replace them
    if provenance.startswith('llm_') or provenance.startswith('qwen') or provenance.startswith('gpt') or provenance.startswith('claude'):
        return False
    # Already generated with the new attack chain format.
    # But mark stale if it's missing account names that are now available.
    if 'attack_chain_narrative' in provenance:
        shared_users = lead.get('shared_users') or []
        if shared_users:
            summary_text_chk = _safe_text(cached.get('executive_summary') or '').lower()
            # If none of the top-3 user accounts appear in the summary, it needs refresh
            top_users = [str(u).lower() for u in shared_users[:3] if u]
            if top_users and not any(u in summary_text_chk for u in top_users):
                return True
        return False
    # Legacy generic template text is always stale regardless of provenance
    summary_text = _safe_text(cached.get('executive_summary') or '').lower()
    if any(p in summary_text for p in _LEGACY_EXEC_PATTERNS):
        return True
    # Old DREAD-fragment concatenation (provenance contains 'deterministic' or 'dread_deterministic')
    # is stale if cluster now has richer data to build an attack chain narrative
    if any(kw in provenance for kw in ('deterministic', 'legacy', 'fallback', 'pasta_deterministic', 'diamond_deterministic')):
        return True
    return False


def _row_geo_asn(row: dict) -> dict:
    geo = row.get('_geo') if isinstance(row.get('_geo'), dict) else {}
    country = (
        row.get('geo_dst_country') or row.get('dst_country') or row.get('destination_country')
        or row.get('country') or row.get('geo_country') or row.get('geo_src_country')
        or row.get('src_country') or geo.get('dst_country') or geo.get('country') or geo.get('src_country') or ''
    )
    asn = (
        row.get('geo_dst_asn') or row.get('destination_asn') or row.get('dst_asn')
        or row.get('asn') or row.get('source_asn') or row.get('src_asn') or row.get('geo_src_asn')
        or geo.get('dst_asn') or geo.get('asn') or geo.get('src_asn') or ''
    )
    org = (
        row.get('geo_dst_org') or row.get('destination_as_org') or row.get('as_org')
        or row.get('asn_org') or row.get('source_as_org') or row.get('src_as_org')
        or geo.get('dst_org') or geo.get('as_org') or geo.get('src_org') or ''
    )
    return {'country': _safe_text(country), 'asn': _safe_text(asn), 'asn_org': _safe_text(org)}


_VERDICT_RANK = {
    'VALIDATED_BREACH':     60,
    'CONFIRMED_BREACH':     58,  # gated output of VALIDATED_BREACH — must outrank everything
    'CONFIRMED_INTRUSION':  55,
    'LIKELY_BREACH':        45,
    'LIKELY_COMPROMISE':    40,
    'SUSPICIOUS_ACTIVITY':  30,
    'INSUFFICIENT_TELEMETRY': 20,
    'BENIGN_EXPECTED':      10,
}


def _cluster_rank(cluster: dict) -> tuple[int, int, float]:
    verdict = str(cluster.get('verdict') or cluster.get('final_verdict') or '').upper()
    sev_rank = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(
        str(cluster.get('severity') or '').lower(),
        0,
    )
    try:
        conf = float(cluster.get('verdict_confidence') or cluster.get('confidence') or 0.0)
    except Exception:
        conf = 0.0
    return (_VERDICT_RANK.get(verdict, 0), sev_rank, conf)


def _cluster_rows(cluster: dict, assessment: dict) -> list[dict]:
    rows = (
        assessment.get('normalized_rows')
        or assessment.get('evidence_rows')
        or assessment.get('rows')
        or []
    )
    refs = {int(v) for v in (cluster.get('row_refs') or []) if str(v).lstrip('-').isdigit()}
    if not refs:
        return list(cluster.get('evidence_preview') or [])
    result = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key in ('row_index', 'row_number'):
            try:
                if int(row.get(key)) in refs:
                    result.append(row)
                    break
            except Exception:
                continue
    preview = [row for row in (cluster.get('evidence_preview') or []) if isinstance(row, dict)]
    if result:
        def _idx(row: dict) -> int | None:
            for key in ('row_index', 'row_number'):
                try:
                    value = row.get(key)
                    if value is not None:
                        return int(value)
                except Exception:
                    continue
            return None

        if preview and len({idx for row in result for idx in [_idx(row)] if idx is not None}) < min(len(refs), len(preview)):
            seen = set()
            merged = []
            for row in result + preview:
                idx = _idx(row)
                if idx is not None and idx in seen:
                    continue
                if idx is not None:
                    seen.add(idx)
                merged.append(row)
            return merged
        return result
    # normalized_rows/evidence_rows may not overlap with this cluster's row_refs —
    # fall back to evidence_preview which is pre-sampled against the actual refs.
    return preview


def _scope_uniq(values: list[Any], limit: int = 8) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = _safe_text(value).strip()
        if not text or text.lower() in {'-', 'n/a', 'none', 'null', 'unknown'}:
            continue
        if text.lower() in seen:
            continue
        seen.add(text.lower())
        out.append(text)
        if len(out) >= limit:
            break
    return out


def _is_public_ip_text(value: Any) -> bool:
    try:
        import ipaddress
        ip = ipaddress.ip_address(str(value))
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)
    except Exception:
        return False


def _build_affected_scope_footer(assessment: dict, sorted_clusters: list[dict], lead: dict) -> str:
    """Append-only executive scope footer for infra/network/endpoint/users."""
    scoped_clusters = [c for c in ([lead] + list(sorted_clusters[:8])) if isinstance(c, dict)]
    rows: list[dict] = []
    seen_rows: set[int] = set()
    for cluster in scoped_clusters:
        for row in _cluster_rows(cluster, assessment):
            if not isinstance(row, dict):
                continue
            marker = id(row)
            if marker in seen_rows:
                continue
            seen_rows.add(marker)
            rows.append(row)
            if len(rows) >= 400:
                break
        if len(rows) >= 400:
            break
    if not rows:
        rows = [
            row for row in (
                assessment.get('evidence_rows')
                or assessment.get('normalized_rows')
                or assessment.get('rows')
                or []
            )
            if isinstance(row, dict)
        ][:400]

    cloud_values: list[Any] = []
    subnets: list[Any] = []
    tiers: list[str] = []
    data_stores: list[str] = []
    external_ips: list[Any] = []
    destinations: list[Any] = []
    zones: list[Any] = []
    hosts: list[Any] = []
    processes: list[Any] = []
    containment: list[Any] = []
    users: list[Any] = []

    for cluster in scoped_clusters:
        users.extend(cluster.get('affected_accounts') or cluster.get('shared_users') or cluster.get('shared_accounts') or [])
        hosts.extend(cluster.get('affected_assets') or cluster.get('shared_hosts') or [])
        external_ips.extend(cluster.get('shared_ips') or [])
        prefill = cluster.get('tier1_prefill') or {}
        fragments = ((prefill.get('dread_narrative') or {}).get('fragments') or {})
        if isinstance(fragments, dict):
            fragment_text = ' '.join(_safe_text(v) for v in fragments.values())
            lower_fragment = fragment_text.lower()
            if 'backblaze' in lower_fragment:
                destinations.append('Backblaze B2')
                data_stores.append('object storage')
            if 'mega.nz' in lower_fragment or 'mega ' in lower_fragment:
                destinations.append('mega.nz')
                data_stores.append('object storage')
            if 'snowflake' in lower_fragment or 'copy into' in lower_fragment:
                data_stores.append('database')
            affected_fragment = _safe_text(fragments.get('affected_users') or '')
            if affected_fragment:
                for token in re.split(r'[:,]', affected_fragment, maxsplit=1)[-1].split(','):
                    users.append(token.strip().strip('.'))
            for token in re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', fragment_text):
                users.append(token)
        diamond = prefill.get('diamond_model') or cluster.get('diamond_model') or {}
        if isinstance(diamond, dict):
            infra = diamond.get('infrastructure') or []
            victims = diamond.get('victims') or []
            for item in (infra if isinstance(infra, list) else [infra]):
                if isinstance(item, dict):
                    external_ips.append(item.get('ip') or item.get('address') or item.get('identity'))
                    destinations.append(item.get('domain') or item.get('service') or item.get('label'))
                else:
                    destinations.append(item)
            for item in (victims if isinstance(victims, list) else [victims]):
                if isinstance(item, dict):
                    users.append(item.get('identity') or item.get('user') or item.get('account'))
                else:
                    users.append(item)

    for row in rows:
        source_type = _safe_text(row.get('_source_type') or row.get('source_type') or row.get('source')).lower()
        provider = row.get('cloud_provider') or row.get('provider') or row.get('account_id') or row.get('subscription_id')
        if provider or source_type in {'cloud', 'aws', 'azure', 'gcp', 'snowflake'}:
            cloud_values.append(provider or source_type.upper())
        for key in ('subnet', 'subnet_id', 'src_ip_cidr24', 'dst_ip_cidr24', 'vpc_subnet', 'network_cidr'):
            if row.get(key):
                subnets.append(row.get(key))
        for key in ('src_ip', 'source_ip', 'client_ip', 'remote_address', 'dst_ip', 'destination_ip', 'dest_ip', 'ip_dst'):
            value = row.get(key)
            if value and _is_public_ip_text(value):
                external_ips.append(value)
            elif value:
                tiers.append('private tier')
        text = ' '.join(_safe_text(row.get(k)) for k in (
            'event_name', 'event_type', 'object', 'resource', 'bucket', 'database',
            'table', 'service', 'operation', 'url', 'domain', 'dns_query',
        )).lower()
        if any(term in text for term in ('s3', 'bucket', 'object storage', 'blob', 'backblaze', 'mega.nz', 'wasabi')):
            data_stores.append('object storage')
        if any(term in text for term in ('snowflake', 'database', 'table', 'copy into', 'sql')):
            data_stores.append('database')
        if any(term in text for term in ('secret', 'key vault', 'secretsmanager')):
            data_stores.append('secret store')
        for key in ('domain', 'dns_query', 'sni', 'url', 'destination_domain', 'dst_domain'):
            if row.get(key):
                destinations.append(row.get(key))
        for key in ('zone', 'network_zone', 'security_zone', 'vpc', 'vpc_id'):
            if row.get(key):
                zones.append(row.get(key))
        for key in ('hostname', 'host', 'src_host', 'dest_host', 'dst_host', 'device_name', 'computer'):
            if row.get(key):
                hosts.append(row.get(key))
        for key in ('process_name', 'process', 'image', 'exe', 'command_line'):
            if row.get(key):
                processes.append(row.get(key))
        for key in ('containment_state', 'isolation_status', 'quarantine_status', 'action', 'status'):
            if row.get(key):
                containment.append(row.get(key))
        for key in ('user_canonical', 'user_principal_name', 'userPrincipalName', 'username', 'user_name', 'account', 'actor', 'user', 'email'):
            value = row.get(key)
            if isinstance(value, dict):
                value = value.get('alternateId') or value.get('login') or value.get('id') or value.get('email')
            if value:
                users.append(value)

    if external_ips:
        tiers.append('public tier')

    infrastructure = '; '.join(filter(None, [
        'Cloud: ' + ', '.join(_scope_uniq(cloud_values, 4)) if _scope_uniq(cloud_values, 4) else 'Cloud: not identified in available evidence',
        'subnet: ' + ', '.join(_scope_uniq(subnets, 4)) if _scope_uniq(subnets, 4) else 'subnet: not identified',
        'tier: ' + ', '.join(_scope_uniq(tiers, 3)) if _scope_uniq(tiers, 3) else 'tier: not identified',
        'data: ' + ', '.join(_scope_uniq(data_stores, 4)) if _scope_uniq(data_stores, 4) else 'data: not identified',
    ]))
    network = '; '.join(filter(None, [
        'external IPs: ' + ', '.join(_scope_uniq(external_ips, 8)) if _scope_uniq(external_ips, 8) else 'external IPs: not identified',
        'C2/exfil destinations: ' + ', '.join(_scope_uniq(destinations, 8)) if _scope_uniq(destinations, 8) else 'C2/exfil destinations: not identified',
        'zones: ' + ', '.join(_scope_uniq(zones, 4)) if _scope_uniq(zones, 4) else 'zones: not identified',
    ]))
    endpoint = '; '.join(filter(None, [
        'hosts: ' + ', '.join(_scope_uniq(hosts, 8)) if _scope_uniq(hosts, 8) else 'hosts: not identified',
        'processes: ' + ', '.join(_scope_uniq(processes, 6)) if _scope_uniq(processes, 6) else 'processes: not identified',
        'containment: ' + ', '.join(_scope_uniq(containment, 4)) if _scope_uniq(containment, 4) else 'containment: not identified',
    ]))
    affected_users = ', '.join(_scope_uniq(users, 10)) or 'not identified in available evidence'

    return (
        f"Infrastructure: {infrastructure}\n"
        f"Network: {network}\n"
        f"Endpoint: {endpoint}\n"
        f"Affected users: {affected_users}"
    )


_NOISY_INCIDENT_NAME_PREFIXES = (
    'day ', 'shared ', 'same ', 'identity compromise or ', 'external infrastructure ',
)


def _cluster_text(cluster: dict, rows: list[dict]) -> str:
    parts: list[str] = [
        _safe_text(cluster.get('incident_name')),
        _safe_text(cluster.get('lead_description')),
        _safe_text(cluster.get('reason_summary')),
        _safe_text(cluster.get('business_significance')),
    ]
    for row in rows[:80]:
        for key in (
            'incident_id', 'threat_actor', 'analyst_notes', 'event_type',
            'email_subject', 'email_body_summary', 'dns_query', 'sni',
            'process_name', 'event_simpleName', 'rule_name', 'rule_destination',
            'mitre_technique', 'notes', 'objectRef', 'user', 'src_ip', 'dst_ip',
            'remote_address', 'ja3', 'ja4',
        ):
            if row.get(key) not in (None, ''):
                parts.append(_safe_text(row.get(key)))
    return ' '.join(parts).lower()


def _clean_incident_name(value: Any) -> str:
    name = _safe_text(value).strip()
    if not name:
        return ''
    lowered = name.lower()
    if lowered.startswith(_NOISY_INCIDENT_NAME_PREFIXES):
        return ''
    if lowered in {'correlated incident', 'no validated breach'}:
        return ''
    if re.match(r'^unknown(?:[-_\s]*\d{4})?(?:[-_\s]*[a-z])?\s*breach$', name, re.I):
        return ''
    if lowered.startswith('day ') or ' — ' in lowered[:30] or len(name) > 72:
        return ''
    if 'cluster-' in lowered or lowered.count(';') >= 2:
        return ''
    return name


def _derive_incident_name(cluster: dict, rows: list[dict]) -> str:
    prefill = cluster.get('tier1_prefill') or {}
    clean = (
        _clean_incident_name(prefill.get('incident_name'))
        or _clean_incident_name(cluster.get('incident_name'))
    )
    if clean:
        return clean

    # Substring-match fallback removed. LLM Tier-1 prefill is the only
    # legitimate source of incident_name. If it's missing or rejected,
    # return a neutral placeholder so the gap is visible in the UI.
    logger.warning(
        'incident_name_fallback cluster_id=%s verdict=%s — LLM prefill missing/rejected',
        cluster.get('cluster_id'), cluster.get('verdict'),
    )
    verdict = (cluster.get('verdict') or 'UNCERTAIN').upper()
    row_count = len(cluster.get('row_refs') or [])
    return f'UNNAMED {verdict} CLUSTER ({row_count} ROWS)'


def _derive_incident_subtitle(cluster: dict, rows: list[dict]) -> str:
    cues = _evidence_cues(cluster, {'rows': rows})
    if cues:
        return 'Evidence: ' + ', '.join(cues)
    summary = _safe_text(cluster.get('reason_summary')).strip()
    if summary and len(summary) <= 140:
        return summary
    return f"{len(cluster.get('row_refs') or [])} correlated evidence rows"


def _repair_assessment_runtime_fields(assessment: dict) -> None:
    """Repair cached assessments that pre-date verdict gates, v2 stories, or top_links."""
    if not isinstance(assessment, dict):
        return
    clusters = assessment.get('correlation_clusters') or []
    if not isinstance(clusters, list):
        return

    try:
        from src.core.verdict_engine.verdict_rules import backfill_cluster_verdicts
        backfill_cluster_verdicts(assessment)
    except Exception:
        pass

    try:
        from src.api.deep_analyze_endpoints import _apply_hvr_gating
        for cluster in clusters:
            if isinstance(cluster, dict):
                _apply_hvr_gating(cluster)
    except Exception:
        pass

    try:
        from src.core.tier1_prefill.prefill_engine import _ensure_v2_prefill_fields
        for cluster in clusters:
            prefill = cluster.get('tier1_prefill') if isinstance(cluster, dict) else None
            if isinstance(cluster, dict) and not isinstance(prefill, dict):
                cluster_rows = _cluster_rows(cluster, assessment)
                prefill = {
                    'incident_name': _derive_incident_name(cluster, cluster_rows),
                    'headline_subtitle': _derive_incident_subtitle(cluster, cluster_rows),
                    'short_narrative': cluster.get('business_significance') or cluster.get('reason_summary') or '',
                    'top_actions': [
                        'Validate the correlated evidence rows and containment scope.',
                        'Collect the recommended missing logs before closing the incident.',
                    ],
                    'mitre_techniques': cluster.get('top_mitre') or [],
                    'confidence_meter': cluster.get('confidence_meter'),
                    '_fallback_generated': True,
                }
                cluster['tier1_prefill'] = prefill
            if isinstance(prefill, dict) and prefill.get('incident_name'):
                _ensure_v2_prefill_fields(prefill, cluster, _cluster_rows(cluster, assessment))
    except Exception:
        pass

    if any(isinstance(c, dict) and c.get('top_links') for c in clusters):
        return

    try:
        from src.api.deep_analyze_endpoints import _build_correlation_clusters, _normalize_assessment_rows
        rebuilt, _adj = _build_correlation_clusters(_normalize_assessment_rows(assessment))
    except Exception:
        return
    by_exact = {
        tuple(sorted(int(v) for v in (c.get('row_refs') or []))): c
        for c in rebuilt
        if isinstance(c, dict) and c.get('top_links')
    }
    for cluster in clusters:
        if not isinstance(cluster, dict) or cluster.get('top_links'):
            continue
        refs = tuple(sorted(int(v) for v in (cluster.get('row_refs') or []) if str(v).lstrip('-').isdigit()))
        match = by_exact.get(refs)
        if match is None and refs:
            ref_set = set(refs)
            best = None
            best_overlap = 0
            for candidate in rebuilt:
                cand_refs = set(int(v) for v in (candidate.get('row_refs') or []) if str(v).lstrip('-').isdigit())
                overlap = len(ref_set & cand_refs)
                if overlap > best_overlap:
                    best = candidate
                    best_overlap = overlap
            if best_overlap >= 2:
                match = best
        if match:
            cluster['top_links'] = match.get('top_links') or []
            if not cluster.get('reason_summary'):
                cluster['reason_summary'] = match.get('reason_summary') or ''


# ── Geo-location helpers ──────────────────────────────────────────────────────

# Approximate great-circle distances (km) between country centroids.
# Used for velocity-based impossible-travel detection.
_COUNTRY_CENTROIDS: dict[str, tuple[float, float]] = {
    'AU': (-25.3, 133.8), 'NZ': (-40.9, 174.9),
    'SG': (1.4, 103.8),   'JP': (36.2, 138.3),   'KR': (35.9, 127.8),
    'CN': (35.9, 104.2),  'IN': (20.6, 78.9),     'HK': (22.3, 114.2),
    'MY': (4.2, 101.9),   'TH': (15.9, 100.9),    'ID': (-2.5, 118.0),
    'PH': (12.9, 121.8),  'VN': (14.1, 108.3),
    'US': (38.9, -77.0),  'CA': (56.1, -106.3),   'MX': (23.6, -102.5),
    'GB': (55.4, -3.4),   'DE': (51.2, 10.5),      'FR': (46.2, 2.2),
    'NL': (52.1, 5.3),    'SE': (60.1, 18.6),      'NO': (60.5, 8.5),
    'RU': (61.5, 105.3),  'UA': (48.4, 31.2),      'PL': (51.9, 19.1),
    'BR': (-14.2, -51.9), 'AR': (-38.4, -63.6),
    'ZA': (-28.5, 24.7),  'NG': (9.1, 8.7),
    'AE': (23.4, 53.8),   'SA': (23.9, 45.1),      'IL': (31.0, 34.9),
}


# Full country name lookup — keeps UI readable for non-technical executives
_COUNTRY_NAMES: dict[str, str] = {
    'AU': 'Australia',   'NZ': 'New Zealand',
    'SG': 'Singapore',   'JP': 'Japan',         'KR': 'South Korea',
    'CN': 'China',       'IN': 'India',          'HK': 'Hong Kong',
    'MY': 'Malaysia',    'TH': 'Thailand',       'ID': 'Indonesia',
    'PH': 'Philippines', 'VN': 'Vietnam',        'TW': 'Taiwan',
    'US': 'United States', 'CA': 'Canada',       'MX': 'Mexico',
    'GB': 'United Kingdom', 'DE': 'Germany',     'FR': 'France',
    'NL': 'Netherlands', 'SE': 'Sweden',         'NO': 'Norway',
    'FI': 'Finland',     'DK': 'Denmark',        'CH': 'Switzerland',
    'AT': 'Austria',     'BE': 'Belgium',        'IT': 'Italy',
    'ES': 'Spain',       'PT': 'Portugal',       'PL': 'Poland',
    'RU': 'Russia',      'UA': 'Ukraine',        'RO': 'Romania',
    'CZ': 'Czech Republic', 'HU': 'Hungary',     'SK': 'Slovakia',
    'BR': 'Brazil',      'AR': 'Argentina',      'CO': 'Colombia',
    'CL': 'Chile',       'PE': 'Peru',
    'ZA': 'South Africa','NG': 'Nigeria',        'KE': 'Kenya',
    'EG': 'Egypt',       'MA': 'Morocco',
    'AE': 'UAE',         'SA': 'Saudi Arabia',   'IL': 'Israel',
    'TR': 'Turkey',      'IR': 'Iran',           'PK': 'Pakistan',
    'BD': 'Bangladesh',
}


def _format_geo_location(ip: str, city: str, country: str, country_code: str, asn_org: str) -> str:
    """Format a human-readable location string including technical detail in brackets."""
    cc = (country_code or '').upper()
    country_full = _COUNTRY_NAMES.get(cc) or country or cc or 'Unknown'
    city_part = city.strip() if city else ''
    location = f"{city_part}, {country_full}" if city_part else country_full

    detail_parts = [p for p in [ip, asn_org, cc] if p]
    detail = ' · '.join(detail_parts)
    return f"{location} ({detail})" if detail else location


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    import math
    r = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
    return r * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _extract_geo_from_row(row: dict) -> dict:
    """Pull geo context from whatever the event already carries."""
    geo: dict = {}

    # Okta: event.context.geographicalContext
    ctx = row.get('context') or row.get('event_context') or {}
    if isinstance(ctx, dict):
        geo_ctx = ctx.get('geographicalContext') or ctx.get('geo') or {}
        if isinstance(geo_ctx, dict):
            if geo_ctx.get('country'):
                geo['country'] = str(geo_ctx['country']).strip()
            if geo_ctx.get('city'):
                geo['city'] = str(geo_ctx['city']).strip()
            if geo_ctx.get('countryCode') or geo_ctx.get('country_code'):
                geo['country_code'] = str(geo_ctx.get('countryCode') or geo_ctx.get('country_code')).strip().upper()
            if geo_ctx.get('geolocation'):
                loc = geo_ctx['geolocation']
                if isinstance(loc, dict):
                    try:
                        geo['lat'] = float(loc.get('lat', 0))
                        geo['lon'] = float(loc.get('lon', 0))
                    except Exception:
                        pass

    # Okta: context.ipChain[0].geographicalContext
    ip_chain = ctx.get('ipChain') or []
    if isinstance(ip_chain, list) and ip_chain and isinstance(ip_chain[0], dict):
        chain_geo = ip_chain[0].get('geographicalContext') or {}
        if isinstance(chain_geo, dict) and not geo.get('country'):
            if chain_geo.get('country'):
                geo['country'] = str(chain_geo['country']).strip()
            if chain_geo.get('city'):
                geo['city'] = str(chain_geo['city']).strip()

    # Generic field scan — common across connectors
    for field in ('geo_country', 'country_name', 'country', 'geoip_country_name', 'geo_location_country'):
        val = row.get(field)
        if val and isinstance(val, str) and len(val) > 1 and not geo.get('country'):
            geo['country'] = val.strip()
            break
    for field in ('country_code', 'geo_country_code', 'geoip_country_code', 'countryCode'):
        val = row.get(field)
        if val and isinstance(val, str) and 2 <= len(val) <= 3 and not geo.get('country_code'):
            geo['country_code'] = val.strip().upper()
            break
    for field in ('geo_city', 'city', 'geoip_city_name'):
        val = row.get(field)
        if val and isinstance(val, str) and not geo.get('city'):
            geo['city'] = val.strip()
            break
    for field in ('asn', 'as_number', 'asn_number', 'geo_asn', 'autonomous_system_number'):
        val = row.get(field)
        if val is not None and not geo.get('asn'):
            geo['asn'] = str(val).strip()
            break
    for field in ('as_org', 'asn_org', 'asn_organization', 'isp', 'geo_isp', 'autonomous_system_organization'):
        val = row.get(field)
        if val and isinstance(val, str) and not geo.get('asn_org'):
            geo['asn_org'] = val.strip()
            break

    # Source IP
    for field in ('source_ip', 'src_ip', 'client_ip', 'ClientIP', 'remote_address', 'sourceIPAddress', 'ip_address'):
        val = row.get(field)
        if val and isinstance(val, str) and not geo.get('ip'):
            geo['ip'] = val.strip()
            break

    # If we have a country_code but no lat/lon, look up centroid
    if not geo.get('lat') and geo.get('country_code'):
        centroid = _COUNTRY_CENTROIDS.get(geo['country_code'].upper())
        if centroid:
            geo['lat'], geo['lon'] = centroid

    return geo


def _detect_impossible_travel(rows: list[dict]) -> list[dict]:
    """Per-user impossible travel analysis across all rows."""
    import math
    from datetime import datetime, timezone

    def _parse_ts(row: dict):
        for f in (
            'timestamp_utc', 'timestamp', '@timestamp', 'ts', 'event_ts',
            'event_time', 'start_time', 'end_time', 'time', 'published', 'created',
        ):
            v = row.get(f)
            if not v:
                continue
            try:
                s = str(v).replace('Z', '+00:00')
                return datetime.fromisoformat(s)
            except Exception:
                pass
        return None

    def _user_key(row: dict) -> str:
        for f in ('user_principal_name', 'userPrincipalName', 'username', 'user_name',
                  'actor', 'user', 'initiator', 'email'):
            v = row.get(f)
            if v and isinstance(v, str) and '@' in v or (v and isinstance(v, str) and len(v) > 2):
                return str(v).lower().strip()
            if isinstance(v, dict):
                inner = v.get('alternateId') or v.get('login') or v.get('id') or ''
                if inner:
                    return str(inner).lower().strip()
        return ''

    # Group login events by user
    user_events: dict[str, list[dict]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        user = _user_key(row)
        if not user:
            continue
        geo = row.get('_geo') or _extract_geo_from_row(row)
        if not geo.get('country') and not geo.get('country_code'):
            continue  # no geo signal — skip
        ts = _parse_ts(row)
        if not ts:
            continue
        row['_geo'] = geo
        row['_parsed_ts'] = ts
        user_events.setdefault(user, []).append(row)

    flags: list[dict] = []
    for user, events in user_events.items():
        events_sorted = sorted(events, key=lambda r: r['_parsed_ts'])
        for i in range(len(events_sorted) - 1):
            e1, e2 = events_sorted[i], events_sorted[i + 1]
            g1, g2 = e1.get('_geo', {}), e2.get('_geo', {})
            cc1 = (g1.get('country_code') or '').upper()
            cc2 = (g2.get('country_code') or '').upper()
            c1 = g1.get('country', cc1)
            c2 = g2.get('country', cc2)
            if not c1 or not c2 or c1 == c2:
                continue

            # Time delta
            dt = (e2['_parsed_ts'] - e1['_parsed_ts']).total_seconds()
            if dt <= 0:
                verdict = 'CONCURRENT_IMPOSSIBLE'
                km, km_hr = 0.0, float('inf')
            else:
                hours = dt / 3600.0
                lat1, lon1 = g1.get('lat', 0.0), g1.get('lon', 0.0)
                lat2, lon2 = g2.get('lat', 0.0), g2.get('lon', 0.0)
                if lat1 and lat2:
                    km = _haversine_km(lat1, lon1, lat2, lon2)
                    km_hr = km / hours if hours > 0 else float('inf')
                else:
                    km, km_hr = -1.0, -1.0

                if km_hr == float('inf') or km_hr > 900:
                    verdict = 'IMPOSSIBLE'
                elif km_hr > 400:
                    verdict = 'SUSPICIOUS'
                else:
                    verdict = 'PLAUSIBLE_TRAVEL'

            from_city = g1.get('city', '')
            to_city = g2.get('city', '')
            from_ip = g1.get('ip', '')
            to_ip = g2.get('ip', '')
            from_asn = g1.get('asn_org', '') or g1.get('asn', '')
            to_asn = g2.get('asn_org', '') or g2.get('asn', '')

            _APPROX_FLIGHT: dict[tuple[str, str], float] = {
                ('AU', 'SG'): 8, ('SG', 'AU'): 8,
                ('AU', 'GB'): 22, ('GB', 'AU'): 22,
                ('AU', 'US'): 17, ('US', 'AU'): 17,
                ('AU', 'JP'): 10, ('JP', 'AU'): 10,
                ('AU', 'NZ'): 3, ('NZ', 'AU'): 3,
                ('SG', 'GB'): 13, ('GB', 'SG'): 13,
                ('US', 'GB'): 8, ('GB', 'US'): 8,
                ('US', 'RO'): 11, ('RO', 'US'): 11,
                ('AU', 'RO'): 24, ('RO', 'AU'): 24,
            }
            flight_hrs = _APPROX_FLIGHT.get((cc1, cc2)) or _APPROX_FLIGHT.get((cc2, cc1))

            flags.append({
                'user': user,
                'from_country': c1,
                'from_country_code': cc1,
                'from_city': from_city,
                'from_ip': from_ip,
                'from_asn_org': from_asn,
                'from_ts': e1['_parsed_ts'].isoformat(),
                'to_country': c2,
                'to_country_code': cc2,
                'to_city': to_city,
                'to_ip': to_ip,
                'to_asn_org': to_asn,
                'to_ts': e2['_parsed_ts'].isoformat(),
                'hours_between': round(dt / 3600, 2) if dt > 0 else 0,
                'km': round(km, 0) if km >= 0 else None,
                'km_hr': round(km_hr, 0) if 0 <= km_hr < 10000 else None,
                'verdict': verdict,
                'min_flight_hours': flight_hrs,
                'row_index_from': e1.get('row_index', e1.get('row_number')),
                'row_index_to': e2.get('row_index', e2.get('row_number')),
                'from_label': _format_geo_location(from_ip, from_city, c1, cc1, from_asn),
                'to_label': _format_geo_location(to_ip, to_city, c2, cc2, to_asn),
            })

    return flags


def _geo_enrich_cluster(cluster: dict, assessment: dict) -> dict:
    """Compute geo summary for a cluster: countries, impossible travel, IAM playbook."""
    rows = _cluster_rows(cluster, assessment)
    if not rows:
        return {}

    # Attach _geo to each row
    for row in rows:
        if '_geo' not in row:
            geo = _extract_geo_from_row(row)
            if geo:
                row['_geo'] = geo

    # Unique countries seen
    countries: dict[str, int] = {}
    for row in rows:
        geo = row.get('_geo') or {}
        c = geo.get('country') or geo.get('country_code')
        if c:
            countries[c] = countries.get(c, 0) + 1

    # ASNs
    asns: dict[str, int] = {}
    for row in rows:
        geo = row.get('_geo') or {}
        if geo.get('asn_org'):
            asns[geo['asn_org']] = asns.get(geo['asn_org'], 0) + 1
        elif geo.get('asn'):
            asns[geo['asn']] = asns.get(geo['asn'], 0) + 1

    # Impossible travel
    travel_flags = _detect_impossible_travel(rows)
    impossible = [f for f in travel_flags if f['verdict'] in ('IMPOSSIBLE', 'CONCURRENT_IMPOSSIBLE')]
    suspicious = [f for f in travel_flags if f['verdict'] == 'SUSPICIOUS']
    plausible = [f for f in travel_flags if f['verdict'] == 'PLAUSIBLE_TRAVEL']

    # Derive a travel verdict for the cluster
    if impossible:
        travel_verdict = 'IMPOSSIBLE_TRAVEL'
    elif suspicious:
        travel_verdict = 'SUSPICIOUS_TRAVEL'
    elif plausible and len(countries) > 1:
        travel_verdict = 'PLAUSIBLE_TRAVEL'
    elif countries:
        travel_verdict = 'LOCAL' if len(countries) == 1 else 'MULTI_COUNTRY'
    else:
        travel_verdict = 'UNKNOWN'

    # IAM playbook: generate when travel is flagged
    iam_playbook: list[str] = []
    affected_users = list({f['user'] for f in travel_flags if f.get('user')})[:3]
    if impossible or suspicious:
        for flag in (impossible or suspicious)[:2]:
            user = flag.get('user', 'affected user')
            c1, c2 = flag.get('from_country', '?'), flag.get('to_country', '?')
            hrs = flag.get('hours_between', 0)
            iam_playbook.append(
                f"Prompt {user} via Okta/Entra step-up MFA to confirm {c2} access"
                f" ({hrs}h after {c1} login). If unconfirmed within 30 min → terminate session."
            )
    elif plausible:
        for flag in plausible[:2]:
            user = flag.get('user', 'affected user')
            c2 = flag.get('to_country', '?')
            iam_playbook.append(
                f"Verify {user} travel to {c2} is approved (check HR/calendar). "
                f"If unplanned, escalate to identity team."
            )

    return {
        'geo_countries': countries,
        'geo_asns': dict(list(asns.items())[:5]),
        'travel_flags': travel_flags[:10],
        'impossible_travel': impossible,
        'suspicious_travel': suspicious,
        'plausible_travel': plausible,
        'travel_verdict': travel_verdict,
        'geo_affected_users': affected_users,
        'iam_playbook': iam_playbook,
    }


def _verdict_bucket(verdict: str) -> str:
    v = str(verdict or '').upper()
    if v == 'VALIDATED_BREACH':
        return 'validated'
    if v == 'CONFIRMED_INTRUSION' or 'CONFIRMED' in v:
        return 'confirmed'
    if v == 'LIKELY_COMPROMISE' or 'LIKELY' in v:
        return 'likely'
    if v == 'SUSPICIOUS_ACTIVITY':
        return 'suspicious'
    if v == 'INSUFFICIENT_TELEMETRY' or 'UNCERTAIN' in v:
        return 'insufficient telemetry'
    if v == 'BENIGN_EXPECTED':
        return 'benign'
    return 'unclassified'


def _cluster_name(cluster: dict) -> str:
    prefill = cluster.get('tier1_prefill') or {}
    clean = (
        _clean_incident_name(prefill.get('incident_name'))
        or _clean_incident_name(cluster.get('incident_name'))
    )
    if clean:
        return clean
    return _derive_incident_name(cluster, [])


def _cluster_subtitle(cluster: dict) -> str:
    prefill = cluster.get('tier1_prefill') or {}
    return (
        _safe_text(prefill.get('headline_subtitle')).strip()
        or _safe_text(prefill.get('root_cause')).strip()
        or _safe_text(cluster.get('reason_summary')).strip()
        or _derive_incident_subtitle(cluster, [])
    )


def _evidence_cues(cluster: dict, assessment: dict) -> list[str]:
    rows = _cluster_rows(cluster, assessment)
    joined = ' '.join(
        _safe_text(row.get(k))
        for row in rows
        for k in (
            'analyst_notes', 'email_subject', 'email_body_summary', 'event_type',
            'rule_name', 'rule_destination', 'source_ip', 'mitre_technique',
            'wire_transfer_amount_aud', 'notes', 'objectRef', 'user', 'src_ip',
            'dst_ip', 'remote_address', 'ja3', 'ja4',
        )
        if row.get(k) not in (None, '')
    ).lower()
    cues: list[str] = []
    if any(t in joined for t in ('k8s.audit', 'kubernetes', 'daemonsets', 'pods/exec')):
        cues.append('Kubernetes privileged workload activity')
    if any(t in joined for t in ('anomalous ja3', 'ja3', 'c2', 'beacon', 'command-and-control')):
        cues.append('C2 or beaconing traffic')
    if any(t in joined for t in ('mfa fatigue', 'push', 't1621')):
        cues.append('MFA fatigue')
    if any(t in joined for t in ('bcc', 'forward', 'imap', 'mailbox')):
        cues.append('mailbox rule or legacy-mail access')
    if any(t in joined for t in ('bec', 'wire', 'payment', 'finance officer')):
        cues.append('business email compromise')
    amounts = sorted({
        _safe_text(row.get('wire_transfer_amount_aud')).strip()
        for row in rows
        if row.get('wire_transfer_amount_aud') not in (None, '')
    })
    if amounts:
        cues.append('AUD ' + ', AUD '.join(amounts[:2]) + ' payment exposure')
    if any(t in joined for t in ('dns', 'beacon', 'c2', 'command and control')):
        cues.append('C2 or DNS beaconing')
    return cues[:4]


# ── Request / Response models ─────────────────────────────────────────────────

class ExecSummaryRequest(BaseModel):
    model: str = 'qwen3:14b'
    regenerate: bool = False
    deep: bool = False  # Tier 3 deep analysis (async background job)
    persona_llm: bool = False  # Rewrite each persona narrative via LLM
    persona_subset: Optional[list[str]] = None  # Limit to specified persona keys
    # Audience calibration — controls attribution language and nexus sentence content
    persona: str = 'ir'  # 'ir' | 'ciso' | 'board' | 'legal' | 'gc' | 'regulator'
    context: str = ''    # '' | 'merger' | 'pentest' — suppresses/rewrites nexus block


# ── E9: Kill-chain phase lookup (deterministic, zero LLM) ─────────────────────

_MITRE_PHASE: dict[str, str] = {
    # Reconnaissance
    'T1595': 'Reconnaissance', 'T1592': 'Reconnaissance', 'T1589': 'Reconnaissance',
    'T1590': 'Reconnaissance', 'T1591': 'Reconnaissance', 'T1598': 'Reconnaissance',
    'T1596': 'Reconnaissance', 'T1593': 'Reconnaissance',
    # Resource Development
    'T1583': 'Resource Development', 'T1584': 'Resource Development',
    'T1585': 'Resource Development', 'T1586': 'Resource Development',
    'T1587': 'Resource Development', 'T1588': 'Resource Development',
    # Initial Access
    'T1189': 'Initial Access', 'T1190': 'Initial Access', 'T1133': 'Initial Access',
    'T1566': 'Initial Access', 'T1195': 'Initial Access', 'T1199': 'Initial Access',
    'T1078': 'Initial Access',
    # Execution
    'T1059': 'Execution', 'T1203': 'Execution', 'T1106': 'Execution',
    'T1053': 'Execution', 'T1569': 'Execution', 'T1204': 'Execution', 'T1047': 'Execution',
    # Persistence
    'T1098': 'Persistence', 'T1547': 'Persistence', 'T1136': 'Persistence',
    'T1543': 'Persistence', 'T1546': 'Persistence', 'T1574': 'Persistence',
    'T1505': 'Persistence', 'T1525': 'Persistence', 'T1556': 'Persistence',
    # Privilege Escalation
    'T1548': 'Privilege Escalation', 'T1134': 'Privilege Escalation',
    'T1484': 'Privilege Escalation', 'T1611': 'Privilege Escalation',
    'T1068': 'Privilege Escalation',
    # Defense Evasion
    'T1140': 'Defense Evasion', 'T1564': 'Defense Evasion', 'T1562': 'Defense Evasion',
    'T1070': 'Defense Evasion', 'T1036': 'Defense Evasion', 'T1027': 'Defense Evasion',
    'T1578': 'Defense Evasion', 'T1112': 'Defense Evasion',
    # Credential Access
    'T1110': 'Credential Access', 'T1003': 'Credential Access', 'T1606': 'Credential Access',
    'T1056': 'Credential Access', 'T1557': 'Credential Access', 'T1621': 'Credential Access',
    'T1539': 'Credential Access', 'T1558': 'Credential Access', 'T1552': 'Credential Access',
    # Discovery
    'T1087': 'Discovery', 'T1482': 'Discovery', 'T1083': 'Discovery',
    'T1046': 'Discovery', 'T1135': 'Discovery', 'T1069': 'Discovery',
    'T1057': 'Discovery', 'T1082': 'Discovery', 'T1016': 'Discovery',
    'T1049': 'Discovery', 'T1033': 'Discovery', 'T1518': 'Discovery',
    'T1124': 'Discovery', 'T1526': 'Discovery', 'T1538': 'Discovery',
    # Lateral Movement
    'T1210': 'Lateral Movement', 'T1534': 'Lateral Movement', 'T1570': 'Lateral Movement',
    'T1563': 'Lateral Movement', 'T1021': 'Lateral Movement', 'T1550': 'Lateral Movement',
    # Collection
    'T1560': 'Collection', 'T1119': 'Collection', 'T1530': 'Collection',
    'T1213': 'Collection', 'T1005': 'Collection', 'T1074': 'Collection',
    'T1114': 'Collection', 'T1113': 'Collection',
    # Command & Control
    'T1071': 'Command & Control', 'T1132': 'Command & Control', 'T1573': 'Command & Control',
    'T1008': 'Command & Control', 'T1105': 'Command & Control', 'T1095': 'Command & Control',
    'T1571': 'Command & Control', 'T1572': 'Command & Control', 'T1090': 'Command & Control',
    'T1219': 'Command & Control', 'T1102': 'Command & Control',
    # Exfiltration
    'T1020': 'Exfiltration', 'T1048': 'Exfiltration', 'T1041': 'Exfiltration',
    'T1567': 'Exfiltration', 'T1537': 'Exfiltration',
    # Impact
    'T1485': 'Impact', 'T1486': 'Impact', 'T1491': 'Impact', 'T1499': 'Impact',
    'T1490': 'Impact', 'T1498': 'Impact', 'T1496': 'Impact', 'T1489': 'Impact',
}

_PHASE_ORDER = [
    'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
    'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
    'Discovery', 'Lateral Movement', 'Collection', 'Data Staging', 'Command & Control',
    'Exfiltration', 'Impact',
]


def tag_kill_chain_phase(row: dict) -> str:
    """Return the kill-chain phase string for a row, or 'Unknown'."""
    for f in ('mitre_technique', 'mitre', 'technique_id', 'mitre_id'):
        val = row.get(f)
        if not val:
            continue
        techs = val if isinstance(val, list) else [val]
        for t in techs:
            t_str = str(t).strip().upper()
            # Match on base technique T1234 (strip sub-technique .001 etc.)
            base = t_str.split('.')[0]
            if base in _MITRE_PHASE:
                return _MITRE_PHASE[base]
    text = ' '.join(
        _safe_text(row.get(k))
        for k in (
            'description', 'activityDisplayName', 'operationName', 'analyst_notes',
            'command_line', 'process_command_line', 'process_name', 'event_simpleName',
            'database_name', 'warehouse_name', 'query_text', 'object_name', 'dst_ip',
            'destination_ip', 'dns_query', 'url', 'event_type'
        )
    ).lower()
    if any(token in text for token in ('copy into', 'snowflake', 'unload', 'stage', 'sfl_data', 'finance_wh')):
        return 'Data Staging'
    if any(token in text for token in ('rclone', 'backblaze', 'mega.nz', 'mega ', 'cloud sync', 'exfil', 'bytes out', 'outbound transfer')):
        return 'Exfiltration'
    if any(token in text for token in ('c2', 'command-and-control', 'command and control', 'beacon', 'dns beacon', 'udp ', 'ja3')):
        return 'Command & Control'
    if any(token in text for token in ('rundll32', 'comsvcs', 'minidump', 'lsass', 'credential', 'token theft')):
        return 'Credential Access'
    if any(token in text for token in ('processrollup', 'process rollup', 'powershell', 'cmd.exe', 'process started', 'execute')):
        return 'Execution'
    if any(token in text for token in ('collect', 'archive', 'compress', 'staging', 'file share', 'it-scripts')):
        return 'Collection'
    return 'Unknown'


def _extract_iocs(cluster: dict, rows: list[dict]) -> dict:
    """Extract all unique IOC entities from cluster rows."""
    users: set[str] = set()
    ips: set[str] = set()
    hosts: set[str] = set()
    for r in rows:
        for f in ('user', 'user_principal_name', 'username', 'account', 'entity'):
            v = str(r.get(f) or '').strip()
            if v and v not in ('-', 'N/A', 'n/a', ''):
                users.add(v)
        for f in ('src_ip', 'source_ip', 'dst_ip', 'destination_ip'):
            v = str(r.get(f) or '').strip()
            if v and v not in ('-', 'N/A', ''):
                ips.add(v)
        for f in ('hostname', 'host', 'src_host', 'device_name'):
            v = str(r.get(f) or '').strip()
            if v and v not in ('-', 'N/A', ''):
                hosts.add(v)
    return {
        'users': sorted(users),
        'ips': sorted(ips),
        'hosts': sorted(hosts),
        'cluster_id': cluster.get('cluster_id', ''),
        'severity': cluster.get('severity', ''),
        'verdict': cluster.get('verdict') or cluster.get('final_verdict', ''),
    }


# ── Route ─────────────────────────────────────────────────────────────────────

@router.post('/{assessment_id}/executive-summary')
async def get_executive_summary(
    assessment_id: str,
    body: ExecSummaryRequest,
    request: Request,
) -> JSONResponse:
    assessment = _legacy_helper('_get_assessment', _get_assessment)(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    cached = assessment.get('exec_summary_llm')

    # Prefer presentation-layer threat_cases for lead selection (they have real verdicts).
    # Fall back to correlation_clusters for full inventory stats.
    threat_cases = assessment.get('threat_cases') or []
    clusters = assessment.get('correlation_clusters') or []
    # Use threat_cases for lead ranking when available; they carry pre-assigned verdicts.
    lead_pool = threat_cases if threat_cases else clusters

    # Prefer the DuckDB-backed row count (Phase 2 ingest) over the sampled in-memory rows
    evidence_store = assessment.get('evidence_store') or {}
    total_rows = (
        evidence_store.get('row_count')
        or assessment.get('rows_processed')
        or len(assessment.get('normalized_rows') or assessment.get('evidence_rows') or assessment.get('rows') or [])
    )
    total_sources = (
        len(evidence_store.get('source_counts') or {})
        or len(set(
            str(r.get('_source') or r.get('source') or '')
            for r in (assessment.get('normalized_rows') or assessment.get('rows') or [])
            if r.get('_source') or r.get('source')
        ))
    )

    # Deterministic backbone. This must be correct without the LLM: the CEO
    # view should answer "was there a breach?" before giving extra color.
    # Count from threat_cases only when available — they are derived from clusters,
    # so iterating both causes double-counting of the same incidents.
    verdict_pool = threat_cases if threat_cases else clusters
    verdict_counts: dict[str, int] = {}
    for c in verdict_pool:
        v = str(c.get('verdict') or c.get('final_verdict') or 'UNCERTAIN').upper()
        label = _verdict_bucket(v)
        verdict_counts[label] = verdict_counts.get(label, 0) + 1

    # Surface clustering diagnostics so the frontend can show reingest prompts.
    clustering_diagnostics = assessment.get('cluster_diagnostics') or {}
    requires_reingest = bool(assessment.get('requires_reingest'))
    fallback_used = bool(assessment.get('fallback_used'))

    sorted_clusters = sorted(lead_pool, key=_cluster_rank, reverse=True)
    lead = sorted_clusters[0] if sorted_clusters else {}
    if cached and not body.regenerate and not _cached_summary_is_stale(cached, lead):
        return JSONResponse({
            'assessment_id': assessment_id,
            **cached,
            'from_cache': True,
        })
    lead_verdict = str(lead.get('verdict') or lead.get('final_verdict') or 'UNCERTAIN').upper()
    lead_name = _cluster_name(lead) if lead else 'No lead incident'
    lead_subtitle = _cluster_subtitle(lead) if lead else ''
    lead_rows = len(lead.get('row_refs') or []) if lead else 0
    lead_cluster_rows = _cluster_rows(lead, assessment) if lead else []
    lead_cues = _evidence_cues(lead, assessment) if lead else []

    def _uniq(values: list[Any], limit: int) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for value in values:
            text = _safe_text(value).strip()
            if not text or text in {'-', 'N/A', 'n/a'}:
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(text)
            if len(out) >= limit:
                break
        return out

    row_accounts = _uniq([
        row.get(k)
        for row in lead_cluster_rows
        for k in ('user_principal_name', 'userPrincipalName', 'username', 'user_name', 'UserId', 'user', 'account', 'actor', 'email')
    ], 5)
    row_ips = _uniq([
        row.get(k)
        for row in lead_cluster_rows
        for k in ('source_ip', 'src_ip', 'client_ip', 'ClientIP', 'remote_address', 'sourceIPAddress', 'dst_ip', 'destination_ip')
    ], 5)
    # RFC 5737 documentation/test-net ranges (192.0.2.x, 198.51.100.x, 203.0.113.x) are used
    # for synthetic or pentest data and must never appear in breach entity context.
    _TESTNET_PREFIXES = ('192.0.2.', '198.51.100.', '203.0.113.')
    row_ips = [ip for ip in row_ips if not any(ip.startswith(p) for p in _TESTNET_PREFIXES)]
    row_assets = _uniq([
        row.get(k)
        for row in lead_cluster_rows
        for k in ('hostname', 'host', 'device_name', 'ComputerName', 'database_name', 'warehouse_name')
    ], 5)
    row_times = sorted(_uniq([
        row.get(k)
        for row in lead_cluster_rows
        for k in ('timestamp_utc', 'timestamp', '@timestamp', 'event_ts', 'event_time', 'start_time', 'end_time', 'time', 'ts')
    ], 200))
    entity_context = ''
    if row_accounts or row_assets or row_ips:
        bits = []
        if row_accounts:
            bits.append('accounts ' + ', '.join(row_accounts[:3]))
        if row_assets:
            bits.append('assets ' + ', '.join(row_assets[:3]))
        if row_ips:
            bits.append('IPs ' + ', '.join(row_ips[:3]))
        entity_context = '; '.join(bits)

    # Geo enrichment for lead cluster (compute once, reuse in both deterministic + LLM paths)
    lead_geo: dict = {}
    if lead:
        try:
            lead_geo = _geo_enrich_cluster(lead, assessment)
            lead['_geo_summary'] = lead_geo  # cache on cluster for UI access
        except Exception as _geo_err:
            logger.debug('geo_enrich_failed: %s', _geo_err)
    counts_text = ', '.join(
        f"{count} {label}"
        for label, count in sorted(verdict_counts.items(), key=lambda x: (-x[1], x[0]))
    ) or '0 findings'
    ruled_out_rows = sum(
        len(c.get('row_refs') or [])
        for c in clusters
        if _verdict_bucket(str(c.get('verdict') or c.get('final_verdict') or '').upper()) == 'benign'
    )
    # Geo addendum for deterministic text
    geo_travel = lead_geo.get('travel_verdict', '')
    geo_countries = lead_geo.get('geo_countries') or {}
    geo_impossible = lead_geo.get('impossible_travel') or []
    geo_suspicious = lead_geo.get('suspicious_travel') or []
    geo_plausible = lead_geo.get('plausible_travel') or []
    geo_addendum = ''
    if geo_impossible:
        f0 = geo_impossible[0]
        from_lbl = f0.get('from_label') or f0.get('from_country', '?')
        to_lbl = f0.get('to_label') or f0.get('to_country', '?')
        hrs = f0.get('hours_between')
        flight = f0.get('min_flight_hours')
        geo_addendum = (
            f" Impossible travel: {f0.get('user', 'the affected user')} logged in from"
            f" {from_lbl}, then {to_lbl}"
            + (f" — only {hrs}h apart" if hrs is not None else '')
            + (f" (minimum flight time: {flight}h)" if flight else '')
            + '. This is a strong indicator of stolen credentials.'
        )
    elif geo_suspicious:
        f0 = geo_suspicious[0]
        from_lbl = f0.get('from_label') or f0.get('from_country', '?')
        to_lbl = f0.get('to_label') or f0.get('to_country', '?')
        hrs = f0.get('hours_between')
        geo_addendum = (
            f" Suspicious travel: {f0.get('user', 'the affected user')} accessed from"
            f" {from_lbl}, then {to_lbl}"
            + (f" ({hrs}h apart — high velocity)" if hrs is not None else '')
            + '.'
        )
    elif geo_plausible and geo_countries:
        f0 = geo_plausible[0]
        from_lbl = f0.get('from_label') or f0.get('from_country', '?')
        to_lbl = f0.get('to_label') or f0.get('to_country', '?')
        hrs = f0.get('hours_between')
        flight = f0.get('min_flight_hours')
        geo_addendum = (
            f" Overseas access: {f0.get('user', 'the affected user')} logged in from"
            f" {to_lbl}"
            + (f", {hrs}h after their login from {from_lbl}" if hrs is not None else f" (previously accessed from {from_lbl})")
            + (f". A direct flight takes approximately {flight}h — consistent with business travel." if flight else '. Geographically plausible — verify with HR or travel calendar.')
        )

    dread_summary = _dread_summary_for_cluster(
        _resolve_full_cluster(lead, assessment),
        assessment,
        total_rows=int(total_rows or 0),
        total_sources=int(total_sources or 0),
        ruled_out_rows=ruled_out_rows,
    ) if lead else None

    # Build the attack chain narrative (deterministic, evidence-specific, no LLM needed).
    # IMPORTANT: use _resolve_full_cluster so that tier1_prefill (DREAD, Diamond, PASTA, enriched
    # llm_narrative) is present — without this _build_attack_chain_exec_summary returns empty.
    attack_chain_exec, attack_chain_provenance, _nexus_confidence = (
        _build_attack_chain_exec_summary(
            _resolve_full_cluster(lead, assessment), assessment,
            persona=body.persona, org_context=body.context,
        )
        if lead else ('', 'fallback', 'NONE')
    )

    if lead and lead_verdict in {'VALIDATED_BREACH', 'CONFIRMED_INTRUSION', 'CONFIRMED_BREACH', 'LIKELY_BREACH'}:
        headline = f"Confirmed breach: {lead_name}"
        subline = (
            f"{lead_rows} evidence rows"
            + (f" across {total_sources} sources" if total_sources else '')
            + (f" link {', '.join(lead_cues)}" if lead_cues else ' — attack chain reconstructed')
        )
        if attack_chain_exec:
            executive_summary = attack_chain_exec + (geo_addendum if geo_addendum else '')
        elif dread_summary:
            executive_summary = dread_summary['executive_summary']
        else:
            executive_summary = (
                f"Confirmed multi-phase intrusion. Lead incident: {lead_name}. "
                + (f"Evidence involves {entity_context}. " if entity_context else '')
                + (f"Indicators: {', '.join(lead_cues)}. " if lead_cues else '')
                + geo_addendum
            )
    elif lead:
        headline = f"Highest finding: {lead_verdict} — {lead_name}"
        subline = (
            f"{lead_rows} evidence rows"
            + (f" across {total_sources} sources" if total_sources else '')
            + " require investigation before breach validation."
        )
        if attack_chain_exec:
            executive_summary = attack_chain_exec
        elif dread_summary:
            executive_summary = dread_summary['executive_summary']
        else:
            executive_summary = (
                f"{len(clusters)} threat cases from {total_rows} rows"
                + (f" across {total_sources} sources" if total_sources else '')
                + f": {counts_text}. Lead finding: {lead_name}."
                + geo_addendum
            )
    elif requires_reingest or lead_verdict == 'ANALYSIS_INCOMPLETE':
        headline = 'Analysis incomplete — re-ingest required'
        stale_pct = clustering_diagnostics.get('stale_rows', 0)
        subline = (
            'Telemetry was stored with an outdated normalizer and could not be clustered. '
            'Re-upload the source files to generate a typed assessment.'
        )
        executive_summary = subline
        if stale_pct:
            executive_summary += f' ({stale_pct} stale rows detected.)'
        attack_chain_provenance = 'analysis_incomplete'
    else:
        headline = 'No confirmed breach found'
        subline = f'No correlated incident clusters were found in {total_rows} rows.'
        executive_summary = subline
        attack_chain_provenance = 'no_breach'
    deterministic = '\n'.join([headline, subline, executive_summary])

    # Attempt LLM narrative for the executive_summary body.
    llm_color: Optional[str] = None
    _llm_ran = False
    if lead and body.regenerate:
        try:
            llm = _legacy_helper('_get_llm', _get_llm)(body.model)
            lead_prefill = lead.get('tier1_prefill') or {}
            mitre_tags = lead_prefill.get('mitre_techniques') or lead.get('mitre_tags') or []
            mitre_str = ', '.join(mitre_tags[:6]) if mitre_tags else ''

            raw_accounts = (
                lead_prefill.get('affected_users')
                or lead.get('shared_users')
                or lead.get('shared_accounts')
                or lead.get('affected_accounts')
                or row_accounts
            )
            accounts_str = ', '.join([str(a) for a in raw_accounts[:6] if a]) or ''

            raw_ips = (
                lead.get('shared_external_ips')
                or lead.get('external_ips')
                or lead.get('shared_ips')
                or lead_prefill.get('source_ips')
                or row_ips
            )
            ips_str = ', '.join([str(ip) for ip in raw_ips[:5] if ip]) or ''

            raw_assets = (
                lead.get('shared_hosts')
                or lead.get('affected_assets')
                or lead_prefill.get('affected_assets')
                or row_assets
            )
            assets_str = ', '.join([str(a) for a in raw_assets[:4] if a]) or ''

            chain_steps = lead_prefill.get('evidence_chain') or []
            ts_list = [s.get('timestamp') or s.get('ts') for s in chain_steps if s.get('timestamp') or s.get('ts')]
            if not ts_list:
                ts_list = row_times
            ts_list = sorted([str(t) for t in ts_list if t])
            time_range_str = f"{ts_list[0]} to {ts_list[-1]}" if len(ts_list) >= 2 else ''

            chain_summary = ''
            if chain_steps:
                chain_summary = ' → '.join(
                    str(s.get('what') or s.get('event') or s.get('description') or '')
                    for s in chain_steps[:7] if s.get('what') or s.get('event') or s.get('description')
                )

            business_context = (
                lead_prefill.get('business_significance')
                or lead.get('business_significance')
                or ''
            )

            dn = lead_prefill.get('dread_narrative') or {}
            frags = dn.get('fragments') or {}
            dread_damage = _safe_text(frags.get('damage')).strip()
            dread_affected = _safe_text(frags.get('affected_users')).strip()
            dread_exploit = _safe_text(frags.get('exploitability')).strip()
            dread_discover = _safe_text(frags.get('discoverability')).strip()
            dread_rendered = _safe_text(dn.get('rendered')).strip()

            pasta = lead_prefill.get('pasta_summary') or {}
            pasta_exploitation = _safe_text(pasta.get('exploitation_path')).strip()
            pasta_impact = _safe_text(pasta.get('business_impact')).strip()
            pasta_threat = _safe_text(pasta.get('threat_profile')).strip()

            diamond = lead_prefill.get('diamond_model') or {}
            diamond_caps = diamond.get('capability') or []
            diamond_victim_data = diamond.get('victim_data') or []
            diamond_infra = diamond.get('infrastructure') or []
            diamond_caps_str = ', '.join(str(c) for c in diamond_caps[:6]) if diamond_caps else ''
            diamond_data_str = ', '.join(str(d) for d in diamond_victim_data[:4]) if diamond_victim_data else ''

            enriched = lead.get('llm_narrative') or {}
            infra = enriched.get('attacker_infrastructure') or {}
            exfil_dests = infra.get('exfil_destinations') or lead.get('exfil_destinations') or []
            staging_res = infra.get('staging_resources') or []
            exfil_str = ', '.join(str(x) for x in exfil_dests[:4]) if exfil_dests else ''
            staging_str = ', '.join(str(s) for s in staging_res[:3]) if staging_res else ''

            affected_data = enriched.get('affected_data') or {}
            crown_jewel = affected_data.get('crown_jewel_touched', False)
            sensitive_tables = affected_data.get('tables') or []
            data_classes = affected_data.get('classes') or []
            record_est = affected_data.get('record_count_estimate')
            crown_jewel_str = ', '.join(str(t) for t in sensitive_tables[:3]) if sensitive_tables else ''

            discovery = enriched.get('discovery') or {}
            disc_source = discovery.get('source') or ''
            disc_who = discovery.get('who') or ''
            disc_lag_secs = discovery.get('lag_seconds_from_first_evidence')
            dwell_days = round(disc_lag_secs / 86400, 1) if disc_lag_secs else None

            principals = enriched.get('affected_principals') or {}
            cloud_keys = principals.get('cloud_access_keys') or []
            cloud_keys_str = ', '.join(str(k) for k in cloud_keys[:2]) if cloud_keys else ''

            context_parts = [f"Assessment verdict: {lead_verdict}. Incident: {lead_name}."]
            context_parts.append(f"Evidence: {lead_rows} rows across {total_sources} sources.")
            if accounts_str:
                context_parts.append(f"Affected accounts: {accounts_str}.")
            if ips_str:
                context_parts.append(f"Attacker IPs: {ips_str}.")
            if assets_str:
                context_parts.append(f"Affected systems: {assets_str}.")
            if time_range_str:
                context_parts.append(f"Breach window: {time_range_str}.")
            if dwell_days:
                context_parts.append(f"Dwell time before detection: {dwell_days} days.")
            if disc_source and disc_who:
                context_parts.append(f"Discovery method: {disc_source} by {disc_who}.")
            if chain_summary:
                context_parts.append(f"Attack chain: {chain_summary}.")
            if mitre_str:
                context_parts.append(f"MITRE techniques: {mitre_str}.")
            if business_context:
                context_parts.append(f"Business significance: {business_context}.")
            if lead_cues:
                context_parts.append(f"Key indicators: {', '.join(lead_cues[:6])}.")
            if dread_damage:
                context_parts.append(f"DAMAGE: {dread_damage}")
            if dread_affected:
                context_parts.append(f"AFFECTED: {dread_affected}")
            if dread_exploit:
                context_parts.append(f"EXPLOITATION: {dread_exploit}")
            if dread_discover:
                context_parts.append(f"DISCOVERY: {dread_discover}")
            if dread_rendered and not dread_damage:
                context_parts.append(f"Threat narrative: {dread_rendered[:500]}")
            if pasta_threat and not dread_damage:
                context_parts.append(f"Threat actor: {pasta_threat}")
            if pasta_exploitation and not dread_exploit:
                context_parts.append(f"Exploitation path: {pasta_exploitation}")
            if pasta_impact and not business_context:
                context_parts.append(f"Business impact: {pasta_impact}")
            if diamond_caps_str and not chain_summary:
                context_parts.append(f"Attacker capabilities: {diamond_caps_str}.")
            if diamond_data_str and not crown_jewel_str:
                context_parts.append(f"Data assets compromised: {diamond_data_str}.")
            if exfil_str:
                context_parts.append(f"Exfiltration destinations: {exfil_str}.")
            if staging_str:
                context_parts.append(f"Staging resources: {staging_str}.")
            if crown_jewel:
                context_parts.append(f"CROWN JEWEL DATA ACCESSED: {crown_jewel_str or 'sensitive restricted tables'}.")
            elif crown_jewel_str:
                context_parts.append(f"Sensitive tables accessed: {crown_jewel_str}.")
            if data_classes:
                context_parts.append(f"Data classes: {', '.join(data_classes[:4])}.")
            if record_est:
                context_parts.append(f"Estimated records exfiltrated: {record_est:,}.")
            # Inject assessment-level deterministic intelligence (external IPs, principal actors,
            # external domains) as supplementary context so the LLM can name names even when
            # enriched llm_narrative fields are sparse.
            _det_exec = assessment.get('executive_summary', '')
            if _det_exec and len(_det_exec) > 50:
                context_parts.append(f"Assessment intelligence (use as additional context): {_det_exec[:700]}")
            if cloud_keys_str:
                context_parts.append(f"Cloud access keys compromised: {cloud_keys_str}.")

            if geo_impossible:
                f0 = geo_impossible[0]
                from_lbl = f0.get('from_label') or f0.get('from_country', '?')
                to_lbl = f0.get('to_label') or f0.get('to_country', '?')
                hrs = f0.get('hours_between')
                flight = f0.get('min_flight_hours')
                context_parts.append(
                    f"CRITICAL — Impossible travel: {f0.get('user')} logged in from"
                    f" {from_lbl}, then {to_lbl}"
                    + (f" — only {hrs}h apart" if hrs is not None else '')
                    + (f" (min flight: {flight}h)" if flight else '')
                    + ". This indicates stolen credentials used by a remote attacker."
                )
            elif geo_suspicious:
                f0 = geo_suspicious[0]
                from_lbl = f0.get('from_label') or f0.get('from_country', '?')
                to_lbl = f0.get('to_label') or f0.get('to_country', '?')
                context_parts.append(
                    f"Suspicious travel: {f0.get('user')} accessed from {from_lbl},"
                    f" then {to_lbl}"
                    + (f" ({f0.get('hours_between')}h apart — high velocity)." if f0.get('hours_between') is not None else '.')
                )
            elif geo_plausible:
                f0 = geo_plausible[0]
                from_lbl = f0.get('from_label') or f0.get('from_country', '?')
                to_lbl = f0.get('to_label') or f0.get('to_country', '?')
                hrs = f0.get('hours_between')
                flight = f0.get('min_flight_hours')
                context_parts.append(
                    f"Overseas access (likely business travel): {f0.get('user')} logged in from"
                    f" {to_lbl}, {hrs}h after login from {from_lbl}."
                    + (f" A direct flight takes ~{flight}h — geographically consistent." if flight else " Travel is geographically plausible.")
                    + " Recommend verifying with HR or travel calendar before escalating."
                )
            if geo_countries and len(geo_countries) > 1:
                formatted_countries = [
                    _COUNTRY_NAMES.get(cc.upper(), cc) + f" ({cc})"
                    for cc in list(geo_countries.keys())[:5]
                ]
                context_parts.append(
                    f"Logins observed from {len(geo_countries)} countries: {', '.join(formatted_countries)}."
                )

            if attack_chain_exec:
                context_parts.insert(0, f"ATTACK CHAIN NARRATIVE (use as basis, improve prose):\n{attack_chain_exec}")

            prompt = (
                "You are a senior security analyst writing an executive briefing for a CISO and board.\n"
                "Use ONLY the evidence provided below. Do not invent facts not present in the evidence.\n"
                "Format: 3-4 sentences of clear, factual English — no bullet points, no headers.\n"
                "Sentence 1: Who was compromised, how (name accounts, tools, IPs from evidence).\n"
                "Sentence 2: The pivot chain — how the attacker moved laterally and what data was accessed or exfiltrated.\n"
                "Sentence 3: How the breach was discovered and dwell time.\n"
                "Sentence 4 (if applicable): Regulatory exposure and most urgent containment action.\n"
                "Do not start with 'The'. Do not repeat the incident name or assessment metadata.\n"
                "Be specific — use the exact account names, IPs, tools, table names from the evidence.\n\n"
                "EVIDENCE:\n"
                + "\n".join(context_parts)
            )
            _LLM_TIMEOUT = int(os.getenv('EXEC_SUMMARY_LLM_TIMEOUT', '120'))
            resp = await asyncio.wait_for(
                asyncio.to_thread(
                    llm.generate,
                    prompt,
                    400,
                    None,
                    {'ollama_model': body.model},
                    body.model,
                ),
                timeout=_LLM_TIMEOUT,
            )
            llm_text = (resp.get('text') or '').strip()
            if llm_text and len(llm_text) > 30 and not llm_text.startswith('{'):
                executive_summary = llm_text
                _llm_ran = True
        except asyncio.TimeoutError:
            logger.warning('exec_summary LLM timed out after %ss — using deterministic fallback', _LLM_TIMEOUT)
        except Exception as _llm_err:
            logger.warning('exec_summary LLM failed: %s — using deterministic fallback', _llm_err)

    cluster_headlines = []
    for c in sorted_clusters[:3]:
        prefill = c.get('tier1_prefill') or {}
        cluster_headlines.append({
            'verdict': c.get('verdict') or c.get('final_verdict') or 'UNCERTAIN',
            'incident_name': prefill.get('incident_name') or _cluster_name(c),
            'headline_subtitle': prefill.get('headline_subtitle') or _cluster_subtitle(c),
        })

    # ── Enriched pipeline: TemporalRAG + bitemporal + per-cluster narratives ──
    enriched: dict = {}
    try:
        from src.exec_summary.orchestrator import run_enriched_pipeline

        # Build per-cluster deterministic texts so the pipeline has a backbone
        # Resolve each cluster so tier1_prefill is available to the humaniser
        det_texts: dict[str, str] = {}
        for c in sorted_clusters:
            cid = str(c.get('cluster_id', ''))
            txt, _prov, _ = _build_attack_chain_exec_summary(
                _resolve_full_cluster(c, assessment), assessment
            )
            if txt:
                det_texts[cid] = txt

        # The pipeline LLM function must be synchronous (thread-offloaded inside)
        _pipeline_llm = None
        if body.regenerate:
            try:
                _pipeline_llm = _legacy_helper('_get_llm', _get_llm)(body.model).generate
            except Exception:
                pass

        enriched = await run_enriched_pipeline(
            assessment_id=assessment_id,
            assessment=assessment,
            sorted_clusters=sorted_clusters,
            llm_func=_pipeline_llm,
            model=body.model,
            deterministic_texts=det_texts,
            max_clusters=10,
            tenant=assessment.get('tenant_id', 'default'),
            persona_llm=bool(body.persona_llm and body.regenerate),
            persona_subset=body.persona_subset or None,
        )
    except Exception as _pipe_err:
        logger.warning('enriched exec-summary pipeline failed: %s — using legacy result', _pipe_err)

    # ── Deterministic postscript: always append compliance + state-nexus + business consequence
    # regardless of whether the main executive_summary came from the LLM or deterministic path.
    _assess_exec_text_ps = _safe_text(assessment.get('executive_summary', '')).strip()
    _ps_compliance_map: dict[str, int] = {}
    _ps_ext_domains: list[str] = []
    _ps_principal_actors: list[str] = []
    if _assess_exec_text_ps:
        import re as _re_ps
        for _cnt, _fw in _re_ps.findall(r'(\d+)\s+(apra_cps234|asd_ism|essential_eight|iso27001|nist_800_53|nist_csf)\s+control', _assess_exec_text_ps):
            _ps_compliance_map[_fw] = int(_cnt)
        _dm = _re_ps.search(r'External destinations?:\s*([^;\n]+?)(?:\.\s+[A-Z]|\.$|\n|$)', _assess_exec_text_ps)
        if _dm:
            _ps_ext_domains = [x.strip().rstrip('.') for x in _dm.group(1).split(',') if x.strip()][:4]
        _am = _re_ps.search(r'Principal actors?:\s*([^\.]+?)(?:\.\s+[A-Z]|\.$|Source infra|External)', _assess_exec_text_ps)
        if _am:
            _ps_principal_actors = [a.strip() for a in _am.group(1).split(',') if a.strip()][:8]

    _postscript_parts: list[str] = []

    # State-nexus / cross-border movement indicator (generalised, persona-aware)
    _ps_nexus = _classify_nexus(_ps_ext_domains, _ps_principal_actors, [])
    _ps_nexus_sent = _nexus_sentence(_ps_nexus, persona=body.persona, org_context=body.context)
    if _ps_nexus_sent:
        _postscript_parts.append(_ps_nexus_sent)

    # Business consequence + control gaps (postscript fallback — only fires if not already in main text)
    _pivot_lower = executive_summary.lower()
    _ctrl_gaps_ps = []
    if 'assumerole' in _pivot_lower or 'assume role' in _pivot_lower or 'assumed a higher-privilege' in _pivot_lower:
        _ctrl_gaps_ps.append('cloud accounts were not restricted to minimum required permissions (AWS AssumeRole least-privilege boundary absent)')
    if _ps_ext_domains:
        _ctrl_gaps_ps.append(f"outbound data transfers were not blocked to {', '.join(_ps_ext_domains[:2])} (DLP controls absent)")
    if not _ctrl_gaps_ps:
        _ctrl_gaps_ps.append('the attacker escalated privileges and moved between systems without restriction (privilege escalation and lateral movement controls absent)')
    _postscript_parts.append(
        f"What this means for the organisation: The attacker gained and maintained access across "
        f"multiple systems without detection. "
        f"Security controls that failed: {'; '.join(_ctrl_gaps_ps)}."
    )

    # Compliance control failures
    if _ps_compliance_map:
        _fw_labels = {
            'apra_cps234': 'APRA CPS234',
            'asd_ism': 'ASD ISM',
            'essential_eight': 'ASD Essential Eight',
            'iso27001': 'ISO 27001',
            'nist_800_53': 'NIST 800-53',
            'nist_csf': 'NIST CSF',
        }
        _fw_parts = [
            f"{_fw_labels.get(fw, fw)} ({cnt} control{'s' if cnt > 1 else ''})"
            for fw, cnt in sorted(_ps_compliance_map.items(), key=lambda x: -x[1])
        ]
        _proposed_ps = assessment.get('proposed_actions') or []
        _has_ndb = any('NDB' in str(a.get('description', '')) for a in _proposed_ps)
        _ndb_clause = ' The NDB Scheme 72-hour mandatory breach notification clock is running.' if _has_ndb else ''
        _postscript_parts.append(
            f"Regulatory impact: This breach has triggered failures against {', '.join(_fw_parts)}.{_ndb_clause}"
        )

    # Only append postscript sections that are not already present in the text
    _es_lower = executive_summary.lower()
    _filtered_postscript: list[str] = []
    for _ps_part in _postscript_parts:
        # Detect which section this is and whether it's already covered
        _ps_lower = _ps_part.lower()
        if ('state-nexus' in _ps_lower or 'cross-border movement' in _ps_lower or
                'foreign data movement' in _ps_lower or 'legal review required' in _ps_lower) and (
                'state-nexus' in _es_lower or 'cross-border' in _es_lower or
                'foreign data movement' in _es_lower or 'legal review required' in _es_lower):
            continue  # already included by deterministic path
        # Match both old ('business consequence') and new ('what this means') phrasing
        _biz_in_ps = 'business consequence' in _ps_lower or 'what this means' in _ps_lower
        _biz_in_es = 'business consequence' in _es_lower or 'what this means' in _es_lower
        if _biz_in_ps and _biz_in_es:
            continue
        # Match both old ('compliance control') and new ('regulatory impact') phrasing
        _comp_in_ps = 'compliance control' in _ps_lower or 'regulatory impact' in _ps_lower
        _comp_in_es = 'compliance control' in _es_lower or 'regulatory impact' in _es_lower
        if _comp_in_ps and _comp_in_es:
            continue
        _filtered_postscript.append(_ps_part)
    if _filtered_postscript:
        executive_summary = executive_summary.rstrip() + ' ' + ' '.join(_filtered_postscript)

    if 'infrastructure:' not in executive_summary.lower() or 'affected users:' not in executive_summary.lower():
        _scope_footer = _build_affected_scope_footer(assessment, sorted_clusters, lead)
        if _scope_footer.strip():
            executive_summary = executive_summary.rstrip() + '\n\n' + _scope_footer

    result = {
        'headline': headline,
        'subline': subline,
        'executive_summary': executive_summary,
        'deterministic': deterministic,
        'llm_color': llm_color,
        'model_used': body.model,
        'attribution_confidence': _nexus_confidence,
        'persona': body.persona,
        'org_context': body.context,
        'generated_at': int(time.time()),
        'from_cache': False,
        'narrative_provenance': attack_chain_provenance if not _llm_ran else f'llm_{body.model}',
        'narrative_source': (body.model if _llm_ran else attack_chain_provenance),
        'render_warning': (dread_summary or {}).get('render_warning') or '',
        'evidence_refs': (dread_summary or {}).get('evidence_refs') or [],
        'dread_fragments': (dread_summary or {}).get('dread_fragments') or {},
        'sabsa_attributes': (dread_summary or {}).get('sabsa_attributes') or [],
        'sabsa_coda_draft': (dread_summary or {}).get('sabsa_coda_draft') or '',
        'why_confirmed': (dread_summary or {}).get('why_confirmed') or [],
        'scope': (dread_summary or {}).get('scope') or {},
        # Geo signals surfaced to the UI
        'geo_travel_verdict': lead_geo.get('travel_verdict', ''),
        'geo_countries': lead_geo.get('geo_countries', {}),
        'geo_impossible_travel': lead_geo.get('impossible_travel', []),
        'geo_suspicious_travel': lead_geo.get('suspicious_travel', []),
        'geo_plausible_travel': lead_geo.get('plausible_travel', []),
        'iam_playbook': lead_geo.get('iam_playbook', []),
        # Clustering provenance — used by the UI to show stale/reingest warnings.
        'requires_reingest': requires_reingest,
        'fallback_used': fallback_used,
        'clustering_diagnostics': clustering_diagnostics,
        'normalizer_version': assessment.get('normalizer_version'),
        'cluster_merge_version': assessment.get('cluster_merge_version'),
        'clustering_mode': assessment.get('clustering_mode'),
        # Enriched pipeline outputs (new — blueprint architecture)
        'cluster_summaries': enriched.get('cluster_summaries', []),
        'belief_trajectories': enriched.get('belief_trajectories', {}),
        'temporal_rag_context': enriched.get('temporal_rag_context', {}),
        'verdict_reasoning': enriched.get('verdict_reasoning', {}),
        'rollup_summary': enriched.get('rollup_summary', ''),
        'rollup_provenance': enriched.get('rollup_provenance', ''),
        'persona_summaries': enriched.get('persona_summaries', {}),
        'pipeline_ran': enriched.get('pipeline_ran', False),
    }
    assessment['exec_summary_llm'] = result
    _legacy_helper('_persist', _persist)(assessment_id, assessment)

    # If deep=True, queue the Tier 3 background job and include the job_id
    if body.deep and body.regenerate:
        try:
            from src.exec_summary.deep_analysis import create_job, run_deep_analysis_job

            _deep_llm_func = None
            try:
                _deep_llm_func = _legacy_helper('_get_llm', _get_llm)(body.model).generate
            except Exception:
                pass

            _deep_job_id = create_job(assessment_id)
            # Fire-and-forget — do NOT await, the SSE stream delivers results
            asyncio.ensure_future(run_deep_analysis_job(
                job_id=_deep_job_id,
                assessment_id=assessment_id,
                assessment=assessment,
                sorted_clusters=sorted_clusters,
                llm_func=_deep_llm_func,
                model=body.model,
            ))
            result['deep_job_id'] = _deep_job_id
            result['deep_status'] = 'queued'
        except Exception as _deep_err:
            logger.warning('deep analysis job creation failed: %s', _deep_err)

    return JSONResponse({'assessment_id': assessment_id, **result})


# ── Deep exec summary: job status ─────────────────────────────────────────────

@router.get('/{assessment_id}/deep-exec-summary/status/{job_id}')
async def get_deep_exec_status(
    assessment_id: str,
    job_id: str,
) -> JSONResponse:
    """Poll the status of a deep analysis background job."""
    from src.exec_summary.deep_analysis import get_job
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail='deep_analysis_job_not_found')
    if job.get('assessment_id') != assessment_id:
        raise HTTPException(status_code=403, detail='job_not_for_assessment')
    return JSONResponse({
        'job_id': job_id,
        'assessment_id': assessment_id,
        'status': job.get('status'),
        'phase': job.get('phase'),
        'progress': job.get('progress', 0),
        'created_at': job.get('created_at'),
        'updated_at': job.get('updated_at'),
        'error': job.get('error'),
        # Include full result when ready
        'result': job.get('result') if job.get('status') == 'ready' else None,
    })


# ── Deep exec summary: SSE stream ─────────────────────────────────────────────

@router.get('/{assessment_id}/deep-exec-summary/stream/{job_id}')
async def stream_deep_exec_analysis(
    assessment_id: str,
    job_id: str,
) -> StreamingResponse:
    """Stream Tier 3 deep analysis events via Server-Sent Events.

    Events:
        progress  — {phase: str, progress: int}
        cluster_complete — {cluster_id, ceo_one_liner, cross_source_count, ...}
        complete  — {rollup: dict, cluster_count: int}
        error     — {message: str}
    """
    from src.exec_summary.deep_analysis import get_job, subscribe_job

    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail='deep_analysis_job_not_found')
    if job.get('assessment_id') != assessment_id:
        raise HTTPException(status_code=403, detail='job_not_for_assessment')

    async def _generate():
        # If job already completed, return result immediately
        if job.get('status') == 'ready' and job.get('result'):
            yield f'data: {json.dumps({"type": "complete", "result": job["result"]})}\n\n'
            return
        if job.get('status') == 'failed':
            yield f'data: {json.dumps({"type": "error", "message": job.get("error", "unknown")})}\n\n'
            return

        # Subscribe for live events
        q = subscribe_job(job_id)
        timeout = int(os.getenv('DEEP_ANALYSIS_STREAM_TIMEOUT', '180'))
        deadline = time.monotonic() + timeout

        # Send heartbeat every 15s to keep connection alive
        while time.monotonic() < deadline:
            try:
                msg = await asyncio.wait_for(q.get(), timeout=15)
                yield f'data: {msg}\n\n'
                parsed = json.loads(msg)
                if parsed.get('type') in ('complete', 'error'):
                    break
            except asyncio.TimeoutError:
                yield 'data: {"type":"heartbeat"}\n\n'

    return StreamingResponse(
        _generate(),
        media_type='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
        },
    )
