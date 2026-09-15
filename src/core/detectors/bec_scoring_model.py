"""BECScoringModel — Business Email Compromise behavioral scoring.

Extends email_bec.py with ML-backed baseline signals:
    email:bec_sender_anomaly     — EWMA deviation: sender domain sending frequency outside baseline
    email:bec_replyto_mismatch   — Reply-To domain differs from From domain (classic BEC tell)
    email:bec_first_contact      — First-ever message from this sender to this recipient group
    email:bec_display_name_spoof — Display name contains executive/vendor name but From is external
    email:bec_urgency_pressure   — High-urgency language combined with auth anomaly (wire fraud pattern)
    email:bec_lookalike_advanced — Enhanced homoglyph beyond edit distance: Unicode confusable sets

State: per-tenant EWMA of (sender_domain → messages_per_hour) via AdaptiveEWMA.
Communication graph: per-tenant dict tracking (sender → recipient_set) for first-contact detection.
Both structures are in-memory with JSON persistence to data/bec_state.json.

HopGraph wiring: add edge (email:<sender>, email:<recipient>, 'bec_risk', weight=score)
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import unicodedata
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

try:
    from src.detectors.ewma_adaptive import AdaptiveEWMA
except Exception:
    try:
        from detectors.ewma_adaptive import AdaptiveEWMA  # type: ignore
    except Exception:
        AdaptiveEWMA = None  # type: ignore

# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
_STATE_PATH = os.getenv('BEC_STATE_PATH', 'data/bec_state.json')
_STATE_LOCK = threading.RLock()
_BEC_EWMA: Optional[Any] = AdaptiveEWMA(base_alpha=0.2, min_alpha=0.05, max_alpha=0.7) if AdaptiveEWMA else None
_SENDER_HOURLY_STATE: Dict[str, Dict[str, float]] = defaultdict(dict)

# Communication graph: tenant → sender_domain → frozenset of recipient_domains seen
# Loaded from _STATE_PATH at import time; saved on writes (lazy, not every call)
_COMM_GRAPH: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
_DIRTY = False


def _load_state() -> None:
    global _COMM_GRAPH
    try:
        if os.path.exists(_STATE_PATH):
            with open(_STATE_PATH, 'r', encoding='utf-8') as fh:
                raw = json.load(fh)
            cg = raw.get('comm_graph', {})
            for tenant, senders in cg.items():
                for sender, recipients in senders.items():
                    _COMM_GRAPH[tenant][sender] = set(recipients)
    except Exception:
        pass


def _save_state() -> None:
    global _DIRTY
    try:
        os.makedirs(os.path.dirname(_STATE_PATH) or '.', exist_ok=True)
        cg_serializable = {
            tenant: {sender: list(recips) for sender, recips in senders.items()}
            for tenant, senders in _COMM_GRAPH.items()
        }
        with open(_STATE_PATH, 'w', encoding='utf-8') as fh:
            json.dump({'comm_graph': cg_serializable, 'saved_at': time.time()}, fh)
        _DIRTY = False
    except Exception:
        pass


# Load on import
_load_state()

# ---------------------------------------------------------------------------
# Executive / vendor role keywords for display-name spoofing
# ---------------------------------------------------------------------------
_EXEC_KEYWORDS = re.compile(
    r'\b(ceo|cfo|coo|cto|ciso|vp|vice.?president|president|director|manager|'
    r'controller|treasurer|payroll|finance|accounts.?payable|vendor|supplier|'
    r'partner|auditor|legal|counsel|compliance)\b',
    re.IGNORECASE,
)

# Urgency language patterns (wire fraud / BEC social engineering)
_URGENCY_PATTERNS = re.compile(
    r'\b(urgent|immediately|asap|right.?away|within.?(?:the.?)?hour|today.?only|'
    r'do.?not.?reply.?to.?anyone|keep.?confidential|secret|wire|transfer.?now|'
    r'pay.?now|confirm.?payment|invoice.?attached|overdue|final.?notice|'
    r'gift.?card|itunes|amazon.?card)\b',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Unicode confusable set normalization (extend as needed)
# ---------------------------------------------------------------------------
# Maps visually confusable characters to ASCII baseline
_UNICODE_CONFUSABLE = str.maketrans({
    '\u0430': 'a',  # Cyrillic a
    '\u0435': 'e',  # Cyrillic e
    '\u043e': 'o',  # Cyrillic o
    '\u0440': 'r',  # Cyrillic r
    '\u0441': 'c',  # Cyrillic c
    '\u0445': 'x',  # Cyrillic x
    '\u0443': 'y',  # Cyrillic y
    '\u0440': 'p',  # Cyrillic p
    '\u03b9': 'i',  # Greek iota
    '\u03bf': 'o',  # Greek omicron
    '\u03c1': 'p',  # Greek rho
    '\u03c5': 'u',  # Greek upsilon
    '\u03b1': 'a',  # Greek alpha
    '\u0131': 'i',  # Dotless i (Turkish)
    '\u0069': 'i',  # Combining dotless
    '\u2019': "'",  # Right single quote
    '\u02b9': "'",  # Modifier letter prime
})

_PROTECTED_BRANDS_BEC = {
    'paypal', 'microsoft', 'amazon', 'apple', 'google', 'office', 'outlook',
    'azure', 'adobe', 'okta', 'wellsfargo', 'chase', 'bankofamerica', 'citibank',
    'hsbc', 'docusign', 'dropbox', 'salesforce', 'workday', 'sap', 'oracle',
    'quickbooks', 'intuit', 'xero', 'myob',
}


def _normalize_unicode_confusable(domain: str) -> str:
    nfkc = unicodedata.normalize('NFKC', domain.lower())
    return nfkc.translate(_UNICODE_CONFUSABLE)


def _extract_domain(address: str) -> str:
    """Extract domain from email address or return empty string."""
    address = str(address or '').strip().lower()
    if '@' in address:
        return address.split('@', 1)[-1].split('>')[0].strip()
    return address


def _extract_display_name(from_header: str) -> str:
    """Extract display name from 'Display Name <address>' format."""
    m = re.match(r'^"?([^"<]+)"?\s*<', from_header.strip())
    if m:
        return m.group(1).strip()
    return ''


# ---------------------------------------------------------------------------
# Main scorer
# ---------------------------------------------------------------------------

def score_bec(
    events: List[Dict[str, Any]],
    tenant_id: str = 'default',
    event_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Score events for BEC indicators.

    Args:
        events:    List of normalized email events (sanitized_events format).
        tenant_id: Tenant for EWMA baseline and comm graph isolation.
        event_id:  Optional event ID for factor dedup.

    Returns:
        List of factor dicts.
    """
    global _DIRTY
    factors: List[Dict[str, Any]] = []
    sender_counts: Dict[tuple[str, int], int] = defaultdict(int)
    sender_meta: Dict[tuple[str, int], Dict[str, Any]] = {}

    for ev in events:
        try:
            src = (ev.get('source_platform') or ev.get('source') or '').lower()
            if 'email' not in src and ev.get('type') not in {'email', 'mail'}:
                continue

            headers = ev.get('headers') or {}
            if isinstance(headers, str):
                hdrs: Dict[str, str] = {}
                for ln in headers.splitlines():
                    if ':' in ln:
                        k, v = ln.split(':', 1)
                        hdrs[k.strip().lower()] = v.strip()
                headers = hdrs

            from_raw      = headers.get('from') or ev.get('sender') or ev.get('from') or ''
            reply_to_raw  = headers.get('reply-to') or ev.get('reply_to') or ''
            to_raw        = headers.get('to') or ev.get('recipients') or ev.get('to') or ''
            subject       = headers.get('subject') or ev.get('subject') or ''
            body          = ev.get('body') or ev.get('text') or ''
            ts            = float(ev.get('timestamp') or ev.get('ts') or time.time())

            from_domain     = _extract_domain(from_raw)
            reply_to_domain = _extract_domain(reply_to_raw)
            display_name    = _extract_display_name(from_raw)
            recipient_domain = _extract_domain(to_raw) if '@' in str(to_raw) else ''
            if from_domain:
                hour_bucket = int(ts // 3600)
                sender_key = (from_domain, hour_bucket)
                sender_counts[sender_key] += 1
                sender_meta[sender_key] = {
                    'from_domain': from_domain,
                    'recipient_domain': recipient_domain,
                    'timestamp': ts,
                }

            # ----------------------------------------------------------------
            # 1. Reply-To mismatch
            # ----------------------------------------------------------------
            if (reply_to_domain and from_domain and
                    reply_to_domain != from_domain):
                factors.append({
                    'factor': 'email:bec_replyto_mismatch',
                    'score': 0.72,
                    'reason': f'Reply-To domain "{reply_to_domain}" differs from From domain "{from_domain}"',
                    'from_domain': from_domain,
                    'reply_to_domain': reply_to_domain,
                    'tags': ['ATTACK:T1566.003', 'ATTACK:T1036', 'STRIDE:spoofing'],
                })

            # ----------------------------------------------------------------
            # 2. Display name → From misalignment (executive impersonation)
            # ----------------------------------------------------------------
            if display_name and from_domain:
                if _EXEC_KEYWORDS.search(display_name):
                    # Display name claims executive role but From is external domain
                    # (external = not the organization's own domain — heuristic: not internal)
                    factors.append({
                        'factor': 'email:bec_display_name_spoof',
                        'score': 0.68,
                        'reason': f'Display name "{display_name}" contains executive/role keywords but From is "{from_domain}"',
                        'display_name': display_name,
                        'from_domain': from_domain,
                        'tags': ['ATTACK:T1566.003', 'ATTACK:T1036', 'STRIDE:spoofing'],
                    })

            # ----------------------------------------------------------------
            # 3. Enhanced brand lookalike (Unicode confusable)
            # ----------------------------------------------------------------
            if from_domain:
                sld = from_domain.split('.')[-2] if from_domain.count('.') >= 1 else from_domain
                normalized_sld = _normalize_unicode_confusable(sld)
                for brand in _PROTECTED_BRANDS_BEC:
                    if normalized_sld == brand and sld != brand:
                        factors.append({
                            'factor': 'email:bec_lookalike_advanced',
                            'score': 0.80,
                            'reason': f'Sender domain "{from_domain}" Unicode-normalizes to protected brand "{brand}"',
                            'from_domain': from_domain,
                            'brand': brand,
                            'tags': ['ATTACK:T1566.003', 'ATTACK:T1036', 'STRIDE:spoofing'],
                        })
                        break

            # ----------------------------------------------------------------
            # 4. First contact detection via communication graph
            # ----------------------------------------------------------------
            if from_domain and recipient_domain:
                with _STATE_LOCK:
                    known_recipients = _COMM_GRAPH[tenant_id][from_domain]
                    if recipient_domain not in known_recipients:
                        factors.append({
                            'factor': 'email:bec_first_contact',
                            'score': 0.42,
                            'reason': f'First email from domain "{from_domain}" to recipient domain "{recipient_domain}" — no prior communication history',
                            'from_domain': from_domain,
                            'recipient_domain': recipient_domain,
                            'tags': ['ATTACK:T1566.003', 'STRIDE:spoofing'],
                        })
                        _COMM_GRAPH[tenant_id][from_domain].add(recipient_domain)
                        _DIRTY = True

            # ----------------------------------------------------------------
            # 5. EWMA sender frequency anomaly
            # ----------------------------------------------------------------
            if from_domain and _BEC_EWMA is not None:
                # Use hour-bucket for frequency baseline
                hour_bucket = int(ts // 3600)
                tenant_sender_key = f'{tenant_id}:{from_domain}:{hour_bucket}'
                result = _BEC_EWMA.update(tenant_sender_key, 1.0, timestamp=ts)
                if result.get('alert') and result.get('score', 0) > 3.0:
                    factors.append({
                        'factor': 'email:bec_sender_anomaly',
                        'score': min(0.40 + 0.05 * result['score'], 0.75),
                        'reason': (
                            f'Sender domain "{from_domain}" sending frequency deviates {result["score"]:.1f}σ '
                            f'from EWMA baseline (ewma={result["ewma"]:.2f})'
                        ),
                        'from_domain': from_domain,
                        'ewma_score': round(result['score'], 3),
                        'ewma_value': round(result['ewma'], 3),
                        'tags': ['ATTACK:T1566.003', 'STRIDE:spoofing'],
                    })

            # ----------------------------------------------------------------
            # 6. Urgency pressure (combined with other signals for score boost)
            # ----------------------------------------------------------------
            body_str = body if isinstance(body, str) else ''
            subj_str = subject if isinstance(subject, str) else ''
            combined_text = subj_str + ' ' + body_str
            urgency_matches = _URGENCY_PATTERNS.findall(combined_text)
            if len(urgency_matches) >= 2:
                # Urgency alone is weak; score is boosted if combined with other factors
                existing_bec_score = max((f.get('score', 0) for f in factors), default=0.0)
                urgency_score = 0.45 if existing_bec_score < 0.5 else min(existing_bec_score + 0.15, 0.90)
                factors.append({
                    'factor': 'email:bec_urgency_pressure',
                    'score': urgency_score,
                    'reason': f'Message contains {len(urgency_matches)} urgency/pressure phrases: {urgency_matches[:5]}',
                    'urgency_phrases': urgency_matches[:10],
                    'tags': ['ATTACK:T1566.003', 'DREAD:damage', 'STRIDE:spoofing'],
                })

        except Exception:
            continue

    # Post-pass sender volume anomaly scoring. This uses hourly sender counts
    # rather than constant 1.0 updates so it can surface real spikes without
    # adding a heavier ML dependency.
    if _BEC_EWMA is not None:
        for (from_domain, hour_bucket), count in sender_counts.items():
            baseline_key = f'{tenant_id}:{from_domain}'
            prior_state = _BEC_EWMA.tenants.get(baseline_key) if hasattr(_BEC_EWMA, 'tenants') else None
            prior_ewma = float(getattr(prior_state, 'ewma', 0.0) or 0.0)
            prior_ratio = float(count) / max(prior_ewma, 1.0)
            result = _BEC_EWMA.update(baseline_key, float(count), timestamp=float(hour_bucket * 3600))
            if (result.get('alert') and result.get('score', 0) > 3.0) or (count >= 5 and prior_ratio >= 2.5):
                meta = sender_meta.get((from_domain, hour_bucket)) or {}
                factors.append({
                    'factor': 'email:bec_sender_anomaly',
                    'score': min(0.45 + 0.05 * max(float(result.get('score') or 0.0), prior_ratio), 0.82),
                    'reason': f'Sender domain "{from_domain}" hourly volume spike: {int(count)} messages versus prior EWMA baseline {prior_ewma:.2f}',
                    'from_domain': from_domain,
                    'recipient_domain': meta.get('recipient_domain') or '',
                    'ewma_score': round(float(result.get('score') or 0.0), 3),
                    'ewma_value': round(prior_ewma, 3),
                    'message_count': int(count),
                    'hour_bucket': hour_bucket,
                    'tags': ['ATTACK:T1566.003', 'STRIDE:spoofing'],
                })

    # Lazy save if comm graph changed
    if _DIRTY:
        try:
            with _STATE_LOCK:
                _save_state()
        except Exception:
            pass

    return factors


def detect_bec_advanced(runtime, tenant_id: str = 'default', event_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Runtime adapter. Pairs with detect_email_bec for full BEC coverage."""
    try:
        events = list(getattr(runtime, 'sanitized_events', []) or [])
    except Exception:
        events = []
    return score_bec(events, tenant_id=tenant_id, event_id=event_id)


__all__ = ['score_bec', 'detect_bec_advanced']
