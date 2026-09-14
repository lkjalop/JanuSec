from __future__ import annotations

from typing import Any, Dict, List
import re

def _domain_top_label(d: str) -> str:
    parts = str(d or '').lower().split('.')
    return parts[-2] if len(parts) >= 2 else (parts[0] if parts else '')

def _simple_edit_distance(a: str, b: str) -> int:
    # Lightweight Levenshtein-like distance (O(n*m) DP) without external deps
    a = str(a); b = str(b)
    n, m = len(a), len(b)
    if n == 0: return m
    if m == 0: return n
    dp = [[0]*(m+1) for _ in range(n+1)]
    for i in range(n+1): dp[i][0] = i
    for j in range(m+1): dp[0][j] = j
    for i in range(1, n+1):
        for j in range(1, m+1):
            cost = 0 if a[i-1] == b[j-1] else 1
            dp[i][j] = min(dp[i-1][j] + 1, dp[i][j-1] + 1, dp[i-1][j-1] + cost)
    return dp[n][m]

def _looks_like_brand(sender_domain: str, brand_domain: str) -> bool:
    a = _domain_top_label(sender_domain)
    b = _domain_top_label(brand_domain)
    if not a or not b:
        return False
    dist = _simple_edit_distance(a, b)
    # allow small edit distance ≤1 (e.g., rn vs m), treat as suspicious homoglyph/typo
    return dist <= 1 and a != b

def detect_email_bec(runtime) -> List[Dict[str, Any]]:
    """Detect basic BEC patterns: DMARC/DKIM/SPF failures + lookalike domains
    and payroll/vendor change intents in message bodies.
    """
    out: List[Dict[str, Any]] = []
    try:
        events = list(getattr(runtime, 'sanitized_events', []) or [])
    except Exception:
        events = []

    for ev in events:
        try:
            src = (ev.get('source_platform') or ev.get('source') or '').lower()
            if 'email' not in src and ev.get('type') not in {'email','mail'}:
                continue
            headers = ev.get('headers') or {}
            if isinstance(headers, str):
                # minimal parse: key: value lines
                hdrs = {}
                for ln in headers.splitlines():
                    if ':' in ln:
                        k, v = ln.split(':', 1)
                        hdrs[k.strip().lower()] = v.strip()
                headers = hdrs
            sender = (ev.get('sender_domain') or ev.get('from_domain') or ev.get('sender') or '').lower()
            brand = (ev.get('recipient_domain') or ev.get('brand_domain') or '').lower()
            auth = (headers.get('authentication-results') or '').lower()
            spf_fail = ('spf=fail' in auth) or (str(ev.get('spf_result') or '').lower() == 'fail')
            dmarc_fail = ('dmarc=fail' in auth) or (str(ev.get('dmarc_result') or '').lower() == 'fail')
            dkim_fail = ('dkim=fail' in auth) or (str(ev.get('dkim_result') or '').lower() == 'fail')
            if spf_fail or dmarc_fail or dkim_fail:
                out.append({
                    'factor': 'email_bec_auth_fail',
                    'score': 0.45,
                    'reason': 'One or more email auth checks failed',
                    'auth': {
                        'spf': 'fail' if spf_fail else 'pass',
                        'dmarc': 'fail' if dmarc_fail else 'pass',
                        'dkim': 'fail' if dkim_fail else 'pass',
                    },
                    'tags': ['ATTACK:T1566.003','STRIDE:spoofing']
                })
            # Lookalike domain
            if sender and brand and _looks_like_brand(sender, brand):
                out.append({
                    'factor': 'email_bec_lookalike',
                    'score': 0.5,
                    'reason': f"Sender top-label '{_domain_top_label(sender)}' resembles brand '{_domain_top_label(brand)}'",
                    'sender_domain': sender,
                    'brand_domain': brand,
                    'tags': ['ATTACK:T1566.003','STRIDE:spoofing']
                })
            # Payroll/vendor change intents
            body = (ev.get('body') or ev.get('text') or '')
            hint = False
            if isinstance(body, str) and body:
                s = body.lower()
                hint = bool(re.search(r"(routing|account|iban|swift|wire|ach|bank)\s+(change|update|new)", s)) or ('payroll' in s)
            meta = ev.get('meta') or {}
            if not hint and isinstance(meta, dict):
                note = (meta.get('intent') or meta.get('action'))
                if isinstance(note, str):
                    ns = note.lower()
                    hint = 'payroll' in ns or ('vendor' in ns and 'change' in ns)
            if hint:
                out.append({
                    'factor': 'email_bec_payroll_change',
                    'score': 0.6,
                    'reason': 'Message indicates payroll/vendor account change intent',
                    'tags': ['ATTACK:T1566.003','DREAD:damage']
                })
        except Exception:
            continue
    return out

__all__ = ['detect_email_bec']
