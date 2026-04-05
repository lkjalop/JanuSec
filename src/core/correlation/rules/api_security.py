"""API security correlation rules (heuristic examples).

These rules are intentionally simple: they provide a small set of heuristic
matchers that can be used in the correlation engine to flag likely API attacks.
Extend with richer logic and thresholds in production.
"""
from __future__ import annotations
from typing import Dict, Any
import re


def match_bola(parsed: Dict[str, Any]) -> bool:
    """Detect potential BOLA attempts by looking for suspicious object ids in URIs
    or encoded tokens that resemble another user's identifier. This is heuristic.
    """
    uri = (parsed.get('uri') or '') or ''
    # Simple heuristic: presence of 'user_id=' combined with other user's numeric id pattern
    if 'user_id=' in uri and '/admin/' in uri:
        return True
    # common misuse pattern: integer id in path followed by an action
    import re
    if re.search(r'/api/v[0-9]+/users/\d+/', uri):
        # If request includes an Authorization header with a different user id pattern,
        # we'd flag it in a richer parser. For now, flag candidate
        return True
    return False


def match_ssrf(parsed: Dict[str, Any]) -> bool:
    """Detect SSRF-like requests based on destination host patterns or embedded URLs.
    """
    msg = (parsed.get('message') or '') or ''
    uri = (parsed.get('uri') or '') or ''
    # Look for 'http://' or private IPs inside URI or message
    if 'http://' in uri or 'http://' in msg:
        return True
    # private IPs string evidence
    for p in ['127.0.0.1', '169.254.', '10.', '192.168.', '172.16.']:
        if p in uri or p in msg:
            return True
    return False


def match_idor(parsed: Dict[str, Any]) -> bool:
    """Detect possible IDOR patterns.
    Heuristics:
      - path includes another user's integer id and request is not owner-marked
      - query/body has `user_id` differing from `auth_user` field if present
    """
    uri = (parsed.get('uri') or '')
    auth_user = str(parsed.get('auth_user') or parsed.get('user') or '').strip()
    # integer id in path like /users/1234/resource and no owner flag
    if re.search(r'/users/(\d+)/(?:[a-zA-Z_\-]+)', uri) and not parsed.get('is_owner'):
        return True
    # conflicting user ids in body vs auth
    body_user = str((parsed.get('body') or {}).get('user_id') or (parsed.get('params') or {}).get('user_id') or '').strip()
    if body_user and auth_user and body_user != auth_user:
        return True
    return False


def match_rate_limit_abuse(parsed: Dict[str, Any]) -> bool:
    """Detect rate-limit abuse.
    Heuristics:
      - status 429 present
      - header x-rate-limit-remaining near zero with high request rate hint
    """
    status = int(parsed.get('status') or 0)
    if status == 429:
        return True
    hdrs = (parsed.get('headers') or {})
    try:
        remaining = int(hdrs.get('x-rate-limit-remaining') or hdrs.get('rate-limit-remaining') or -1)
        if 0 <= remaining <= 1:
            return True
    except Exception:
        pass
    return False


# Exported rule set
RULES = {
    'CORR_BOLA_ATTEMPT': match_bola,
    'CORR_SSRF_SUSPECTED': match_ssrf,
    'CORR_IDOR_SUSPECTED': match_idor,
    'CORR_RATE_LIMIT_ABUSE': match_rate_limit_abuse,
}
