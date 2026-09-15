"""URLRiskScorer — production-grade URL threat signal extractor.

Emits factors:
    email:url_entropy_high      — Shannon entropy of URL path/query > threshold (obfuscated C2 / redirect)
    email:url_homoglyph         — Domain contains non-ASCII or visually confusable chars vs. protected brands
    email:url_redirect_chain    — Redirect chain depth >= threshold (URL shortener stacking)
    email:url_fresh_domain      — Domain registered recently (heuristic: low Alexa-rank proxy or regex patterns)
    email:url_dga_candidate     — Domain features consistent with DGA (high consonant ratio, entropy)

Each factor dict matches the pattern used by email_bec.py and endpoint_ransom.py:
    {'factor': str, 'score': float, 'reason': str, 'tags': List[str], ...metadata...}

HopGraph wiring: call hopgraph.add_edge('domain:<domain>', 'ip:<src_ip>', 'url_risk', weight=score)
Compliance: see factor_to_compliance.py for CIS / NIST CSF / ISO27001 / SOC2 / PCI-DSS mappings.
"""
from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, unquote

# ---------------------------------------------------------------------------
# Protected brand domains for homoglyph detection (extend as needed)
# ---------------------------------------------------------------------------
_PROTECTED_BRANDS = {
    'paypal', 'microsoft', 'amazon', 'apple', 'google', 'office', 'outlook',
    'azure', 'adobe', 'okta', 'dropbox', 'docusign', 'linkedin', 'twitter',
    'facebook', 'instagram', 'netflix', 'wellsfargo', 'chase', 'bankofamerica',
    'citibank', 'hsbc', 'fedex', 'ups', 'dhl', 'usps', 'irs', 'gov',
}

# Confusable character substitution map (homoglyph normalization)
_CONFUSABLE = str.maketrans({
    '0': 'o', '1': 'l', '3': 'e', '5': 's', '7': 't', '4': 'a',
    '@': 'a', '!': 'i', '$': 's', 'ν': 'v', 'с': 'c', 'а': 'a',
    'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
})

# Minimum path+query length to run entropy check (avoid false positives on short paths)
_MIN_PATH_LEN = 12

# Thresholds
_URL_PATH_ENTROPY_THRESHOLD = float(3.8)   # bits — typical clean path ~2.5, obfuscated ~4.5+
_REDIRECT_DEPTH_THRESHOLD   = int(2)       # number of chained shortener hops
_DGA_CONSONANT_RATIO_MIN    = float(0.65)  # consonant-heavy label = likely DGA
_DGA_ENTROPY_MIN            = float(3.6)   # bits per char in domain label


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = float(len(s))
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _normalize_homoglyphs(domain: str) -> str:
    """NFKC normalize then apply confusable substitution map."""
    try:
        normalized = unicodedata.normalize('NFKC', domain.lower())
        return normalized.translate(_CONFUSABLE)
    except Exception:
        return domain.lower()


def _extract_effective_tld_label(hostname: str) -> str:
    """Return the registrable part (SLD) of a hostname for brand comparison."""
    parts = hostname.lower().split('.')
    # Strip 'www' prefix
    if parts and parts[0] == 'www':
        parts = parts[1:]
    # Return second-to-last label (SLD) for simple TLDs; for .co.uk style use -3
    if len(parts) >= 2:
        return parts[-2]
    return parts[0] if parts else ''


def _is_known_shortener(hostname: str) -> bool:
    """Return True if hostname is a well-known URL shortener service."""
    shorteners = {
        'bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'buff.ly',
        'tiny.cc', 'is.gd', 'cl.gs', 'su.pr', 'twurl.nl', 'snipurl.com',
        'short.to', 'budurl.com', 'ping.fm', 'post.ly', 'just.as',
        'bkite.com', 'snipr.com', 'fic.kr', 'loopt.us', 'doiop.com',
        'cutt.ly', 'rb.gy', 'shorturl.at', 'qr.io', 'lnkd.in',
    }
    h = hostname.lower().lstrip('www.')
    return h in shorteners


def _parse_urls(text: str) -> List[str]:
    """Extract URLs from free text using a conservative regex."""
    pattern = re.compile(
        r'https?://[^\s<>"\')\]]+',
        re.IGNORECASE,
    )
    return pattern.findall(text or '')


def _count_redirect_depth(url_list: List[str]) -> int:
    """
    Estimate redirect chain depth from a list of URLs in a message body.
    Each shortener domain in the list counts as one hop.
    """
    depth = 0
    for url in url_list:
        try:
            parsed = urlparse(url)
            if _is_known_shortener(parsed.netloc):
                depth += 1
        except Exception:
            continue
    return depth


def _is_dga_candidate(label: str) -> bool:
    """Heuristic DGA check on a single domain label (no dots)."""
    if len(label) < 8:
        return False
    vowels = set('aeiou')
    consonants = sum(1 for c in label if c.isalpha() and c not in vowels)
    total_alpha = sum(1 for c in label if c.isalpha())
    if total_alpha == 0:
        return False
    consonant_ratio = consonants / total_alpha
    entropy = _shannon_entropy(label)
    return consonant_ratio >= _DGA_CONSONANT_RATIO_MIN and entropy >= _DGA_ENTROPY_MIN


# ---------------------------------------------------------------------------
# Main scorer
# ---------------------------------------------------------------------------

def score_urls(
    urls: List[str],
    body_text: Optional[str] = None,
    event_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Score a list of URLs extracted from an email or attachment.

    Args:
        urls: Pre-extracted URL list (from attachment_vision or header parser).
        body_text: Raw message body for supplemental URL extraction.
        event_id: Optional event ID for factor emission dedup.

    Returns:
        List of factor dicts ready for risk_score aggregation.
    """
    factors: List[Dict[str, Any]] = []
    if not urls and body_text:
        urls = _parse_urls(body_text)
    if not urls:
        return factors

    # Deduplicate while preserving order
    seen: set[str] = set()
    deduped = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    urls = deduped

    # Redirect chain depth across all URLs in this message
    redirect_depth = _count_redirect_depth(urls)
    if redirect_depth >= _REDIRECT_DEPTH_THRESHOLD:
        factors.append({
            'factor': 'email:url_redirect_chain',
            'score': min(0.55 + 0.10 * (redirect_depth - _REDIRECT_DEPTH_THRESHOLD), 0.85),
            'reason': f'URL redirect chain depth {redirect_depth} (≥{_REDIRECT_DEPTH_THRESHOLD} shorteners)',
            'redirect_depth': redirect_depth,
            'tags': ['ATTACK:T1566.001', 'ATTACK:T1027', 'STRIDE:tampering'],
        })

    for url in urls:
        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or '').lower()
            path = unquote(parsed.path or '')
            query = unquote(parsed.query or '')

            # --- Entropy check on path + query ---
            path_query = path + query
            if len(path_query) >= _MIN_PATH_LEN:
                entropy = _shannon_entropy(path_query)
                if entropy >= _URL_PATH_ENTROPY_THRESHOLD:
                    factors.append({
                        'factor': 'email:url_entropy_high',
                        'score': min(0.45 + 0.08 * (entropy - _URL_PATH_ENTROPY_THRESHOLD), 0.80),
                        'reason': f'URL path/query Shannon entropy {entropy:.2f}b (threshold {_URL_PATH_ENTROPY_THRESHOLD}b)',
                        'url': url[:200],
                        'entropy': round(entropy, 3),
                        'tags': ['ATTACK:T1566.001', 'ATTACK:T1027', 'STRIDE:spoofing'],
                    })

            if not hostname:
                continue

            # --- Homoglyph / brand impersonation check ---
            sld = _extract_effective_tld_label(hostname)
            normalized_sld = _normalize_homoglyphs(sld)
            # Check if the normalized SLD matches or closely resembles a protected brand
            for brand in _PROTECTED_BRANDS:
                if normalized_sld == brand:
                    # exact match after normalization (different before) → homoglyph
                    if sld != brand:
                        factors.append({
                            'factor': 'email:url_homoglyph',
                            'score': 0.78,
                            'reason': f'Domain "{hostname}" normalizes to protected brand "{brand}"',
                            'domain': hostname,
                            'brand': brand,
                            'tags': ['ATTACK:T1566.001', 'ATTACK:T1036', 'STRIDE:spoofing'],
                        })
                        break
                    # Check for non-ASCII characters in the raw hostname (IDN homoglyph)
                    if any(ord(c) > 127 for c in hostname):
                        factors.append({
                            'factor': 'email:url_homoglyph',
                            'score': 0.82,
                            'reason': f'Domain "{hostname}" contains non-ASCII IDN chars resembling "{brand}"',
                            'domain': hostname,
                            'brand': brand,
                            'tags': ['ATTACK:T1566.001', 'ATTACK:T1036', 'STRIDE:spoofing'],
                        })
                        break

            # --- Fresh domain heuristic ---
            # Heuristic: domains with numeric-heavy labels or very new TLDs are often freshly registered
            labels = hostname.split('.')
            tld = labels[-1] if labels else ''
            sld_label = labels[-2] if len(labels) >= 2 else ''
            # High-risk TLDs commonly abused by phishing infrastructure
            risky_tlds = {
                'top', 'xyz', 'club', 'online', 'site', 'info', 'buzz', 'rest',
                'click', 'link', 'gq', 'ml', 'cf', 'ga', 'tk', 'pw', 'cc',
            }
            digit_count = sum(1 for c in sld_label if c.isdigit())
            digit_ratio = digit_count / max(len(sld_label), 1)
            if tld in risky_tlds and digit_ratio > 0.3:
                factors.append({
                    'factor': 'email:url_fresh_domain',
                    'score': 0.50,
                    'reason': f'Domain "{hostname}" uses high-risk TLD ".{tld}" with numeric-heavy SLD (digit ratio {digit_ratio:.2f})',
                    'domain': hostname,
                    'tld': tld,
                    'tags': ['ATTACK:T1566.001', 'ATTACK:T1583', 'STRIDE:spoofing'],
                })
            elif tld in risky_tlds:
                factors.append({
                    'factor': 'email:url_fresh_domain',
                    'score': 0.38,
                    'reason': f'Domain "{hostname}" uses high-risk TLD ".{tld}"',
                    'domain': hostname,
                    'tld': tld,
                    'tags': ['ATTACK:T1566.001', 'ATTACK:T1583'],
                })

            # --- DGA candidate check on SLD ---
            if _is_dga_candidate(sld_label):
                factors.append({
                    'factor': 'email:url_dga_candidate',
                    'score': 0.65,
                    'reason': f'Domain label "{sld_label}" exhibits DGA-consistent features (entropy, consonant ratio)',
                    'domain': hostname,
                    'label': sld_label,
                    'label_entropy': round(_shannon_entropy(sld_label), 3),
                    'tags': ['ATTACK:T1568', 'ATTACK:T1071.001', 'STRIDE:tampering'],
                })

        except Exception:
            continue

    # Deduplicate by (factor, domain/url) — keep highest score per factor type
    return _dedup_factors(factors)


def _dedup_factors(factors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Keep highest-score entry per (factor, domain)."""
    seen: Dict[tuple, Dict[str, Any]] = {}
    for f in factors:
        key = (f.get('factor', ''), f.get('domain', f.get('url', '')[:80]))
        existing = seen.get(key)
        if existing is None or f.get('score', 0) > existing.get('score', 0):
            seen[key] = f
    return list(seen.values())


def analyze_email_url_risk(runtime, event_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Adapter that pulls URLs from runtime and delegates to score_urls.

    Compatible with the existing detector call pattern used by email_bec.py.
    """
    urls: List[str] = []
    body_text: Optional[str] = None

    try:
        events = list(getattr(runtime, 'sanitized_events', []) or [])
    except Exception:
        events = []

    for ev in events:
        try:
            src = (ev.get('source_platform') or ev.get('source') or '').lower()
            if 'email' not in src and ev.get('type') not in {'email', 'mail'}:
                continue
            # Pre-extracted URL lists take priority
            ev_urls = ev.get('urls') or ev.get('extracted_urls') or []
            if isinstance(ev_urls, list):
                urls.extend(str(u) for u in ev_urls if u)
            # Fall through to body extraction if no pre-extracted list
            if not ev_urls:
                body = ev.get('body') or ev.get('text') or ''
                if isinstance(body, str):
                    body_text = body
        except Exception:
            continue

    return score_urls(urls, body_text=body_text, event_id=event_id)


__all__ = ['score_urls', 'analyze_email_url_risk']
