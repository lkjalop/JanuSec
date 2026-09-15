"""Email analysis helpers for HopGraph.

This module contains simple homograph detection helper and campaign clustering
entry points. These are intentionally simple and designed to be extended.
"""
from typing import List, Dict, Any, Tuple
import unicodedata


def normalize_display_name(name: str) -> str:
    # Basic normalization: NFKC plus lower
    try:
        nm = unicodedata.normalize('NFKC', name)
        return nm.lower()
    except Exception:
        return name.lower()


PROTECTED_BRANDS: List[str] = [
    'paypal.com', 'microsoft.com', 'amazon.com', 'apple.com', 'google.com',
    'office.com', 'outlook.com', 'azure.com', 'adobe.com', 'okta.com'
]


def detect_homograph(domain: str) -> bool:
    """Rudimentary homograph detector.

    Returns True if domain contains characters outside ASCII or contains
    visually confusable characters (placeholder logic).
    """
    try:
        # if domain contains non-ascii chars it's suspicious as potential IDN homograph
        return any(ord(c) > 127 for c in domain)
    except Exception:
        return False


def _normalize_ascii_homoglyphs(label: str) -> str:
    """Very small ASCII homoglyph normalization for brand comparisons.

    This is deliberately simple and avoids heavy deps; it's not exhaustive.
    """
    s = label.lower()
    s = s.replace('0', 'o')
    s = s.replace('1', 'l')
    s = s.replace('3', 'e')
    s = s.replace('5', 's')
    s = s.replace('7', 't')
    s = s.replace('@', 'a')
    # common digraphs that approximate letters
    s = s.replace('rn', 'm')
    s = s.replace('vv', 'w')
    return s


def detect_homograph_against_brands(domain: str, brands: List[str] | None = None) -> bool:
    """Return True if sender domain appears to homograph a protected brand.

    Strategy:
      - Extract the registrable domain (last two labels best-effort)
      - If domain contains non-ASCII: suspicious
      - Compare top-label ASCII-homoglyph-normalized against brand top-label; if
        normalized-equal but original differs, consider homograph.
    """
    try:
        brands = brands or PROTECTED_BRANDS
        d = (domain or '').strip().lower()
        # fast-path: any non-ascii in full domain => suspicious
        if any(ord(c) > 127 for c in d):
            return True
        parts = d.split('.')
        if len(parts) < 2:
            return False
        top = parts[-2]  # best-effort top label
        t_norm = _normalize_ascii_homoglyphs(top)
        for b in brands:
            b = b.lower()
            bl = b.split('.')
            if len(bl) < 2:
                continue
            btop = bl[-2]
            if t_norm == _normalize_ascii_homoglyphs(btop) and top != btop:
                # looks like brand top label via homoglyphs but differs
                return True
        return False
    except Exception:
        return False


def cluster_by_campaign(emails: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    """Very small campaign clustering: group by normalized sender domain and subject tokens.

    This is a placeholder; replace with TF-IDF or locality-sensitive hashing later.
    """
    groups: Dict[str, List[Dict[str, Any]]] = {}
    stopwords = {'the','a','an','now','please','urgent','re'}
    for e in emails:
        from_addr = e.get('from') or ''
        subject = (e.get('subject') or '').lower()
        # simple tokenization and stopword removal
        toks = [t for t in subject.split() if t not in stopwords]
        subj_key = ' '.join(toks[:3])
        dom = from_addr.split('@')[-1].lower() if '@' in from_addr else from_addr.lower()
        key = dom + '|' + subj_key
        groups.setdefault(key, []).append(e)
    return list(groups.values())


def parse_email_signals(raw: Dict[str, Any] | None) -> Dict[str, Any]:
    """Extract lightweight SPF/DKIM/DMARC signals from parsed headers or gateway logs.

    Inputs expected from gateways:
      - raw['spf_result'] in {'pass','fail','softfail','neutral','none'}
      - raw['dkim_result'] in {'pass','fail','permerror','temperror','none'}
      - raw['dmarc_result'] in {'pass','fail','none','quarantine','reject'}
      - or consolidated raw['authentication_results'] string (RFC 8601 style)

    Returns a compact dict: {'spf': 'pass|fail|...', 'dkim': 'pass|fail|...', 'dmarc': 'pass|fail|...', 'risk': 0..1}
    """
    raw = raw or {}
    spf = str(raw.get('spf_result') or raw.get('spf') or '').lower()
    dkim = str(raw.get('dkim_result') or raw.get('dkim') or '').lower()
    dmarc = str(raw.get('dmarc_result') or raw.get('dmarc') or '').lower()

    ar = str(raw.get('authentication_results') or '')
    if not (spf and dkim and dmarc) and ar:
        s = ar.lower()
        if 'spf=' in s and not spf:
            try:
                spf = s.split('spf=')[1].split()[0]
            except Exception:
                pass
        if 'dkim=' in s and not dkim:
            try:
                dkim = s.split('dkim=')[1].split()[0]
            except Exception:
                pass
        if 'dmarc=' in s and not dmarc:
            try:
                dmarc = s.split('dmarc=')[1].split()[0]
            except Exception:
                pass

    # Normalize values
    def norm(v: str, ok: Tuple[str, ...]) -> str:
        v = (v or '').strip().lower()
        return v if v in ok else ('' if v == 'none' else v)

    spf = norm(spf, ('pass','fail','softfail','neutral','none'))
    dkim = norm(dkim, ('pass','fail','permerror','temperror','none'))
    dmarc = norm(dmarc, ('pass','fail','quarantine','reject','none'))

    # Simple risk: start at 0.2, add penalties for failures and missing
    risk = 0.2
    if spf in ('fail','softfail') or not spf:
        risk += 0.3
    if dkim in ('fail','permerror','temperror') or not dkim:
        risk += 0.3
    if dmarc in ('fail','quarantine','reject') or not dmarc:
        risk += 0.3
    risk = max(0.0, min(1.0, round(risk, 2)))

    return {'spf': spf or 'none', 'dkim': dkim or 'none', 'dmarc': dmarc or 'none', 'risk': risk}

__all__ = [
    'normalize_display_name','detect_homograph','detect_homograph_against_brands',
    'cluster_by_campaign','parse_email_signals','PROTECTED_BRANDS'
]
