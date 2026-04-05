from __future__ import annotations

import logging
import re
import time
from typing import Dict, List, Optional, Tuple

from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

logger = logging.getLogger(__name__)


TRACKING_PARAMS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "gclid",
    "mc_eid",
    "proofpoint",
    "mimecast",
}


def _decode_punycode(host: str) -> str:
    host = host.strip().lower()
    if host.startswith("xn--"):
        try:
            import idna  # optional
            return idna.decode(host)
        except Exception:
            return host
    return host


def normalize_url(url: str) -> str:
    """Normalize URL: lowercase host, enforce scheme, strip trackers, decode punycode."""
    if not url:
        return url
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme or "https"
        host = _decode_punycode(parsed.netloc or parsed.hostname or "")

        # strip tracking params
        query_pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k not in TRACKING_PARAMS]
        query = urlencode(query_pairs)

        path = re.sub(r"/+", "/", parsed.path or "/")
        norm = urlunparse((scheme, host, path, "", query, ""))
        return norm
    except Exception:
        return url


def _hamming_distance(a: str, b: str) -> int:
    if len(a) != len(b):
        # pad shorter
        m = max(len(a), len(b))
        a = a.ljust(m, " ")
        b = b.ljust(m, " ")
    return sum(ch1 != ch2 for ch1, ch2 in zip(a, b))


def _levenshtein_distance(s1: str, s2: str) -> int:
    if s1 == s2:
        return 0
    if not s1:
        return len(s2)
    if not s2:
        return len(s1)
    # DP O(n*m) small strings only
    n, m = len(s1), len(s2)
    dp = list(range(m + 1))
    for i in range(1, n + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, m + 1):
            tmp = dp[j]
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            dp[j] = min(
                dp[j] + 1,      # deletion
                dp[j - 1] + 1,  # insertion
                prev + cost,    # substitution
            )
            prev = tmp
    return dp[m]


SAFE_LINK_PREFIXES = [
    "https://urldefense.proofpoint.com/",
    "https://protect-us.mimecast.com/",
]


def decode_rewritten_link(url: str) -> str:
    """Best-effort decode for Proofpoint/Mimecast safe links.

    Keeps strict tolerance and returns original on parsing failure.
    """
    try:
        if any(url.startswith(pfx) for pfx in SAFE_LINK_PREFIXES):
            parsed = urlparse(url)
            qs = dict(parse_qsl(parsed.query))
            # Proofpoint encodes original in 'u' parameter; Mimecast uses 'u' or 'url'
            target = qs.get("u") or qs.get("url")
            if target:
                return target
    except Exception:
        pass
    return url


def resolve_redirect(url: str, budget_hops: int = 3, timeout_seconds: float = 3.0) -> Tuple[str, List[str]]:
    """Resolve limited redirects via HTTP, returning final URL and hop trail.

    Uses lightweight HEAD then GET fallback. Denylists dynamic content by path patterns.
    """
    hops: List[str] = []
    current = url
    deny_patterns = [r"/login", r"/oauth", r"/authorize", r"/consent"]
    try:
        import requests
    except Exception:
        # No network client; return original
        return current, hops

    session = requests.Session()
    session.max_redirects = budget_hops
    for _ in range(budget_hops):
        hops.append(current)
        try:
            if any(re.search(pat, urlparse(current).path or "") for pat in deny_patterns):
                break
            resp = session.head(current, allow_redirects=False, timeout=timeout_seconds)
            if resp.is_redirect:
                loc = resp.headers.get("Location")
                if not loc:
                    break
                current = normalize_url(loc)
                continue
            # Fallback GET once
            resp = session.get(current, allow_redirects=False, timeout=timeout_seconds)
            if resp.is_redirect:
                loc = resp.headers.get("Location")
                if not loc:
                    break
                current = normalize_url(loc)
                continue
            break
        except Exception:
            # timeout or errors — stop
            break
    return current, hops


def enrich_urls(event) -> None:
    """Normalize event URLs, decode safelinks, resolve minimal redirects, and attach lookalike metrics."""
    try:
        raw_urls: List[str] = list(event.urls or [])
        enriched: List[Dict[str, object]] = []
        for u in raw_urls:
            base = decode_rewritten_link(u)
            norm = normalize_url(base)
            final, trail = resolve_redirect(norm)

            host = urlparse(final).hostname or ""
            sender_dom = None
            sender = (event.sender or {}).get("email") if isinstance(event.sender, dict) else None
            if sender and "@" in sender:
                sender_dom = sender.rpartition("@")[2].lower()

            # Lookalike distance: compare host label vs sender domain label
            lookalike = None
            if host and sender_dom:
                lookalike = {
                    "hamming": _hamming_distance(host, sender_dom),
                    "levenshtein": _levenshtein_distance(host, sender_dom),
                }

            enriched.append({
                "original": u,
                "decoded": base,
                "normalized": norm,
                "final": final,
                "redirects": trail,
                "host": host,
                "lookalike": lookalike,
            })

        # Attach enriched URLs (non-destructive)
        event.raw_event = dict(event.raw_event or {})
        event.raw_event["url_enrichment"] = enriched
        logger.debug("url enrichment applied", extra={"count": len(enriched)})
    except Exception as e:  # pragma: no cover
        logger.warning("url enrichment failed: %s", e)
