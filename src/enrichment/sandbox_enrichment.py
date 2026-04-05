from __future__ import annotations

import logging
import os
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class _Cache:
    def __init__(self, ttl_seconds: int = 3600):
        self.ttl = ttl_seconds
        self.store: Dict[str, Tuple[float, Dict[str, object]]] = {}

    def get(self, key: str) -> Optional[Dict[str, object]]:
        now = time.time()
        entry = self.store.get(key)
        if not entry:
            return None
        ts, val = entry
        if now - ts > self.ttl:
            self.store.pop(key, None)
            return None
        return val

    def set(self, key: str, val: Dict[str, object]) -> None:
        self.store[key] = (time.time(), val)


_vt_cache = _Cache(ttl_seconds=int(os.getenv("VT_CACHE_TTL", "3600")))


def _vt_lookup_url(url: str) -> Optional[Dict[str, object]]:
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return None
    cache = _vt_cache.get(f"url:{url}")
    if cache:
        cache["cached"] = True
        return cache
    try:
        import requests
        headers = {"x-apikey": api_key}
        resp = requests.get(f"https://www.virustotal.com/api/v3/urls", params={"url": url}, headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            # Simplified extraction
            verdict = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            out = {
                "vt_score": verdict,
                "family": data.get("data", {}).get("attributes", {}).get("popular_threat_classification", {}).get("suggested_threat_label"),
                "confidence": data.get("data", {}).get("attributes", {}).get("reputation"),
                "first_seen": data.get("data", {}).get("attributes", {}).get("first_submission_date"),
                "cached": False,
            }
            _vt_cache.set(f"url:{url}", out)
            return out
    except Exception:
        return None
    return None


def _vt_lookup_hash(sha256: str) -> Optional[Dict[str, object]]:
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return None
    cache = _vt_cache.get(f"hash:{sha256}")
    if cache:
        cache["cached"] = True
        return cache
    try:
        import requests
        headers = {"x-apikey": api_key}
        resp = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            out = {
                "vt_score": attrs.get("last_analysis_stats"),
                "malware_family": attrs.get("popular_threat_classification", {}).get("suggested_threat_label"),
                "sandbox_behavior": attrs.get("sandbox_verdicts"),
                "ioc_extraction": attrs.get("sigma_analysis"),
                "confidence": attrs.get("reputation"),
                "first_seen": attrs.get("first_submission_date"),
                "cached": False,
            }
            _vt_cache.set(f"hash:{sha256}", out)
            return out
    except Exception:
        return None
    return None


def enrich_sandbox(event) -> None:
    """Batch lookup URLs and attachment hashes; attach verdicts.

    Uses caching and rate-limited VT integrations when configured.
    """
    try:
        raw_urls: List[str] = list(event.urls or [])
        url_verdicts: List[Dict[str, object]] = []
        for u in raw_urls[:5]:  # budget
            v = _vt_lookup_url(u)
            if v:
                url_verdicts.append({"url": u, **v})

        hash_verdicts: List[Dict[str, object]] = []
        for att in list(event.attachments or [])[:5]:
            sha256 = att.get("sha256") if isinstance(att, dict) else None
            if not sha256:
                continue
            v = _vt_lookup_hash(sha256)
            if v:
                hash_verdicts.append({"sha256": sha256, **v})

        event.raw_event = dict(event.raw_event or {})
        event.raw_event["sandbox_enrichment"] = {
            "url": url_verdicts,
            "hash": hash_verdicts,
        }
        logger.debug("sandbox enrichment applied", extra={
            "url_count": len(url_verdicts),
            "hash_count": len(hash_verdicts),
        })
    except Exception as e:  # pragma: no cover
        logger.warning("sandbox enrichment failed: %s", e)
