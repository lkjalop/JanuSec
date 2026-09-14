"""
IOC Cross-Reference Guard (P1)
Validates Indicators of Compromise (IOCs) across multiple independent threat
intelligence feeds before marking them as 'confirmed'.  An IOC must appear in
at least N_MIN_FEEDS independent feeds (default 2) to be promoted from
'candidate' to 'confirmed', preventing a single compromised/poisoned feed from
causing FP storms or denial-of-service via mass IP blocking.

Architecture:
  - FeedAdapter: thin interface each feed implements (get_reputation)
  - IOCRecord: holds per-feed hit info and final verdict
  - IOCCrossReference: orchestrates cross-feed validation with TTL cache

Env vars:
    IOC_MIN_FEEDS           — minimum feeds required to confirm an IOC (default 2)
    IOC_CACHE_TTL_SECONDS   — result cache TTL (default 3600)
    IOC_MAX_RETRIES         — per-feed retry attempts (default 2)
    IOC_FEED_TIMEOUT_SECS   — per-feed HTTP timeout (default 5)
"""
from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

_MIN_FEEDS = int(os.getenv('IOC_MIN_FEEDS', '2'))
_CACHE_TTL = int(os.getenv('IOC_CACHE_TTL_SECONDS', '3600'))
_MAX_RETRIES = int(os.getenv('IOC_MAX_RETRIES', '2'))
_FEED_TIMEOUT = int(os.getenv('IOC_FEED_TIMEOUT_SECS', '5'))


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class FeedHit:
    feed_name: str
    ioc_value: str
    confidence: float           # 0.0 – 1.0
    categories: list[str]
    raw: dict = field(default_factory=dict)


@dataclass
class IOCRecord:
    ioc_value: str
    ioc_type: str               # 'ip' | 'domain' | 'hash' | 'url' | 'email'
    hits: list[FeedHit] = field(default_factory=list)
    # Derived
    confirmed: bool = False
    feed_count: int = 0
    avg_confidence: float = 0.0
    categories: list[str] = field(default_factory=list)
    evaluated_at: float = field(default_factory=time.time)

    def compute(self) -> 'IOCRecord':
        """Derive confirmed/confidence/categories from per-feed hits."""
        self.feed_count = len(self.hits)
        self.confirmed = self.feed_count >= _MIN_FEEDS
        if self.hits:
            self.avg_confidence = sum(h.confidence for h in self.hits) / len(self.hits)
            cats: set[str] = set()
            for h in self.hits:
                cats.update(h.categories)
            self.categories = sorted(cats)
        return self


# ---------------------------------------------------------------------------
# Feed adapter protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class FeedAdapter(Protocol):
    """Minimal interface each threat intel feed adapter must implement."""
    name: str

    def get_reputation(self, ioc_value: str, ioc_type: str) -> FeedHit | None:
        """Query the feed synchronously; return FeedHit or None if not found."""
        ...


# ---------------------------------------------------------------------------
# Built-in lightweight feed adapters
# ---------------------------------------------------------------------------

class AbuseCHMalwareFeed:
    """abuse.ch URLhaus / MalwareBazaar (no API key needed for basic lookups)."""
    name = 'abuse_ch'

    def get_reputation(self, ioc_value: str, ioc_type: str) -> FeedHit | None:
        import json as _json
        import urllib.request as _req
        import urllib.parse as _parse
        if ioc_type not in ('url', 'domain', 'hash', 'ip'):
            return None
        try:
            if ioc_type == 'hash':
                url = 'https://mb-api.abuse.ch/api/v1/'
                data = _parse.urlencode({'query': 'get_info', 'hash': ioc_value}).encode()
            elif ioc_type in ('url', 'domain'):
                url = 'https://urlhaus-api.abuse.ch/v1/host/'
                data = _parse.urlencode({'host': ioc_value}).encode()
            else:
                return None
            request = _req.Request(url, data=data, method='POST', headers={'Accept': 'application/json'})
            with _req.urlopen(request, timeout=_FEED_TIMEOUT) as resp:  # noqa: S310
                body = _json.loads(resp.read())
            status = body.get('query_status') or body.get('url_status', '')
            if 'no_results' in status or 'not_found' in status:
                return None
            return FeedHit(
                feed_name=self.name,
                ioc_value=ioc_value,
                confidence=0.85,
                categories=['malware'],
                raw=body,
            )
        except Exception as exc:
            logger.debug('abuse_ch feed error for %s: %s', ioc_value, exc)
            return None


class AbuseIPDBFeed:
    """AbuseIPDB (requires API key via ABUSEIPDB_API_KEY env var)."""
    name = 'abuseipdb'
    _API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')

    def get_reputation(self, ioc_value: str, ioc_type: str) -> FeedHit | None:
        if ioc_type != 'ip' or not self._API_KEY:
            return None
        import json as _json
        import urllib.request as _req
        try:
            url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ioc_value}&maxAgeInDays=90'
            request = _req.Request(url, headers={
                'Key': self._API_KEY,
                'Accept': 'application/json',
            })
            with _req.urlopen(request, timeout=_FEED_TIMEOUT) as resp:  # noqa: S310
                body = _json.loads(resp.read())
            score = body.get('data', {}).get('abuseConfidenceScore', 0)
            if score < 25:
                return None
            return FeedHit(
                feed_name=self.name,
                ioc_value=ioc_value,
                confidence=min(1.0, score / 100),
                categories=['abuse', 'ip_reputation'],
                raw=body,
            )
        except Exception as exc:
            logger.debug('abuseipdb feed error for %s: %s', ioc_value, exc)
            return None


class GreyNoiseFeed:
    """GreyNoise Community API (free tier, requires GREYNOISE_API_KEY for extended)."""
    name = 'greynoise'
    _API_KEY = os.getenv('GREYNOISE_API_KEY', '')

    def get_reputation(self, ioc_value: str, ioc_type: str) -> FeedHit | None:
        if ioc_type != 'ip':
            return None
        import json as _json
        import urllib.request as _req
        try:
            url = f'https://api.greynoise.io/v3/community/{ioc_value}'
            headers: dict = {'Accept': 'application/json'}
            if self._API_KEY:
                headers['key'] = self._API_KEY
            request = _req.Request(url, headers=headers)
            with _req.urlopen(request, timeout=_FEED_TIMEOUT) as resp:  # noqa: S310
                body = _json.loads(resp.read())
            classification = body.get('classification', '')
            if classification != 'malicious':
                return None
            return FeedHit(
                feed_name=self.name,
                ioc_value=ioc_value,
                confidence=0.90,
                categories=[classification, 'scanner'],
                raw=body,
            )
        except Exception as exc:
            logger.debug('greynoise feed error for %s: %s', ioc_value, exc)
            return None


class InternalBlocklistFeed:
    """
    Internal JanuSec allowlist/blocklist checked from INTERNAL_BLOCKLIST_PATH
    (newline-separated IOC values, or JSON list).
    """
    name = 'internal_blocklist'
    _PATH = os.getenv('INTERNAL_BLOCKLIST_PATH', 'data/blocklist.txt')
    _entries: set[str] = set()
    _loaded_at: float = 0.0

    def _load(self) -> None:
        import pathlib
        p = pathlib.Path(self._PATH)
        if not p.exists():
            return
        if time.time() - self._loaded_at < 300:
            return
        try:
            text = p.read_text(errors='replace')
            if text.strip().startswith('['):
                import json as _j
                self._entries = set(_j.loads(text))
            else:
                self._entries = {line.strip() for line in text.splitlines() if line.strip()}
            self._loaded_at = time.time()
        except Exception as exc:
            logger.debug('internal_blocklist load error: %s', exc)

    def get_reputation(self, ioc_value: str, ioc_type: str) -> FeedHit | None:
        self._load()
        if ioc_value in self._entries or ioc_value.lower() in self._entries:
            return FeedHit(
                feed_name=self.name,
                ioc_value=ioc_value,
                confidence=1.0,
                categories=['internal_blocklist'],
                raw={},
            )
        return None


# ---------------------------------------------------------------------------
# Cross-reference engine
# ---------------------------------------------------------------------------

class IOCCrossReference:
    """Validate IOCs across multiple feeds with TTL caching."""

    def __init__(
        self,
        feeds: list[FeedAdapter] | None = None,
        min_feeds: int = _MIN_FEEDS,
        cache_ttl: int = _CACHE_TTL,
    ) -> None:
        self.min_feeds = min_feeds
        self.cache_ttl = cache_ttl
        self._feeds: list[FeedAdapter] = feeds or self._default_feeds()
        # Cache: ioc_key → (IOCRecord, expiry_ts)
        self._cache: dict[str, tuple[IOCRecord, float]] = {}

    @staticmethod
    def _default_feeds() -> list[FeedAdapter]:
        return [
            AbuseCHMalwareFeed(),  # type: ignore[list-item]
            AbuseIPDBFeed(),       # type: ignore[list-item]
            GreyNoiseFeed(),       # type: ignore[list-item]
            InternalBlocklistFeed(),  # type: ignore[list-item]
        ]

    def _cache_key(self, ioc_value: str, ioc_type: str) -> str:
        return hashlib.sha256(f'{ioc_type}:{ioc_value}'.encode()).hexdigest()[:16]

    def validate(self, ioc_value: str, ioc_type: str = 'ip') -> IOCRecord:
        """Cross-check an IOC across all registered feeds.

        Returns an IOCRecord; record.confirmed=True when ≥ min_feeds agree.
        Results are cached for cache_ttl seconds.
        """
        cache_key = self._cache_key(ioc_value, ioc_type)
        cached, expiry = self._cache.get(cache_key, (None, 0.0))
        if cached and time.time() < expiry:
            return cached

        record = IOCRecord(ioc_value=ioc_value, ioc_type=ioc_type)

        for feed in self._feeds:
            hit: FeedHit | None = None
            for attempt in range(_MAX_RETRIES):
                try:
                    hit = feed.get_reputation(ioc_value, ioc_type)
                    break
                except Exception as exc:
                    logger.debug('ioc_cross_reference: feed %s attempt %d failed: %s',
                                 feed.name, attempt + 1, exc)
            if hit:
                record.hits.append(hit)

        record.compute()
        self._cache[cache_key] = (record, time.time() + self.cache_ttl)

        if record.confirmed:
            logger.info(
                'ioc_cross_reference: CONFIRMED %s %s — feeds=%d avg_conf=%.2f cats=%s',
                ioc_type, ioc_value, record.feed_count, record.avg_confidence, record.categories,
            )
        elif record.hits:
            logger.debug(
                'ioc_cross_reference: CANDIDATE %s %s — feeds=%d (need %d)',
                ioc_type, ioc_value, record.feed_count, self.min_feeds,
            )

        return record

    def bulk_validate(self, iocs: list[dict[str, str]]) -> list[IOCRecord]:
        """Validate a list of {value, type} dicts. Returns IOCRecord for each."""
        return [self.validate(item['value'], item.get('type', 'ip')) for item in iocs]

    def is_confirmed(self, ioc_value: str, ioc_type: str = 'ip') -> bool:
        return self.validate(ioc_value, ioc_type).confirmed

    def flush_cache(self) -> None:
        """Clear the validation cache (useful for tests and feed reloads)."""
        self._cache.clear()

    def add_feed(self, feed: FeedAdapter) -> None:
        self._feeds.append(feed)


# Module-level singleton
_cross_ref = IOCCrossReference()


def get_cross_reference() -> IOCCrossReference:
    return _cross_ref
