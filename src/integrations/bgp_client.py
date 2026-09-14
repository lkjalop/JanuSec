import os
import json
import time
from typing import Any, Dict, List, Optional, Tuple

# Existing imports assumed here

def _checkpoint_path() -> str:
    d = os.environ.get("BGP_CHECKPOINT_DIR", os.path.join("data", "cursors"))
    return os.path.join(d, "bgp_checkpoint.json")
DEFAULT_TTL_SECONDS = int(os.environ.get("BGP_FEED_TTL_SECONDS", "3600"))


def _ensure_dir(path: str) -> None:
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


def _load_checkpoint() -> Dict[str, Any]:
    path = _checkpoint_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_checkpoint(data: Dict[str, Any]) -> None:
    path = _checkpoint_path()
    _ensure_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


class BGPCheckpoint:
    def __init__(self, sources: Optional[List[str]] = None):
        self.sources = sources or []

    def get(self, source: str) -> Tuple[Optional[str], Optional[int]]:
        cp = _load_checkpoint()
        entry = cp.get(source) or {}
        return entry.get("etag"), entry.get("ts")

    def set(self, source: str, etag: Optional[str], ts: Optional[int] = None) -> None:
        cp = _load_checkpoint()
        cp[source] = {"etag": etag, "ts": ts or int(time.time())}
        _save_checkpoint(cp)

    def expired(self, source: str, ttl_seconds: Optional[int] = None) -> bool:
        ttl = ttl_seconds or DEFAULT_TTL_SECONDS
        _, ts = self.get(source)
        if not ts:
            return True
        return (int(time.time()) - int(ts)) > int(ttl)

    # Source registry helpers
    def add_source(self, source: str) -> None:
        if source not in self.sources:
            self.sources.append(source)

    def list_sources(self) -> List[str]:
        return list(self.sources)

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Set

try:
    import httpx  # type: ignore
except Exception:
    httpx = None  # type: ignore


class BgpClient:
    """Lightweight BGP incidents client (hijacks/leaks) with TTL + persistence.

    Feed format is normalized to a flat set of CIDR prefixes. Network calls are optional.
    """

    def __init__(self) -> None:
        self.feed_url = os.getenv('BGP_FEED_URL', '').strip()
        self.ttl = int(os.getenv('BGP_CACHE_TTL_SECONDS', '600') or 600)
        self.persist_path = Path(os.getenv('BGP_CACHE_FILE', 'data/bgp_incidents.json'))
        self._prefixes: Set[str] = set()
        self._last = 0.0
        self._lock = asyncio.Lock()
        self._stop = asyncio.Event()
        self._interval = int(os.getenv('BGP_REFRESH_INTERVAL_SECONDS', '600') or 600)
        try:
            self.persist_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        self._load()

    def _load(self) -> None:
        try:
            if self.persist_path.exists():
                j = json.loads(self.persist_path.read_text(encoding='utf-8'))
                arr = j.get('prefixes') or []
                self._prefixes = {str(x) for x in arr}
                self._last = float(j.get('ts') or 0.0)
        except Exception:
            pass
        # best-effort: push loaded prefixes into network hopgraph for context
        try:
            from src.core.graph.network_hopgraph import ingest_bgp_prefix

            for p in list(self._prefixes):
                try:
                    ingest_bgp_prefix(p, {'source': 'bgp_cache', 'ts': self._last})
                except Exception:
                    pass
        except Exception:
            # avoid hard dependency if import fails in certain test contexts
            pass

    def _save(self) -> None:
        try:
            payload = {'prefixes': sorted(list(self._prefixes)), 'ts': time.time()}
            self.persist_path.write_text(json.dumps(payload), encoding='utf-8')
        except Exception:
            pass

    @staticmethod
    def parse_feed(data: Any) -> Set[str]:
        """Normalize a feed into a set of CIDR prefixes.

        Accepts structures like { incidents:[{prefix:'x/y'}, ...] } or a flat list of strings.
        """
        out: Set[str] = set()
        try:
            if isinstance(data, dict):
                arr = data.get('incidents') or data.get('prefixes') or []
            elif isinstance(data, list):
                arr = data
            else:
                arr = []
            for it in arr:
                if isinstance(it, str):
                    p = it.strip()
                    if '/' in p:
                        out.add(p)
                elif isinstance(it, dict):
                    p = (it.get('prefix') or it.get('cidr') or '').strip()
                    if p and '/' in p:
                        out.add(p)
        except Exception:
            return set()
        return out

    async def refresh(self) -> Dict[str, Any]:
        async with self._lock:
            now = time.time()
            if self._prefixes and (now - self._last) < self.ttl:
                return {'ok': True, 'cached': True, 'count': len(self._prefixes)}
            if not self.feed_url or httpx is None:
                # no-op if feed is not configured or httpx not installed
                self._last = now
                self._save()
                return {'ok': True, 'cached': True, 'count': len(self._prefixes)}
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    r = await client.get(self.feed_url)
                    r.raise_for_status()
                    data = r.json()
                prefixes = self.parse_feed(data)
                if prefixes:
                    self._prefixes = prefixes
                    self._last = now
                    self._save()
                    # push recent prefixes into network hopgraph
                    try:
                        from src.core.graph.network_hopgraph import ingest_bgp_prefix

                        for p in list(prefixes):
                            try:
                                ingest_bgp_prefix(p, {'source': 'bgp_feed', 'ts': now})
                            except Exception:
                                pass
                    except Exception:
                        pass
                    return {'ok': True, 'cached': False, 'count': len(prefixes)}
                else:
                    self._last = now
                    return {'ok': True, 'cached': False, 'count': 0}
            except Exception as exc:
                return {'ok': False, 'error': str(exc)}

    def get_prefixes(self) -> Set[str]:
        return set(self._prefixes)

    def get_prefix_for_ip(self, ip: str) -> str | None:
        """Return the most specific prefix that contains the ip from the loaded prefixes.

        Uses ipaddress to find matching CIDR and picks longest prefix length.
        """
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            best = None
            best_len = -1
            for p in self._prefixes:
                try:
                    net = ipaddress.ip_network(p, strict=False)
                    if addr in net:
                        if net.prefixlen > best_len:
                            best = p
                            best_len = net.prefixlen
                except Exception:
                    continue
            return best
        except Exception:
            return None

    def get_asn(self, ip: str) -> int | None:
        """Best-effort ASN lookup: try pyasn or ipwhois if available, else None.

        This is optional; function returns None when no lookup available.
        """
        try:
            # prefer a local mapping if prefixes include ASN mapping (not yet supported)
            # fallback to ipwhois
            try:
                from ipwhois import IPWhois  # type: ignore
                obj = IPWhois(ip)
                res = obj.lookup_rdap(asn_methods=['whois'])
                asn = res.get('asn')
                if asn and str(asn).isdigit():
                    return int(asn)
            except Exception:
                pass
        except Exception:
            pass
        return None

    async def run(self) -> None:  # background refresher
        while not self._stop.is_set():
            try:
                await self.refresh()
            except Exception:
                pass
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=max(5, self._interval))
            except asyncio.TimeoutError:
                continue

    def stop(self) -> None:
        self._stop.set()


CLIENT = BgpClient()
