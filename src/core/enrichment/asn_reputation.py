from __future__ import annotations
import os, threading, time, json
from functools import lru_cache
from typing import Optional
import ipaddress

_lock = threading.RLock()
_cache: dict[str, dict] = {}
_cache_path = os.getenv('ASN_CACHE_PATH','data/asn_cache.json')
_last_refresh = 0
_refresh_interval = int(os.getenv('ASN_REFRESH_INTERVAL_SECONDS','3600') or 3600)

def _load_cache():
    global _cache
    try:
        if os.path.exists(_cache_path):
            with open(_cache_path,'r',encoding='utf-8') as fh:
                _cache = json.load(fh)
    except Exception:
        _cache = {}

def _save_cache():
    try:
        os.makedirs(os.path.dirname(_cache_path), exist_ok=True)
        with open(_cache_path,'w',encoding='utf-8') as fh:
            json.dump(_cache, fh)
    except Exception:
        pass

def _ip_to_int(ip: str):
    try:
        return int(ipaddress.ip_address(ip))
    except Exception:
        return None

@lru_cache(maxsize=4096)
def asn_lookup(ip: str) -> Optional[dict]:
    """Return ASN record for ip from cache or None."""
    if not ip:
        return None
    with _lock:
        if not _cache:
            _load_cache()
        # cache keys stored as strings of ip or prefix
        # direct hit
        if ip in _cache:
            return _cache[ip]
        # try find containing prefix entry
        try:
            i_val = _ip_to_int(ip)
            if i_val is None:
                return None
            for k,v in list(_cache.items()):
                try:
                    if '/' in k:
                        net = ipaddress.ip_network(k, strict=False)
                        if ipaddress.ip_address(ip) in net:
                            return v
                except Exception:
                    continue
        except Exception:
            pass
    return None

def background_refresher():
    """Background refresher that periodically saves or fetches ASN cache.

    When running live, this can be extended to call Team Cymru lookups and
    persist results into the on-disk cache. For tests we just ensure existing
    cache is loaded.
    """
    def _loop():
        global _last_refresh
        while True:
            try:
                _load_cache()
                _last_refresh = time.time()
                _save_cache()
            except Exception:
                pass
            time.sleep(max(60, _refresh_interval))
    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    return t



# Provide a module-level `requests` symbol so tests can patch
# `src.core.enrichment.asn_reputation.requests.get` even if `requests` is
# not installed in the environment.
try:
    import requests  # type: ignore
except Exception:  # pragma: no cover - fallback for minimal test environments
    class _RequestsFallback:
        def get(self, *args, **kwargs):
            raise RuntimeError("requests not available")

    requests = _RequestsFallback()

TOR_PATH = os.getenv("TOR_EXIT_NODES_PATH", os.path.join("data", "tor_exit_nodes.txt"))
BAD_ASNS_PATH = os.getenv("BAD_ASNS_PATH", os.path.join("data", "bad_asns.txt"))
ASN_REPUTATION_PATH = os.getenv("ASN_REPUTATION_PATH") or os.getenv("ASN_REPUTATION_FILE")

_tor_exits: Set[str] = set()
_bad_asns: Set[int] = set()
_reputation: Dict[str, Any] = {}


def _load_files() -> None:
    """Load tor exit IPs and bad ASN ints from disk into module-level caches."""
    global _tor_exits, _bad_asns
    t: Set[str] = set()
    a: Set[int] = set()
    # Respect runtime environment overrides so tests that set
    # TOR_EXIT_NODES_PATH / BAD_ASNS_PATH at runtime are honored.
    tor_path = os.getenv("TOR_EXIT_NODES_PATH", TOR_PATH)
    asn_path = os.getenv("BAD_ASNS_PATH", BAD_ASNS_PATH)

    if os.path.exists(tor_path):
        try:
            with open(tor_path, "r", encoding="utf-8", errors="ignore") as fh:
                for ln in fh:
                    ln = ln.strip()
                    if ln and not ln.startswith("#"):
                        t.add(ln.split()[0])
        except Exception:
            pass

    if os.path.exists(asn_path):
        try:
            with open(asn_path, "r", encoding="utf-8", errors="ignore") as fh:
                for ln in fh:
                    ln = ln.strip()
                    if not ln or ln.startswith("#"):
                        continue
                    try:
                        a.add(int(ln.split()[0]))
                    except Exception:
                        continue
        except Exception:
            pass

    _tor_exits = t
    _bad_asns = a


def refresh_once(*, tor_url: Optional[str] = None, asn_url: Optional[str] = None) -> Dict[str, Any]:
    """Refresh configured TOR/asn lists and reload caches.

    If `TOR_EXIT_LIST_URL` or `BAD_ASNS_URL` (or the function args) are set,
    attempts to fetch and persist the lists using `requests.get`. Tests
    commonly monkeypatch `requests.get` to return a dummy response.
    """
    summary = {"tor": False, "asn": False, "ts": time.time()}

    tor_source = tor_url or os.getenv("TOR_EXIT_LIST_URL")
    asn_source = asn_url or os.getenv("BAD_ASNS_URL")

    # use runtime paths from env so tests that monkeypatch env vars work
    tor_path = os.getenv("TOR_EXIT_NODES_PATH", TOR_PATH)
    asn_path = os.getenv("BAD_ASNS_PATH", BAD_ASNS_PATH)

    # try to fetch and write tor list
    if tor_source:
        try:
            r = requests.get(tor_source, timeout=10)
            if getattr(r, "status_code", None) == 200:
                try:
                    os.makedirs(os.path.dirname(tor_path) or "", exist_ok=True)
                except Exception:
                    pass
                try:
                    with open(tor_path, "w", encoding="utf-8") as fh:
                        fh.write(r.text)
                    summary["tor"] = True
                except Exception:
                    pass
        except Exception:
            pass

    # try to fetch and write ASN list
    if asn_source:
        try:
            r2 = requests.get(asn_source, timeout=10)
            if getattr(r2, "status_code", None) == 200:
                try:
                    os.makedirs(os.path.dirname(asn_path) or "", exist_ok=True)
                except Exception:
                    pass
                try:
                    with open(asn_path, "w", encoding="utf-8") as fh:
                        fh.write(r2.text)
                    summary["asn"] = True
                except Exception:
                    pass
        except Exception:
            pass

    # reload caches from disk (whether written now or existing)
    try:
        _load_files()
    except Exception:
        pass

    # if no network fetch happened, reflect current disk state
    if not summary["tor"]:
        # reflect current disk state using runtime paths
        summary["tor"] = os.path.exists(tor_path) and bool(_tor_exits)
    if not summary["asn"]:
        summary["asn"] = os.path.exists(asn_path) and bool(_bad_asns)
    summary["ts"] = time.time()
    return summary


def get_tor_exits() -> Set[str]:
    return set(_tor_exits)


def get_bad_asns() -> Set[int]:
    return set(_bad_asns)


def load_reputation(path: Optional[str] = None) -> Dict[str, Any]:
    global _reputation
    p = path or ASN_REPUTATION_PATH
    if not p or not os.path.exists(p):
        return {}
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as fh:
            data = json.load(fh)
            _reputation = {str(k): v for k, v in data.items()}
            return _reputation
    except Exception:
        return {}


def get_asn_reputation(asn: int | str) -> Optional[Any]:
    if asn is None:
        return None
    return _reputation.get(str(asn))


# initialize caches if files exist
try:
    _load_files()
except Exception:
    pass


__all__ = ["refresh_once", "get_bad_asns", "get_tor_exits", "load_reputation", "get_asn_reputation"]
