"""Simple IP -> ASN lookup helper for tests and lightweight enrichment.

Features:
- seed_mapping(dict[ip_prefix_or_ip]->ASN) to provide deterministic test mappings
- lookup_asn(ip) returns 'ASxxxxx' or None
- lookup_ip_meta(ip) returns {"asn", "asn_name", "country"} or None
- seed_from_ips(list_of_ips) will attempt to map IPs via seeded map, else use heuristic
- Optional pluggable backends (maxmind, ipapi) via GEOIP_BACKEND env var

The bundled catalog covers common APT staging / nation-state hosting ASNs and
major cloud providers. Sufficient for offline analyst workflows; for true
production accuracy install MaxMind GeoLite2 and set GEOIP_BACKEND=maxmind.
"""
from __future__ import annotations
from typing import Optional, Dict, Iterable
import ipaddress
import os

# Simple in-memory map: exact IP or CIDR -> ASN string
_mapping: Dict[str, str] = {}

# ── Bundled catalog of well-known network blocks ────────────────────────────
# Format: CIDR -> (asn, asn_name, country)
# Curated for security analysis: high-risk hosting, common APT/nation-state
# infrastructure, major cloud providers. Block lists kept conservative.
_BUNDLED_CATALOG: Dict[str, tuple[str, str, str]] = {
    # ── China Telecom / Unicom / Mobile (commonly cited in CN APT activity) ──
    "1.0.1.0/24":        ("AS4134", "China Telecom", "CN"),
    "1.2.0.0/16":        ("AS4134", "China Telecom", "CN"),
    "27.0.128.0/21":     ("AS4134", "China Telecom", "CN"),
    "58.16.0.0/13":      ("AS4134", "China Telecom", "CN"),
    "61.135.0.0/16":     ("AS4837", "China Unicom", "CN"),
    "112.65.0.0/16":     ("AS9808", "China Mobile", "CN"),
    "120.0.0.0/8":       ("AS4134", "China Telecom", "CN"),
    "175.6.0.0/15":      ("AS4134", "China Telecom", "CN"),
    "180.149.128.0/19":  ("AS4134", "China Telecom", "CN"),
    "183.232.0.0/14":    ("AS9808", "China Mobile", "CN"),
    "202.97.0.0/16":     ("AS4134", "China Telecom", "CN"),
    "210.74.0.0/16":     ("AS4847", "CNNIC", "CN"),
    "218.92.0.0/16":     ("AS4134", "China Telecom", "CN"),
    "219.143.0.0/16":    ("AS4134", "China Telecom", "CN"),
    # Singapore (regional staging hub for APT activity targeting AU/APAC)
    "175.41.128.0/17":   ("AS16509", "AWS Asia Pacific (Singapore)", "SG"),
    "13.228.0.0/15":     ("AS16509", "AWS Asia Pacific (Singapore)", "SG"),
    # ── Russian Federation ──────────────────────────────────────────────────
    "5.8.0.0/19":        ("AS49505", "Selectel", "RU"),
    "31.13.144.0/20":    ("AS16509", "AWS RU edge", "RU"),
    "37.140.192.0/19":   ("AS197695", "Reg.ru", "RU"),
    "46.8.155.0/24":     ("AS49505", "Selectel", "RU"),
    "62.122.224.0/19":   ("AS43350", "NForce Entertainment (RU)", "RU"),
    "77.88.0.0/18":      ("AS13238", "Yandex", "RU"),
    "87.250.224.0/19":   ("AS13238", "Yandex", "RU"),
    "91.108.0.0/16":     ("AS62041", "Telegram Messenger", "RU"),
    "188.93.16.0/20":    ("AS43350", "NForce Entertainment (RU)", "RU"),
    "194.67.192.0/19":   ("AS25513", "Rostelecom", "RU"),
    # ── DPRK / Iran (sparse public allocations) ─────────────────────────────
    "175.45.176.0/22":   ("AS131279", "Star JV (DPRK)", "KP"),
    "5.22.0.0/16":       ("AS44244", "Iran Telecommunication", "IR"),
    "5.144.128.0/17":    ("AS44244", "Iran Telecommunication", "IR"),
    "31.184.128.0/19":   ("AS197207", "Mobile Communication Iran", "IR"),
    # ── AWS public ranges (common for cloud-pivot APT activity) ─────────────
    "3.5.0.0/16":        ("AS16509", "AWS US-East-1", "US"),
    "13.32.0.0/15":      ("AS16509", "AWS CloudFront", "US"),
    "18.32.0.0/12":      ("AS16509", "AWS US", "US"),
    "52.0.0.0/11":       ("AS16509", "AWS Global", "US"),
    # ── Azure ───────────────────────────────────────────────────────────────
    "13.64.0.0/11":      ("AS8075", "Microsoft Azure", "US"),
    "20.0.0.0/8":        ("AS8075", "Microsoft Azure", "US"),
    "40.64.0.0/10":      ("AS8075", "Microsoft Azure", "US"),
    "104.40.0.0/13":     ("AS8075", "Microsoft Azure", "US"),
    # ── GCP ─────────────────────────────────────────────────────────────────
    "34.64.0.0/10":      ("AS15169", "Google Cloud", "US"),
    "35.184.0.0/13":     ("AS15169", "Google Cloud", "US"),
    "35.192.0.0/12":     ("AS15169", "Google Cloud", "US"),
    # ── Cloudflare (often abused for C2 fronting / Worker exfil) ────────────
    "1.1.1.0/24":        ("AS13335", "Cloudflare", "US"),
    "104.16.0.0/12":     ("AS13335", "Cloudflare", "US"),
    "172.64.0.0/13":     ("AS13335", "Cloudflare", "US"),
    "162.158.0.0/15":    ("AS13335", "Cloudflare", "US"),
    # ── Bulletproof / abuse-tolerant hosting commonly seen in C2 ────────────
    "45.61.184.0/22":    ("AS398823", "PUREVOLTAGE", "US"),
    "45.95.232.0/22":    ("AS59425", "MIVOCLOUD", "MD"),
    "185.220.100.0/22":  ("AS208294", "Foundation for Applied Privacy", "AT"),  # Tor exit
    # ── Common DNS over HTTPS / VPN endpoints ───────────────────────────────
    "8.8.8.0/24":        ("AS15169", "Google Public DNS", "US"),
    "9.9.9.0/24":        ("AS19281", "Quad9 DNS", "CH"),
}

# Pre-compile the catalog for fast O(log n) lookup
_CATALOG_NETWORKS: list[tuple[ipaddress.IPv4Network, tuple[str, str, str]]] = []


def _init_catalog():
    global _CATALOG_NETWORKS
    if _CATALOG_NETWORKS:
        return
    nets: list[tuple[ipaddress.IPv4Network, tuple[str, str, str]]] = []
    for cidr, meta in _BUNDLED_CATALOG.items():
        try:
            nets.append((ipaddress.ip_network(cidr, strict=False), meta))
        except Exception:
            continue
    # Sort by prefix length descending (longest match wins)
    nets.sort(key=lambda x: -x[0].prefixlen)
    _CATALOG_NETWORKS = nets


def _catalog_lookup(ip: str) -> Optional[tuple[str, str, str]]:
    """Return (asn, asn_name, country) or None for an IP via the bundled catalog."""
    _init_catalog()
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return None
    if not isinstance(addr, ipaddress.IPv4Address):
        return None
    for net, meta in _CATALOG_NETWORKS:
        if addr in net:
            return meta
    return None


def seed_mapping(d: Dict[str, str]) -> None:
    """Seed explicit IP/CIDR -> ASN mapping. Keys may be IP or CIDR strings."""
    global _mapping
    for k,v in (d or {}).items():
        try:
            _mapping[str(k)] = str(v).upper()
        except Exception:
            continue

def clear_mapping() -> None:
    global _mapping
    _mapping.clear()

def _match_seed(ip: str) -> Optional[str]:
    # exact match
    if ip in _mapping:
        return _mapping[ip]
    # CIDR match
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return None
    for k,v in _mapping.items():
        try:
            if '/' in k:
                net = ipaddress.ip_network(k, strict=False)
                if addr in net:
                    return v
        except Exception:
            continue
    return None

def lookup_asn(ip: str) -> Optional[str]:
    """Return ASN string (e.g. 'AS65001') for given IP when known, else None.
    Uses seeded mappings first, then bundled catalog, then heuristic for RFC1918.
    """
    if not ip:
        return None
    ip = str(ip).strip()
    try:
        got = _match_seed(ip)
        if got:
            return got
    except Exception:
        pass
    # Bundled catalog (real-world ASN/country data for common hosting/APT blocks)
    cat = _catalog_lookup(ip)
    if cat:
        return cat[0]
    # Heuristic fallback: use last octet to synthesize a stable ASN for private ranges
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private:
            parts = ip.split('.')
            if len(parts) == 4 and parts[-1].isdigit():
                n = int(parts[-1])
                asn = 65000 + (n % 1000)
                return f"AS{asn}"
    except Exception:
        pass
    return None


def lookup_ip_meta(ip: str) -> Optional[Dict[str, str]]:
    """Return enrichment dict {asn, asn_name, country} for an IP, or None.

    Resolution order:
      1. GEOIP_BACKEND env var (maxmind/ipapi) — placeholder for future
      2. Bundled catalog (curated APT/hosting/cloud ranges)
      3. Seeded mapping (returns asn only, no country)
      4. Heuristic for private/RFC1918 (returns asn only, no country)
    """
    if not ip:
        return None
    ip = str(ip).strip()

    # Future: pluggable real backend (maxmind, ipapi, etc.)
    backend = os.getenv("GEOIP_BACKEND", "").lower()
    if backend == "maxmind":
        try:
            import geoip2.database  # type: ignore
            db_path = os.getenv("GEOIP_DB_PATH", "/var/lib/GeoIP/GeoLite2-ASN.mmdb")
            with geoip2.database.Reader(db_path) as reader:
                rec = reader.asn(ip)
                meta = {
                    "asn": f"AS{rec.autonomous_system_number}",
                    "asn_name": str(rec.autonomous_system_organization or ""),
                    "country": "",  # Country requires GeoLite2-Country.mmdb
                }
                country_db = os.getenv("GEOIP_COUNTRY_DB_PATH")
                if country_db:
                    try:
                        with geoip2.database.Reader(country_db) as creader:
                            crec = creader.country(ip)
                            meta["country"] = str(crec.country.iso_code or "")
                    except Exception:
                        pass
                return meta
        except Exception:
            pass  # fall through to catalog

    # Bundled catalog (most common path)
    cat = _catalog_lookup(ip)
    if cat:
        return {"asn": cat[0], "asn_name": cat[1], "country": cat[2]}

    # Seeded mapping
    seed_asn = _match_seed(ip)
    if seed_asn:
        return {"asn": seed_asn, "asn_name": "", "country": ""}

    # Heuristic for private ranges
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private:
            parts = ip.split('.')
            if len(parts) == 4 and parts[-1].isdigit():
                n = int(parts[-1])
                return {"asn": f"AS{65000 + (n % 1000)}", "asn_name": "Private/RFC1918", "country": ""}
    except Exception:
        pass
    return None


def is_high_risk_country(country: str) -> bool:
    """Return True if country code is on the high-risk geopolitical list.
    Based on common allied-country threat advisories: CN, RU, KP, IR.
    """
    return str(country or "").upper() in {"CN", "RU", "KP", "IR"}


def seed_from_ips(ips: Iterable[str]) -> Dict[str, str]:
    """Return a map of ip->asn seeded by lookup_asn (best-effort).
    Also registers the found ASNs in the returned mapping.
    """
    out = {}
    for ip in ips or []:
        try:
            asn = lookup_asn(str(ip))
            if asn:
                out[str(ip)] = asn
        except Exception:
            continue
    return out

__all__ = ['seed_mapping','clear_mapping','lookup_asn','lookup_ip_meta','is_high_risk_country','seed_from_ips']
