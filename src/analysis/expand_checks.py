"""Deterministic expand checks for the investigate/expand subtask engine.

These checks run synchronously without LLM calls and produce structured
badge annotations that appear alongside LLM subtask cards.

Public API
----------
extract_entity_fields(rows)        -> dict[str, list[str]]  (OPT-1)
impossible_travel_check(rows)      -> CheckResult            (OPT-2)
after_hours_check(rows)            -> CheckResult            (OPT-2)
same_ip_cross_account_check(rows)  -> CheckResult            (OPT-2)
temp_privilege_check(rows)         -> CheckResult            (OPT-2)
brute_force_rate_check(rows)       -> CheckResult            (OPT-2)
beacon_ewma_check(rows)            -> CheckResult            (OPT-2)
dns_entropy_check(rows)            -> CheckResult            (OPT-2)
bgp_hijack_check(rows)             -> CheckResult            (OPT-2)
run_all_checks(rows)               -> list[CheckResult]
"""
from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ── CheckResult ─────────────────────────────────────────────────────────────

class CheckResult:
    """Result of a single deterministic check."""

    def __init__(
        self,
        check_id: str,
        label: str,
        triggered: bool,
        severity: str = "info",  # info | warning | critical
        detail: str = "",
        evidence_rows: Optional[List[int]] = None,
    ):
        self.check_id = check_id
        self.label = label
        self.triggered = triggered
        self.severity = severity
        self.detail = detail
        self.evidence_rows = evidence_rows or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "label": self.label,
            "triggered": self.triggered,
            "severity": self.severity,
            "detail": self.detail,
            "evidence_rows": self.evidence_rows,
        }


# ── OPT-1: Entity resolution ─────────────────────────────────────────────────

_USER_KEYS = ("user", "username", "user_name", "userId", "user_id", "upn", "email")
_IP_KEYS = ("src_ip", "source_ip", "ip", "client_ip", "remote_ip", "dst_ip", "dest_ip", "destination_ip")
_HOST_KEYS = ("host", "hostname", "device", "computer", "endpoint")
_DOMAIN_KEYS = ("dns_query", "sni", "domain", "fqdn", "url")
_SESSION_KEYS = ("session_id", "sessionId", "session")
_TOKEN_KEYS = ("token_id", "tokenId", "token", "access_token", "auth_token")
_POLICY_KEYS = ("policy_id", "policyId", "policy", "role", "iam_role")


def _collect(rows: List[Dict], keys: tuple) -> List[str]:
    seen: set = set()
    out: List[str] = []
    for row in rows:
        for k in keys:
            v = row.get(k)
            if v and isinstance(v, str) and v.strip() and v not in seen:
                seen.add(v)
                out.append(v.strip())
    return out


def extract_entity_fields(rows: List[Dict]) -> Dict[str, List[str]]:
    """Extract canonical entity field values across all rows (OPT-1).

    Returns a dict with keys: users, ips, hosts, sessions, tokens, policies.
    Each value is a deduplicated list of string values found in that field category.
    """
    return {
        "users": _collect(rows, _USER_KEYS),
        "ips": _collect(rows, _IP_KEYS),
        "hosts": _collect(rows, _HOST_KEYS),
        "domains": _collect(rows, _DOMAIN_KEYS),
        "sessions": _collect(rows, _SESSION_KEYS),
        "tokens": _collect(rows, _TOKEN_KEYS),
        "policies": _collect(rows, _POLICY_KEYS),
    }


# ── Timestamp helpers ─────────────────────────────────────────────────────────

_TS_KEYS = ("ts", "timestamp", "time", "event_time", "evt_time", "created_at")


def _parse_ts(row: Dict) -> Optional[datetime]:
    for k in _TS_KEYS:
        v = row.get(k)
        if not v:
            continue
        if isinstance(v, (int, float)):
            try:
                return datetime.fromtimestamp(float(v), tz=timezone.utc)
            except Exception:
                pass
        if isinstance(v, str):
            # ISO 8601 (most common)
            try:
                s = v.replace("Z", "+00:00")
                return datetime.fromisoformat(s)
            except Exception:
                pass
            # epoch string
            try:
                return datetime.fromtimestamp(float(v), tz=timezone.utc)
            except Exception:
                pass
    return None


# ── Geolocation helper ────────────────────────────────────────────────────────

_GEO_KEYS = (
    "geo", "geolocation", "location", "city", "country", "geo_city",
    "geo_country", "src_geo", "src_country",
)
_LAT_KEYS = ("lat", "latitude", "geo_lat")
_LON_KEYS = ("lon", "lng", "longitude", "geo_lon")


def _extract_latlon(row: Dict) -> Optional[tuple]:
    """Return (lat, lon) float tuple or None."""
    lat = lon = None
    for k in _LAT_KEYS:
        if row.get(k) is not None:
            try:
                lat = float(row[k])
                break
            except Exception:
                pass
    for k in _LON_KEYS:
        if row.get(k) is not None:
            try:
                lon = float(row[k])
                break
            except Exception:
                pass
    if lat is not None and lon is not None:
        return (lat, lon)
    # check nested geo dict
    for k in _GEO_KEYS:
        geo = row.get(k)
        if isinstance(geo, dict):
            try:
                return (float(geo.get("lat", 0)), float(geo.get("lon", 0)))
            except Exception:
                pass
    return None


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Haversine distance in km."""
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


# ── OPT-2 checks ─────────────────────────────────────────────────────────────

# Maximum plausible speed for legitimate human travel (km/h).
# Commercial aircraft cruise at ~900 km/h; using 800 as a generous threshold.
_IMPOSSIBLE_TRAVEL_SPEED_KMH = 800.0
# Minimum distance delta that matters (avoid false positives from GPS jitter)
_MIN_DISTANCE_KM = 200.0


def impossible_travel_check(rows: List[Dict]) -> CheckResult:
    """Detect geolocation delta / time delta exceeding human travel speed (OPT-2).

    Looks for the same user appearing from two distant locations within a short
    time window that would be physically impossible.
    """
    check_id = "impossible_travel"

    # Group rows by user
    by_user: Dict[str, List] = {}
    for row in rows:
        user = next((row.get(k) for k in _USER_KEYS if row.get(k)), None)
        if not user:
            continue
        ts = _parse_ts(row)
        geo = _extract_latlon(row)
        if ts and geo:
            by_user.setdefault(str(user), []).append((ts, geo, row.get("row_index")))

    worst_speed = 0.0
    detail_parts: List[str] = []
    evidence: List[int] = []

    for user, events in by_user.items():
        events.sort(key=lambda x: x[0])
        for i in range(len(events) - 1):
            ts1, (lat1, lon1), ri1 = events[i]
            ts2, (lat2, lon2), ri2 = events[i + 1]
            delta_s = (ts2 - ts1).total_seconds()
            if delta_s <= 0:
                continue
            dist_km = _haversine_km(lat1, lon1, lat2, lon2)
            if dist_km < _MIN_DISTANCE_KM:
                continue
            speed_kmh = (dist_km / delta_s) * 3600
            if speed_kmh > _IMPOSSIBLE_TRAVEL_SPEED_KMH:
                if speed_kmh > worst_speed:
                    worst_speed = speed_kmh
                    detail_parts = [
                        f"User '{user}' traveled {dist_km:.0f} km in "
                        f"{delta_s/60:.1f} min ({speed_kmh:.0f} km/h)"
                    ]
                    evidence = [x for x in [ri1, ri2] if x is not None]

    triggered = worst_speed > _IMPOSSIBLE_TRAVEL_SPEED_KMH
    return CheckResult(
        check_id=check_id,
        label="Impossible Travel",
        triggered=triggered,
        severity="critical" if triggered else "info",
        detail="; ".join(detail_parts) if detail_parts else "",
        evidence_rows=evidence,
    )


_AFTER_HOURS_START = 22  # 10 PM local
_AFTER_HOURS_END = 6     # 6 AM local
_SUSPICIOUS_DAYS = {5, 6}  # Saturday=5, Sunday=6


def after_hours_check(rows: List[Dict]) -> CheckResult:
    """Flag events occurring outside business hours (OPT-2).

    Uses UTC timestamps. After-hours = before 06:00 or after 22:00 UTC,
    or on weekends (Saturday/Sunday UTC).
    """
    check_id = "after_hours"
    flagged: List[str] = []
    evidence: List[int] = []

    for row in rows:
        ts = _parse_ts(row)
        if ts is None:
            continue
        hour = ts.hour
        dow = ts.weekday()  # 0=Mon … 6=Sun
        off = (hour >= _AFTER_HOURS_START or hour < _AFTER_HOURS_END) or (dow in _SUSPICIOUS_DAYS)
        if off:
            user = next((row.get(k) for k in _USER_KEYS if row.get(k)), "unknown")
            et = row.get("event_type") or row.get("event_class") or "event"
            flagged.append(f"{et} by '{user}' at {ts.strftime('%Y-%m-%dT%H:%M')} UTC")
            ri = row.get("row_index")
            if ri is not None:
                evidence.append(ri)

    triggered = len(flagged) > 0
    detail = f"{len(flagged)} after-hours event(s): " + "; ".join(flagged[:3])
    return CheckResult(
        check_id=check_id,
        label="After-Hours Activity",
        triggered=triggered,
        severity="warning" if triggered else "info",
        detail=detail if triggered else "",
        evidence_rows=evidence[:10],
    )


def same_ip_cross_account_check(rows: List[Dict]) -> CheckResult:
    """Detect multiple distinct accounts authenticating from the same IP (OPT-2).

    A single IP used by 2+ distinct users within the event set suggests
    credential stuffing, shared malware C2, or pivot via compromised host.
    """
    check_id = "same_ip_cross_account"
    ip_users: Dict[str, set] = {}
    ip_rows: Dict[str, List[int]] = {}

    for row in rows:
        ip = next((row.get(k) for k in _IP_KEYS if row.get(k)), None)
        user = next((row.get(k) for k in _USER_KEYS if row.get(k)), None)
        if ip and user:
            ip_users.setdefault(str(ip), set()).add(str(user))
            ri = row.get("row_index")
            if ri is not None:
                ip_rows.setdefault(str(ip), []).append(ri)

    flagged: List[str] = []
    evidence: List[int] = []
    for ip, users in ip_users.items():
        if len(users) >= 2:
            flagged.append(f"IP {ip} used by {len(users)} accounts: {', '.join(sorted(users)[:4])}")
            evidence.extend(ip_rows.get(ip, []))

    triggered = len(flagged) > 0
    return CheckResult(
        check_id=check_id,
        label="Cross-Account Same IP",
        triggered=triggered,
        severity="critical" if triggered else "info",
        detail="; ".join(flagged) if triggered else "",
        evidence_rows=evidence[:10],
    )


_PRIV_KEYWORDS = re.compile(
    r"admin|root|global.admin|privileged|breakglass|break.glass|"
    r"tier[._\-]?0|tier[._\-]?1|sts:assumeRole|assumeRole|"
    r"iam.passrole|owner|escalat|elevation|superuser|sysadmin|"
    r"sudo|krbtgt|domain.controller|exchange.admin|security.admin",
    re.IGNORECASE,
)
_TEMP_DURATION_HOURS = 4  # privileges lasting < 4h considered temporary


def temp_privilege_check(rows: List[Dict]) -> CheckResult:
    """Detect temporary or anomalous privilege elevation (OPT-2).

    Looks for privileged roles/commands in a short burst, or any explicit
    privilege-escalation indicators in the row's fields.
    """
    check_id = "temp_privilege"
    flagged: List[str] = []
    evidence: List[int] = []

    for row in rows:
        # Check command_line, role, event_type, mitre_technique fields for privilege keywords
        targets = [
            row.get("command_line", ""),
            row.get("role", ""),
            row.get("iam_role", ""),
            row.get("event_type", ""),
            row.get("mitre_technique", ""),
            row.get("analyst_notes", ""),
        ]
        combined = " ".join(str(t) for t in targets if t)
        if _PRIV_KEYWORDS.search(combined):
            user = next((row.get(k) for k in _USER_KEYS if row.get(k)), "unknown")
            et = row.get("event_type") or row.get("mitre_technique") or "event"
            flagged.append(f"'{user}' — {et}")
            ri = row.get("row_index")
            if ri is not None:
                evidence.append(ri)

    triggered = len(flagged) > 0
    detail = f"{len(flagged)} privilege event(s): " + "; ".join(flagged[:4]) if triggered else ""
    return CheckResult(
        check_id=check_id,
        label="Privilege Escalation / Temp Privilege",
        triggered=triggered,
        severity="critical" if triggered else "info",
        detail=detail,
        evidence_rows=evidence[:10],
    )


# ── Phase A: Hot-path deterministic checks ────────────────────────────────────


def brute_force_rate_check(rows: List[Dict]) -> CheckResult:
    """Detect script_kiddie brute force: ≥2 auth attempts/sec from one IP (OPT-2).

    OKT-039 pattern: 847 attempts in 282s = 3/sec from 117.50.39.100.
    APT pattern: 1 attempt per 7 minutes (evades this check deliberately).
    Threshold: ≥2/sec sustained over ≥10 events = automated scanner, not APT.
    """
    from collections import defaultdict

    auth_rows = [
        r for r in rows
        if any(kw in str(r.get("event_type", "")).lower()
               for kw in ("auth", "login", "password", "sign_in", "logon", "failure", "invalid"))
    ]

    by_ip: Dict[str, List[Dict]] = defaultdict(list)
    for r in auth_rows:
        ip = next((r.get(k) for k in _IP_KEYS if r.get(k)), None)
        if ip:
            by_ip[str(ip)].append(r)

    worst_rate = 0.0
    detail = ""
    evidence: List[int] = []

    for ip, ip_rows in by_ip.items():
        if len(ip_rows) < 10:
            continue
        timestamps = sorted(
            str(r.get("ts", "") or r.get("timestamp_utc", "") or "")
            for r in ip_rows
            if r.get("ts") or r.get("timestamp_utc")
        )
        timestamps = [t for t in timestamps if t]
        if len(timestamps) < 2:
            continue
        try:
            t0 = datetime.fromisoformat(timestamps[0].rstrip("Z").replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(timestamps[-1].rstrip("Z").replace("Z", "+00:00"))
            elapsed = max((t1 - t0).total_seconds(), 1.0)
            rate = len(ip_rows) / elapsed
            if rate >= 2.0 and rate > worst_rate:
                worst_rate = rate
                detail = (
                    f"IP {ip}: {len(ip_rows)} auth events in {elapsed:.0f}s "
                    f"= {rate:.1f}/sec (script_kiddie rate, not APT)"
                )
                evidence = [r.get("row_index", 0) for r in ip_rows[:5] if r.get("row_index") is not None]
        except Exception:
            pass

    triggered = worst_rate >= 2.0
    return CheckResult(
        check_id="brute_force_rate",
        label="Brute Force / Script Kiddie Rate",
        triggered=triggered,
        severity="warning" if triggered else "info",
        detail=detail if triggered else "",
        evidence_rows=evidence,
    )


def beacon_ewma_check(rows: List[Dict]) -> CheckResult:
    """Detect algorithmic beaconing via EWMA jitter analysis (OPT-2).

    Two distinct patterns:
      - C2 beacon: interval ~2700s, jitter_ratio ~0.09 (attacker adds noise to evade)
      - Benign heartbeat: interval ~0s or fixed, jitter_ratio ≈ 0.0 (machine clock)
      - ObservIQ supply chain: interval ~300s, jitter_ratio ~0.04, state=needs_investigation

    Trigger conditions:
      - jitter_ratio < 0.001 AND interval > 0 → algorithmic_beacon (suspicious)
      - interval > 0 AND running_stddev > 0 AND jitter_ratio > 0.05 → c2_beacon_jitter
    """
    beacon_rows = [
        r for r in rows
        if r.get("beacon_interval_seconds") not in (None, "", "N/A", "N")
    ]

    algo_beacon: List[str] = []
    c2_jitter: List[str] = []
    evidence: List[int] = []

    for r in beacon_rows:
        try:
            interval = float(r.get("beacon_interval_seconds") or 0)
            jitter = float(r.get("beacon_jitter_ratio") or 0)
            stddev = float(r.get("running_stddev") or 0)
            eid = r.get("event_id") or f"row-{r.get('row_index','?')}"

            if interval > 0 and stddev == 0:
                # Zero EWMA spread → machine-generated timing (heartbeat or supply chain agent)
                # Covers: jitter=0.0 (machine clock) and jitter=0.04 (ObservIQ 4% fixed noise)
                algo_beacon.append(f"{eid}: interval={interval}s stddev=0 (algorithmic/supply-chain)")
                ri = r.get("row_index")
                if ri is not None:
                    evidence.append(ri)
            elif interval > 0 and jitter > 0.05 and stddev > 0:
                c2_jitter.append(f"{eid}: interval={interval}s jitter={jitter:.3f} stddev={stddev}")
                ri = r.get("row_index")
                if ri is not None:
                    evidence.append(ri)
        except Exception:
            pass

    all_flags = algo_beacon + c2_jitter
    triggered = len(all_flags) > 0

    if algo_beacon and c2_jitter:
        detail = (f"Algorithmic beacon (supply-chain/heartbeat): {len(algo_beacon)} event(s). "
                  f"C2 jitter beacon: {len(c2_jitter)} event(s). " + all_flags[0])
        severity = "critical"
    elif c2_jitter:
        detail = f"C2 beacon with evasion jitter: {len(c2_jitter)} event(s). " + c2_jitter[0]
        severity = "critical"
    elif algo_beacon:
        detail = f"Algorithmic beacon (machine-precise interval): {len(algo_beacon)} event(s). " + algo_beacon[0]
        severity = "warning"
    else:
        detail = ""
        severity = "info"

    return CheckResult(
        check_id="beacon_ewma",
        label="Beacon / EWMA Jitter Analysis",
        triggered=triggered,
        severity=severity,
        detail=detail,
        evidence_rows=evidence[:10],
    )


_DNS_ENTROPY_THRESHOLD = 3.5  # bits/char — tunnel threshold from dataset analysis
_DNS_ENTROPY_KEYS = ("dns_label_entropy_bits", "dns_entropy", "label_entropy")


def dns_entropy_check(rows: List[Dict]) -> CheckResult:
    """Flag high-entropy DNS queries indicating DNS tunnel or exfiltration (OPT-2).

    NET-008 (update-cdn-svc.net): 2.1 bits — normal domain, low entropy
    NET-014 (c2-usr-list-b64data.update-cdn-svc.net): 4.6 bits — DNS exfil
    Benign O365/Google DNS: 2.0–3.0 bits

    Threshold: > 3.5 bits/char on a subdomain query = dns_tunnel_candidate
    """
    flagged: List[str] = []
    evidence: List[int] = []
    max_entropy = 0.0

    for r in rows:
        entropy_val = None
        for k in _DNS_ENTROPY_KEYS:
            if r.get(k) is not None:
                try:
                    entropy_val = float(r[k])
                    break
                except Exception:
                    pass
        if entropy_val is None:
            continue

        if entropy_val > _DNS_ENTROPY_THRESHOLD:
            query = str(r.get("dns_query", "") or r.get("sni", ""))[:50]
            eid = r.get("event_id") or f"row-{r.get('row_index','?')}"
            flagged.append(f"{eid}: {entropy_val:.1f} bits '{query}'")
            if entropy_val > max_entropy:
                max_entropy = entropy_val
            ri = r.get("row_index")
            if ri is not None:
                evidence.append(ri)

    triggered = len(flagged) > 0
    severity = "critical" if max_entropy >= 4.0 else ("warning" if triggered else "info")
    detail = (f"{len(flagged)} high-entropy DNS query/queries (>{_DNS_ENTROPY_THRESHOLD} bits — "
              f"DNS tunnel candidate): " + "; ".join(flagged[:3])) if triggered else ""

    return CheckResult(
        check_id="dns_entropy",
        label="DNS Tunnel / High Entropy Query",
        triggered=triggered,
        severity=severity,
        detail=detail,
        evidence_rows=evidence[:10],
    )


def bgp_hijack_check(rows: List[Dict]) -> CheckResult:
    """Detect BGP prefix hijacks: announced origin ASN ≠ expected origin ASN (OPT-2).

    NET-015 pattern: AS60068 announces 10.10.0.0/16 (RFC1918) — hijack indicator.
    Legitimate route: origin ASN matches expected ASN and prefix is globally routable.

    Triggers on: bgp_hijack_indicator=True OR bgp_origin_asn != bgp_expected_origin_asn.
    """
    flagged: List[str] = []
    evidence: List[int] = []

    for r in rows:
        # Explicit indicator field
        hijack_flag = str(r.get("bgp_hijack_indicator", "")).lower()
        origin = str(r.get("bgp_origin_asn", "") or "")
        expected = str(r.get("bgp_expected_origin_asn", "") or "")
        prefix = str(r.get("bgp_prefix_announced", "") or "")

        is_hijack = (
            hijack_flag in ("true", "1", "yes")
            or (origin and expected and origin != expected and expected not in ("", "N/A", "unknown"))
        )

        if is_hijack:
            eid = r.get("event_id") or f"row-{r.get('row_index','?')}"
            flagged.append(
                f"{eid}: prefix {prefix} announced by {origin} "
                f"(expected {expected or 'N/A'})"
            )
            ri = r.get("row_index")
            if ri is not None:
                evidence.append(ri)

    triggered = len(flagged) > 0
    detail = (f"BGP hijack detected on {len(flagged)} prefix(es): "
              + "; ".join(flagged[:3])) if triggered else ""

    return CheckResult(
        check_id="bgp_hijack",
        label="BGP Prefix Hijack",
        triggered=triggered,
        severity="critical" if triggered else "info",
        detail=detail,
        evidence_rows=evidence[:10],
    )


# ── Run all checks ────────────────────────────────────────────────────────────

def run_all_checks(rows: List[Dict]) -> List[CheckResult]:
    """Run all OPT-2 deterministic checks and return results.

    Phase A checks (hot-path, no LLM):
      brute_force_rate  — script_kiddie vs APT rate discrimination
      beacon_ewma       — C2 beacon + supply chain algorithmic beacon
      dns_entropy       — DNS tunnel / exfil candidate
      bgp_hijack        — BGP prefix origin mismatch

    Original checks:
      impossible_travel, after_hours, same_ip_cross_account, temp_privilege
    """
    return [
        # Original OPT-2
        impossible_travel_check(rows),
        after_hours_check(rows),
        same_ip_cross_account_check(rows),
        temp_privilege_check(rows),
        # Phase A — network-layer hot-path checks
        brute_force_rate_check(rows),
        beacon_ewma_check(rows),
        dns_entropy_check(rows),
        bgp_hijack_check(rows),
    ]
