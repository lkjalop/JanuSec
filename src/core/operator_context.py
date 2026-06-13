"""Operator-provided sanctioned context — the channel a real SOC has but the platform lacks.

The platform deliberately rejects the evaluation "enrichment workbook" as an answer key,
which is correct for *testing* — but a real deployment legitimately knows things the raw
telemetry doesn't: which accounts/IPs belong to an authorized penetration test, which assets
are crown jewels, and which upload destinations are sanctioned. Without this, the platform
flags the authorized pentest as a breach (false positive) and can't distinguish a lookalike
exfil destination from the legitimate corporate one.

This module loads an OPERATOR-curated context (never the answer key) from a JSON file at
JANUSEC_OPERATOR_CONTEXT, and exposes deterministic predicates the pipeline uses to
SUPPRESS authorized activity and ELEVATE crown-jewel touches.

Context file shape (all keys optional):
{
  "authorized_pentest": {
    "accounts": ["pentest-readonly-feb2026"],
    "ips": ["203.0.113.7"], "cidrs": ["203.0.113.0/24"],
    "window_start": "2026-02-01T00:00:00Z", "window_end": "2026-02-28T23:59:59Z"
  },
  "crown_jewels": {"hosts": ["SVR-DB-01"], "accounts": ["svc_sql"], "data_stores": ["finance_wh"]},
  "sanctioned_destinations": ["acmevesper.sharepoint.com"]
}
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


def _parse_ts(v: Any) -> Optional[float]:
    if v in (None, ""):
        return None
    try:
        s = str(v).replace("Z", "+00:00")
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return None


class OperatorContext:
    """Immutable view over the operator-provided context. Empty context == no-op."""

    def __init__(self, data: dict | None = None) -> None:
        data = data or {}
        pt = data.get("authorized_pentest") or {}
        self.pentest_accounts = {str(a).strip().lower() for a in (pt.get("accounts") or []) if a}
        self.pentest_ips = {str(i).strip() for i in (pt.get("ips") or []) if i}
        self._pentest_nets = []
        for c in (pt.get("cidrs") or []):
            try:
                self._pentest_nets.append(ipaddress.ip_network(str(c), strict=False))
            except Exception:
                pass
        self.pentest_window = (_parse_ts(pt.get("window_start")), _parse_ts(pt.get("window_end")))

        cj = data.get("crown_jewels") or {}
        self.cj_hosts = {str(h).strip().lower() for h in (cj.get("hosts") or []) if h}
        self.cj_accounts = {str(a).strip().lower() for a in (cj.get("accounts") or []) if a}
        self.cj_stores = {str(s).strip().lower() for s in (cj.get("data_stores") or []) if s}

        self.sanctioned_destinations = {
            str(d).strip().lower() for d in (data.get("sanctioned_destinations") or []) if d
        }
        self._empty = not any([
            self.pentest_accounts, self.pentest_ips, self._pentest_nets,
            self.cj_hosts, self.cj_accounts, self.cj_stores, self.sanctioned_destinations,
        ])

    @property
    def is_empty(self) -> bool:
        return self._empty

    # ── Authorized-pentest suppression ──────────────────────────────────────────
    def _in_window(self, ts: Optional[float]) -> bool:
        start, end = self.pentest_window
        if start is None and end is None:
            return True  # no window constraint
        if ts is None:
            return True  # can't time-bound → don't exclude on time alone
        if start is not None and ts < start:
            return False
        if end is not None and ts > end:
            return False
        return True

    def is_authorized_pentest(self, *, user: str = "", ip: str = "",
                              ts: Optional[float] = None) -> bool:
        """True if this actor/source is a sanctioned pentest within its window."""
        u = (user or "").strip().lower()
        matched = False
        if u and u in self.pentest_accounts:
            matched = True
        ipx = (ip or "").strip()
        if not matched and ipx:
            if ipx in self.pentest_ips:
                matched = True
            elif self._pentest_nets:
                try:
                    addr = ipaddress.ip_address(ipx)
                    matched = any(addr in n for n in self._pentest_nets)
                except Exception:
                    matched = False
        return matched and self._in_window(ts)

    def cluster_is_authorized_pentest(self, cluster: dict) -> bool:
        """Does an entire cluster's actor/IP set fall under the authorized pentest?"""
        users = [str(u) for u in (cluster.get("shared_users")
                 or cluster.get("shared_accounts") or [])]
        ips = [str(i) for i in (cluster.get("shared_ips") or [])]
        ts = None
        for key in ("max_ts", "_max_ts_epoch", "last_seen_ts"):
            if cluster.get(key):
                ts = _parse_ts(cluster.get(key)) or (float(cluster[key]) if str(cluster[key]).replace('.', '').isdigit() else None)
                break
        if not users and not ips:
            return False
        # Authorized if EITHER every named user is a sanctioned pentest account, OR
        # (when the operator constrained by IP) every named IP is in the pentest range.
        # A pentest legitimately runs from varied IPs, so an account match alone suffices;
        # but a cluster mixing a pentest account with a NON-pentest actor is NOT suppressed
        # (user_ok requires ALL users to be authorized), so a real breach can't hide behind it.
        user_ok = bool(users) and all(self.is_authorized_pentest(user=u, ts=ts) for u in users)
        has_ip_scope = bool(self.pentest_ips or self._pentest_nets)
        ip_ok = bool(ips) and has_ip_scope and all(self.is_authorized_pentest(ip=i, ts=ts) for i in ips)
        return user_ok or ip_ok

    # ── Crown-jewel elevation ───────────────────────────────────────────────────
    def touches_crown_jewel(self, cluster: dict) -> list[str]:
        """Return the crown-jewel assets this cluster touches (for severity elevation)."""
        hit: list[str] = []
        for h in (cluster.get("shared_hosts") or []):
            if str(h).strip().lower() in self.cj_hosts:
                hit.append(str(h))
        for u in (cluster.get("shared_users") or cluster.get("shared_accounts") or []):
            if str(u).strip().lower() in self.cj_accounts:
                hit.append(str(u))
        return hit

    def is_sanctioned_destination(self, dest: str) -> bool:
        d = (dest or "").strip().lower()
        return bool(d) and d in self.sanctioned_destinations


_CACHE: Optional[OperatorContext] = None


def load_operator_context(path: str | None = None) -> OperatorContext:
    """Load (and cache) the operator context from JANUSEC_OPERATOR_CONTEXT or *path*.
    Returns an empty (no-op) context when unset or unreadable — never raises."""
    global _CACHE
    if path is None and _CACHE is not None:
        return _CACHE
    p = path or os.getenv("JANUSEC_OPERATOR_CONTEXT", "").strip()
    ctx = OperatorContext({})
    if p and os.path.exists(p):
        try:
            with open(p, "r", encoding="utf-8") as fh:
                ctx = OperatorContext(json.load(fh))
            logger.info("operator context loaded from %s (empty=%s)", p, ctx.is_empty)
        except Exception as exc:
            logger.warning("operator context load failed (%s): %s", p, exc)
    if path is None:
        _CACHE = ctx
    return ctx
