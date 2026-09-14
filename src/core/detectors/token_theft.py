from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Set

from src.core.detectors.api_security import _token_usage_anomaly  # leverage shared baseline


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", ""))
        except Exception:
            pass
    return datetime.utcnow()


@dataclass
class TokenTelemetryResult:
    factors: list[str] = field(default_factory=list)
    alerts: list[Dict[str, Any]] = field(default_factory=list)
    hopgraph_observations: list[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_alert(self, factor: str, severity: str, note: str, context: Dict[str, Any]) -> None:
        if factor not in self.factors:
            self.factors.append(factor)
        self.alerts.append(
            {
                "factor": factor,
                "severity": severity,
                "note": note,
                "context": context,
            }
        )


class TokenTelemetryAnalyzer:
    """Streaming token telemetry analyzer used by the identity stage."""

    def __init__(self, ttl_seconds: int = 86400, hijack_window: int = 600):
        self._records: Dict[str, Dict[str, Any]] = {}
        self._ttl = ttl_seconds
        self._hijack_window = hijack_window

    def analyze(self, event: Dict[str, Any]) -> TokenTelemetryResult:
        token_id = str(event.get("token_id") or event.get("token") or "").strip()
        if not token_id:
            return TokenTelemetryResult()

        now = _parse_ts(event.get("timestamp") or event.get("event_ts") or datetime.utcnow())
        self._purge_old(now)

        entry = self._records.setdefault(
            token_id,
            {
                "ips": set(),
                "devices": set(),
                "user_agents": set(),
                "geos": set(),
                "last_seen": now,
                "user": event.get("user") or event.get("principal"),
                "revoked_at": None,
            },
        )
        result = TokenTelemetryResult(metadata={"token_id": token_id})
        ip = event.get("ip") or event.get("source_ip")
        geo = event.get("geo") or event.get("location")
        device = event.get("device") or event.get("device_id")
        user_agent = event.get("user_agent")

        # Usage after revocation
        if entry.get("revoked_at"):
            revoked_at: datetime = entry["revoked_at"]
            if now > revoked_at + timedelta(seconds=30):
                result.add_alert(
                    "iam:token_usage_after_revocation",
                    "high",
                    "Token observed after revocation",
                    {"token_id": token_id, "last_revoked": revoked_at.isoformat(), "ip": ip},
                )

        if event.get("revoked") or event.get("revocation_event"):
            entry["revoked_at"] = now

        # Usage anomaly leveraging API stage baseline
        usage_count = event.get("token_usage") or event.get("call_count")
        try:
            usage_value = int(usage_count)
        except Exception:
            usage_value = None
        if usage_value is not None and _token_usage_anomaly(f"token:{token_id}", usage_value):
            result.add_alert(
                "iam:token_usage_anomaly",
                "medium",
                "Token usage deviated from baseline",
                {"token_id": token_id, "usage": usage_value},
            )

        # Session hijack detection: new IP or user-agent within hijack window
        geo_label = self._geo_label(event.get("geo") or event.get("location"))
        oauth_context = bool(event.get("oauth_client_id") or event.get("oauth_scope") or event.get("oauth_app"))
        ip_anomaly = False
        if ip:
            ips: Set[str] = entry["ips"]
            if ips and ip not in ips and (now - entry["last_seen"]).total_seconds() <= self._hijack_window:
                result.add_alert(
                    "iam:session_hijack",
                    "high",
                    "Token reused from new IP/device shortly after previous activity",
                    {"token_id": token_id, "ip": ip, "previous_ips": list(ips)},
                )
                ip_anomaly = True
            ips.add(str(ip))
        if user_agent:
            uas: Set[str] = entry["user_agents"]
            if uas and user_agent not in uas and (now - entry["last_seen"]).total_seconds() <= self._hijack_window:
                result.add_alert(
                    "iam:session_hijack",
                    "medium",
                    "User agent changed for active token",
                    {"token_id": token_id, "user_agent": user_agent, "previous_agents": list(uas)},
                )
            uas.add(user_agent)
        if device:
            devices: Set[str] = entry["devices"]
            devices.add(str(device))

        if geo_label:
            geos: Set[str] = entry["geos"]
            if geos and geo_label not in geos and (now - entry["last_seen"]).total_seconds() <= self._hijack_window:
                result.add_alert(
                    "iam:token_geo_anomaly",
                    "medium",
                    "Token observed from new geo location",
                    {"token_id": token_id, "geo": geo_label, "previous_geos": list(geos)},
                )
            geos.add(geo_label)

        if oauth_context and ip_anomaly:
            result.add_alert(
                "iam:oauth_token_theft",
                "high",
                "OAuth token reused from new network path",
                {
                    "token_id": token_id,
                    "ip": ip,
                    "oauth_client_id": event.get("oauth_client_id"),
                    "oauth_scope": event.get("oauth_scope"),
                },
            )

        if result.factors:
            host = event.get("service_host") or event.get("resource") or ip
            if host and entry.get("user"):
                result.hopgraph_observations.append(
                    {
                        "user": entry["user"],
                        "host": host,
                        "edge_type": "token",
                        "token_id": token_id,
                        "context_identity": True,
                    }
                )

        entry["last_seen"] = now
        return result

    def _purge_old(self, now: datetime) -> None:
        expired = [token for token, rec in self._records.items() if (now - rec.get("last_seen", now)).total_seconds() > self._ttl]
        for token in expired:
            self._records.pop(token, None)

    @staticmethod
    def _geo_label(value: Any) -> Optional[str]:
        if isinstance(value, dict):
            for key in ("country", "city", "region"):
                if value.get(key):
                    return str(value[key])
            if value.get("code"):
                return str(value["code"])
        elif isinstance(value, str):
            return value
        return None


__all__ = ["TokenTelemetryAnalyzer", "TokenTelemetryResult"]
