from typing import Dict, List, Any
from datetime import datetime, timedelta
import asyncio
import logging
import os
from src.core.scoring.dread_engine import compute_dread, severity_from_dread
from src.monitoring.log_pull_contracts import get_contract

logger = logging.getLogger(__name__)


class ForensicLogGapDetector:
    """
    Detect and alert on missing forensic log sources critical for port scan investigation.

    Periodically queries the event store for last-seen timestamps for expected sources
    and emits alerts via an alert manager. Designed to be integrated as a background
    task in the pipeline or service process.
    """

    TIER_1_ESSENTIAL_SOURCES = {
        "firewall_logs": {
            "max_gap_seconds": 3600,
            "severity": "critical",
            "required_fields": ["timestamp", "source_ip", "dest_ip", "dest_port", "action"],
            "gap_impact": "Cannot detect external reconnaissance or port scanning",
            "ask_for": "Firewall connection logs with 5-tuple and action (allow/deny)"
        },
        "endpoint_edr_heartbeat": {
            "max_gap_seconds": 900,
            "severity": "critical",
            "required_fields": ["timestamp", "device_id", "agent_version", "status"],
            "gap_impact": "Cannot verify endpoint coverage or containment readiness",
            "ask_for": "EDR heartbeat/health telemetry by device_id (last 15m)"
        },
        "email_delivery_logs": {
            "max_gap_seconds": 3600,
            "severity": "high",
            "required_fields": ["timestamp", "message_id", "sender", "recipient", "disposition"],
            "gap_impact": "Miss phishing delivery signals tied to initial access",
            "ask_for": "Email delivery logs (sender, recipient, disposition) last 24h"
        },
        "email_click_logs": {
            "max_gap_seconds": 7200,
            "severity": "high",
            "required_fields": ["timestamp", "user", "url", "device_id"],
            "gap_impact": "Miss payload access and click-through telemetry",
            "ask_for": "Email URL-click logs for implicated users (last 24h)"
        },
        "dns_query_logs": {
            "max_gap_seconds": 3600,
            "severity": "critical",
            "required_fields": ["timestamp", "client_ip", "query_name", "response_code"],
            "gap_impact": "Miss pre-scan DNS enumeration",
            "ask_for": "DNS resolver query logs with client IP and queried domain"
        },
        "netflow_ipfix": {
            "max_gap_seconds": 1800,
            "severity": "high",
            "required_fields": ["timestamp", "source_ip", "dest_ip", "dest_port", "packets", "bytes"],
            "gap_impact": "Cannot detect slow-and-low scans or distributed attacks",
            "ask_for": "NetFlow/IPFIX from core routers with flow metadata"
        }
    }

    TIER_2_ENHANCED_SOURCES = {
        "identity_auth_logs": {
            "max_gap_seconds": 3600,
            "severity": "high",
            "gap_impact": "Cannot correlate endpoint/network to account takeover",
            "ask_for": "IdP risky sign-ins, device_id, MFA prompts (last 24h)"
        },
        "ids_ips_alerts": {
            "max_gap_seconds": 7200,
            "severity": "medium",
            "gap_impact": "Miss scan pattern classification and tool fingerprints"
        },
        "web_server_access_logs": {
            "max_gap_seconds": 3600,
            "severity": "medium",
            "gap_impact": "Miss web reconnaissance and path enumeration (404 spikes)"
        },
        "authentication_logs": {
            "max_gap_seconds": 3600,
            "severity": "high",
            "gap_impact": "Cannot correlate scan → credential spray chains"
        }
    }

    SOURCE_TO_EVENT_TYPE = {
        "firewall_logs": "firewall_connection",
        "dns_query_logs": "dns_query",
        "netflow_ipfix": "netflow",
        "ids_ips_alerts": "ids_alert",
        "web_server_access_logs": "web_access",
        "authentication_logs": "auth_event",
        "endpoint_edr_heartbeat": "edr_heartbeat",
        "email_delivery_logs": "email_delivery",
        "email_click_logs": "email_click",
        "identity_auth_logs": "identity_auth"
    }

    def __init__(self, db, alert_manager, check_interval_seconds: int = 900):
        self.db = db
        self.alert_manager = alert_manager
        self.check_interval_seconds = check_interval_seconds
        self._running = False

    async def check_all_tenants(self) -> None:
        tenants = await self._get_active_tenants()
        for tenant_id in tenants:
            gaps = await self.detect_log_gaps(tenant_id)
            if gaps:
                await self._handle_log_gaps(tenant_id, gaps)

    async def detect_log_gaps(self, tenant_id: str) -> List[Dict[str, Any]]:
        gaps: List[Dict[str, Any]] = []
        now = datetime.utcnow()

        # Tier 1
        for source_name, config in self.TIER_1_ESSENTIAL_SOURCES.items():
            last_seen = await self._get_last_log_time(tenant_id, source_name)

            if last_seen is None:
                gap = {
                    "source": source_name,
                    "severity": config["severity"],
                    "status": "never_seen",
                    "impact": config["gap_impact"],
                    "ask_for": config.get("ask_for", ""),
                    "tier": 1
                }
                self._attach_contract(gap, source_name)
                gaps.append(gap)
            else:
                time_since = (now - last_seen).total_seconds()
                if time_since > config["max_gap_seconds"]:
                    gap = {
                        "source": source_name,
                        "severity": config["severity"],
                        "status": "missing",
                        "time_since_seconds": time_since,
                        "time_since_human": self._format_duration(time_since),
                        "last_seen": last_seen.isoformat(),
                        "impact": config["gap_impact"],
                        "ask_for": config.get("ask_for", ""),
                        "tier": 1
                    }
                    self._attach_contract(gap, source_name)
                    gaps.append(gap)

        # Tier 2
        for source_name, config in self.TIER_2_ENHANCED_SOURCES.items():
            last_seen = await self._get_last_log_time(tenant_id, source_name)
            if last_seen:
                time_since = (now - last_seen).total_seconds()
                if time_since > config["max_gap_seconds"]:
                    gap = {
                        "source": source_name,
                        "severity": config["severity"],
                        "status": "missing",
                        "time_since_seconds": time_since,
                        "time_since_human": self._format_duration(time_since),
                        "last_seen": last_seen.isoformat(),
                        "impact": config["gap_impact"],
                        "tier": 2
                    }
                    self._attach_contract(gap, source_name)
                    gaps.append(gap)

        return gaps

    async def detect_log_gaps_for_incident(self, tenant_id: str, incident: Dict[str, Any]) -> Dict[str, Any]:
        """
        Case-scoped gap analysis and ask planning.
        - Gates on incident confidence; if confidence >= threshold, returns empty asks.
        - Restricts queries to entities and time window relevant to the case.
        Returns a structure with 'asks' in progressive order and scoped 'gaps'.
        """
        confidence = float(incident.get("confidence", 0.0) or 0.0)
        threshold = float(os.getenv("INCIDENT_CONFIDENCE_THRESHOLD", "0.7"))
        if confidence >= threshold:
            return {"asks": [], "gaps": []}

        t0 = incident.get("t0")  # ISO string or epoch seconds
        window_min = int(incident.get("time_window_minutes", 60))
        try:
            if isinstance(t0, (int, float)):
                center = datetime.utcfromtimestamp(t0)
            elif isinstance(t0, str):
                center = datetime.fromisoformat(t0)
            else:
                center = datetime.utcnow()
        except Exception:
            center = datetime.utcnow()
        start = center - timedelta(minutes=window_min)
        end = center + timedelta(minutes=window_min)

        entities = incident.get("entities", {}) or {}
        users = entities.get("users", []) or []
        hosts = entities.get("hosts", []) or []
        domains = entities.get("domains", []) or []

        # Build scoped gaps by checking last-seen and volume collapse for just-needed sources
        candidate_sources = [
            "identity_auth_logs",  # Step 1
            "endpoint_edr_heartbeat",  # Step 2 support
            "email_delivery_logs",  # context for phishing
            "email_click_logs",
            "dns_query_logs",  # Step 3 if domain evidence exists
        ]

        scoped_gaps: List[Dict[str, Any]] = []
        for s in candidate_sources:
            last_seen = await self._get_last_log_time(tenant_id, s)
            status = "ok" if last_seen else "never_seen"
            if last_seen:
                # Consider volume collapse if current hour traffic drops vs baseline
                collapse = await self._detect_volume_collapse(tenant_id, s)
                if collapse and collapse.get("collapsed"):
                    status = "volume_collapse"
            scoped_gaps.append({
                "source": s,
                "status": status,
                "last_seen": last_seen.isoformat() if last_seen else None,
            })
            self._attach_contract(scoped_gaps[-1], s)

        asks: List[Dict[str, Any]] = []

        # Progressive asks by marginal uncertainty reduction
        if users:
            asks.append(self._build_identity_risky_signin_ask(users, start, end))

        if hosts:
            asks.append(self._build_edr_process_tree_ask(hosts, center, window_min))

        if domains or entities.get("suspect_domains"):
            doms = domains or entities.get("suspect_domains") or []
            asks.append(self._build_dns_lookup_ask(hosts, doms, start, end))

        # Filter out Nones and attach a quick cost/impact estimate
        asks = [a for a in asks if a]

        return {
            "asks": asks,
            "gaps": scoped_gaps,
            "time_window": {"start": start.isoformat(), "end": end.isoformat()},
            "entities": {"users": users, "hosts": hosts, "domains": domains},
        }

    async def _get_last_log_time(self, tenant_id: str, source_type: str) -> datetime | None:
        event_type = self.SOURCE_TO_EVENT_TYPE.get(source_type)
        if not event_type:
            return None

        # If no DB configured, we cannot query last-seen times
        if not self.db:
            return None

        # Expecting an async DB connection with fetchrow support
        async with self.db.get_connection() as conn:
            row = await conn.fetchrow(
                """
                SELECT MAX(timestamp) as last_seen
                FROM events
                WHERE tenant_id = $1
                  AND event_type = $2
                  AND timestamp > NOW() - INTERVAL '7 days'
                """,
                tenant_id,
                event_type,
            )
            return row["last_seen"] if row and row["last_seen"] else None

    async def _handle_log_gaps(self, tenant_id: str, gaps: List[Dict[str, Any]]) -> None:
        critical_gaps = [g for g in gaps if g["severity"] == "critical"]
        high_gaps = [g for g in gaps if g["severity"] == "high"]
        medium_gaps = [g for g in gaps if g["severity"] == "medium"]

        if critical_gaps:
            await self._send_critical_gap_alert(tenant_id, critical_gaps)

        if high_gaps:
            await self._send_gap_summary(tenant_id, high_gaps, "high")

        # Log all detected gaps for dashboarding / historical tracking
        await self._log_gaps_for_dashboard(tenant_id, gaps)

    async def _send_critical_gap_alert(self, tenant_id: str, gaps: List[Dict[str, Any]]) -> None:
        gap_summary = "\n".join([
            f"- {g['source']}: {g.get('time_since_human', 'Never seen')} (Impact: {g['impact']})"
            for g in gaps
        ])

        alert = {
            "title": "CRITICAL: Missing Essential Log Sources for Port Scan Detection",
            # severity may be updated based on computed DREAD if applicable
            "severity": "critical",
            "tenant_id": tenant_id,
            "description": f"One or more critical log sources required for port scan detection are missing.\n\nMissing Sources:\n{gap_summary}\n\nIMMEDIATE ACTION REQUIRED:\n{self._generate_remediation_steps(gaps)}\n",
            "metadata": {"gaps": gaps, "detection_type": "log_gap", "playbook": "log_gap_remediation"},
        }

        # Compute a simple DREAD for this gap alert using evidence we have
        try:
            artifact = { 'destination_ports': [], 'destination_ips': [], 'business_tier': os.getenv('DEFAULT_TENANT','default') }
            dread = compute_dread(artifact, [])
            alert['metadata']['dread'] = dread
            # adjust severity by dread composite if thresholds indicate higher/lower
            tried_sev = severity_from_dread(dread.get('composite', 0.0))
            alert['severity'] = tried_sev
        except Exception:
            logger.debug('DREAD compute for gap alert failed', exc_info=True)

        if self.alert_manager:
            try:
                await self.alert_manager.send_alert(alert)
            except Exception:
                logger.exception('Failed to send gap alert via alert_manager')
        else:
            # Fallback: log as warning so local dev without alert manager still sees output
            logger.warning('ALERT (no alert_manager): %s', alert.get('description', 'missing description'))

        if await self._soar_enabled():
            await self._create_gap_remediation_ticket(tenant_id, gaps)

    async def _send_gap_summary(self, tenant_id: str, gaps: List[Dict[str, Any]], level: str) -> None:
        # Summary-style alert (lower urgency)
        gap_summary = "\n".join([
            f"- {g['source']}: missing for {g.get('time_since_human', 'unknown')} (Impact: {g['impact']})" for g in gaps
        ])

        alert = {
            "title": f"Missing Log Sources ({level.upper()})",
            "severity": level,
            "tenant_id": tenant_id,
            "description": f"The following log sources show gaps:\n{gap_summary}",
            "metadata": {"gaps": gaps, "detection_type": "log_gap"},
        }

        if self.alert_manager:
            try:
                await self.alert_manager.send_alert(alert)
            except Exception:
                logger.exception('Failed to send gap summary via alert_manager')
        else:
            logger.info('GAP SUMMARY (no alert_manager): %s', alert.get('description', ''))

    async def _log_gaps_for_dashboard(self, tenant_id: str, gaps: List[Dict[str, Any]]) -> None:
        if not self.db:
            logger.debug('DB not configured; skipping persistence of log gap events')
            return

        try:
            async with self.db.get_connection() as conn:
                for gap in gaps:
                    await conn.execute(
                        """
                        INSERT INTO log_gap_events (
                            tenant_id, source_type, severity, status,
                            time_since_seconds, impact, detected_at
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, NOW())
                        """,
                        tenant_id,
                        gap.get("source"),
                        gap.get("severity"),
                        gap.get("status"),
                        int(gap.get("time_since_seconds", 0)),
                        gap.get("impact", ""),
                    )
        except Exception:
            logger.exception('Failed to persist log gap events to DB')

    async def _detect_volume_collapse(self, tenant_id: str, source_type: str) -> Dict[str, Any] | None:
        """
        Compare current 60m event count vs 7-day per-hour baseline.
        Returns dict with collapsed: bool and simple ratios. Gracefully no-ops without DB.
        """
        if not self.db:
            return None
        event_type = self.SOURCE_TO_EVENT_TYPE.get(source_type)
        if not event_type:
            return None

        try:
            async with self.db.get_connection() as conn:
                # Current hour
                row_now = await conn.fetchrow(
                    """
                    SELECT COUNT(*) AS c
                    FROM events
                    WHERE tenant_id = $1 AND event_type = $2 AND timestamp > NOW() - INTERVAL '60 minutes'
                    """,
                    tenant_id,
                    event_type,
                )
                c_now = int(row_now["c"]) if row_now and "c" in row_now else 0

                # Baseline: average per hour over last 7 days, excluding zero-only hours by using moving window count
                row_base = await conn.fetchrow(
                    """
                    SELECT COALESCE(AVG(hour_count), 0) AS avg_per_hour
                    FROM (
                        SELECT DATE_TRUNC('hour', timestamp) AS h, COUNT(*) AS hour_count
                        FROM events
                        WHERE tenant_id = $1 AND event_type = $2 AND timestamp > NOW() - INTERVAL '7 days'
                        GROUP BY h
                    ) t
                    """,
                    tenant_id,
                    event_type,
                )
                avg_per_hour = float(row_base["avg_per_hour"]) if row_base and "avg_per_hour" in row_base else 0.0

                collapsed = avg_per_hour > 0 and c_now < max(1.0, 0.2 * avg_per_hour)
                return {"collapsed": collapsed, "current_hour": c_now, "avg_per_hour": avg_per_hour}
        except Exception:
            logger.debug("volume collapse check failed", exc_info=True)
            return None

    def _generate_remediation_steps(self, gaps: List[Dict[str, Any]]) -> str:
        steps = []
        for i, gap in enumerate(gaps, 1):
            ask_for = gap.get("ask_for", "Contact security operations for assistance")
            steps.append(f"{i}. {gap['source']}: {ask_for}")
        return "\n".join(steps)

    def _build_identity_risky_signin_ask(self, users: List[str], start: datetime, end: datetime) -> Dict[str, Any]:
        ask = {
            "source": "identity_auth_logs",
            "why": "Link endpoint/network activity to potential account takeover",
            "expected_impact": "Raises confidence by corroborating risky signin patterns",
            "cost_estimate": "low",
            "time_estimate": "seconds-1m",
            "api": {
                "method": "POST",
                "endpoint": "/api/v1/identity/pull",
                "payload": {
                    "users": users,
                    "start": start.isoformat(),
                    "end": end.isoformat(),
                    "fields": ["user", "device_id", "risk", "mfa", "geo", "ip"],
                    "ttl_seconds": 1800
                }
            }
        }
        self._attach_contract(ask, "identity_auth_logs")
        return ask

    def _build_edr_process_tree_ask(self, hosts: List[str], center: datetime, window_min: int) -> Dict[str, Any]:
        ask = {
            "source": "endpoint_edr_heartbeat",
            "why": "Confirm execution chain and child processes around suspected time",
            "expected_impact": "Upgrades weak/medium signal to strong when malicious process tree found",
            "cost_estimate": "low",
            "time_estimate": "seconds-2m",
            "api": {
                "method": "POST",
                "endpoint": "/api/v1/edr/process_tree/pull",
                "payload": {
                    "hosts": hosts,
                    "center": center.isoformat(),
                    "window_minutes": window_min,
                    "include_hashes": True,
                    "ttl_seconds": 1800
                }
            }
        }
        self._attach_contract(ask, "endpoint_edr_heartbeat")
        return ask

    def _build_dns_lookup_ask(self, hosts: List[str], domains: List[str], start: datetime, end: datetime) -> Dict[str, Any]:
        ask = {
            "source": "dns_query_logs",
            "why": "Corroborate suspected C2/resolution behavior for implicated hosts/domains",
            "expected_impact": "Improves path coverage; may elevate mapping_semantics/diversity scoring",
            "cost_estimate": "low",
            "time_estimate": "seconds-1m",
            "api": {
                "method": "POST",
                "endpoint": "/api/v1/dns/lookup/pull",
                "payload": {
                    "hosts": hosts,
                    "domains": domains,
                    "start": start.isoformat(),
                    "end": end.isoformat(),
                    "ttl_seconds": 1800
                }
            }
        }
        self._attach_contract(ask, "dns_query_logs")
        return ask

    def _attach_contract(self, record: Dict[str, Any], source: str) -> None:
        contract = get_contract(source)
        if not contract:
            return
        record["contract_id"] = contract.get("id") or source
        record["contract"] = contract
        record["custody_required"] = bool(contract.get("custody_required"))
        record["required_fields"] = contract.get("required_fields") or []
        record["retention_days"] = contract.get("retention_days")
        record["ttl_seconds"] = contract.get("ttl_seconds")
        record["acquisition"] = contract.get("acquisition")
        record["chain_of_custody"] = contract.get("chain_of_custody")
        try:
            api = record.get("api") or {}
            payload = api.get("payload") or {}
            if isinstance(payload, dict) and contract.get("ttl_seconds"):
                payload["ttl_seconds"] = int(contract["ttl_seconds"])
                api["payload"] = payload
                record["api"] = api
        except Exception:
            return

    def _format_duration(self, seconds: float) -> str:
        if seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds / 60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds / 3600)} hours"
        else:
            return f"{int(seconds / 86400)} days"

    async def _get_active_tenants(self) -> List[str]:
        # If no DB available, run as single default tenant to allow developer testing
        if not self.db:
            default_tenant = os.getenv('DEFAULT_TENANT', 'default')
            return [default_tenant]

        try:
            async with self.db.get_connection() as conn:
                rows = await conn.fetch("SELECT DISTINCT tenant_id FROM events WHERE timestamp > NOW() - INTERVAL '1 day'")
                return [row["tenant_id"] for row in rows]
        except Exception:
            logger.exception('Failed to query active tenants; defaulting to single tenant')
            return [os.getenv('DEFAULT_TENANT', 'default')]

    async def _soar_enabled(self) -> bool:
        # Placeholder to check SOAR connector availability
        # If a connector exists, this should check config or health check
        return False

    async def _create_gap_remediation_ticket(self, tenant_id: str, gaps: List[Dict[str, Any]]) -> None:
        # Implement when SOAR integration is available
        pass


async def run_log_gap_monitor(db, alert_manager, interval_seconds: int = 900):
    """Background task that runs the log gap detector periodically."""
    detector = ForensicLogGapDetector(db=db, alert_manager=alert_manager, check_interval_seconds=interval_seconds)
    detector._running = True
    while detector._running:
        try:
            logger.info("Running log gap detection check...")
            await detector.check_all_tenants()
            logger.info("Log gap check complete")
        except Exception as e:
            logger.exception("Log gap detection failed: %s", e)

        await asyncio.sleep(detector.check_interval_seconds)
