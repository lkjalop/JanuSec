"""HopGraph integration helpers with deterministic fallback generation."""
from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:  # pragma: no cover - optional in some build targets
    from src.core.graph.hopgraph_lite import HopGraphLite, get_graph as _get_shared_graph  # type: ignore
except Exception:  # pragma: no cover
    try:
        from src.graph.hopgraph_lite import HopGraphLite, get_graph as _get_shared_graph  # type: ignore
    except Exception:
        HopGraphLite = None  # type: ignore
        _get_shared_graph = None  # type: ignore

logger = logging.getLogger(__name__)


def _env_mode() -> str:
    raw = (os.getenv('ENV') or os.getenv('APP_ENV') or 'dev').strip().lower()
    if raw in {'prod', 'production'}:
        return 'prod'
    if raw in {'stage', 'staging'}:
        return 'staging'
    return 'dev'


def _allow_synthetic_fallback() -> bool:
    if _env_mode() not in {'staging', 'prod'}:
        return True
    return os.getenv('ALLOW_SYNTHETIC_HOPGRAPH_FALLBACK', '0').lower() in {'1', 'true', 'yes'}


def _obtain_graph():
    """Best-effort accessor for the shared HopGraphLite singleton."""
    getter = globals().get("_get_shared_graph")
    if getter is None:
        return None
    try:
        return getter()
    except Exception:
        return None


def _ts_to_iso(value: Any) -> str:
    try:
        if value is None:
            raise ValueError
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
    except Exception:
        return datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()


def _phase_to_severity(phase: str) -> str:
    if not phase:
        return "info"
    phase = phase.lower()
    if phase in {"initial_access", "execution"}:
        return "high"
    if phase in {"lateral", "c2_connection", "exfiltration"}:
        return "critical"
    return "info"


def _format_hopgraph_response(
    payload: Dict[str, Any],
    seed_row: Dict[str, Any],
    max_hops: int,
    org: Optional[str],
    time_window_hours: Optional[int],
) -> Dict[str, Any]:
    seeds = {f"{s.get('type')}:{s.get('id')}" for s in payload.get("seeds", []) if s}
    nodes: List[Dict[str, Any]] = []
    for node in payload.get("nodes", []):
        node_id = f"{node.get('type','artifact')}:{node.get('id')}"
        nodes.append(
            {
                "id": node_id,
                "type": node.get("type") or "artifact",
                "label": f"{node.get('type','artifact').title()} {node.get('id')}".strip(),
                "host": seed_row.get("host"),
                "user": seed_row.get("user"),
                "properties": {
                    "raw_type": node.get("type"),
                    "raw_id": node.get("id"),
                },
                "risk_score": 0,
                "is_pivot": node_id in seeds,
            }
        )
    sorted_edges = sorted(payload.get("edges") or [], key=lambda e: e.get("ts") or 0)
    edges: List[Dict[str, Any]] = []
    for edge in sorted_edges:
        source = f"{edge.get('src_type','artifact')}:{edge.get('src_id')}"
        target = f"{edge.get('dst_type','artifact')}:{edge.get('dst_id')}"
        phase = edge.get("phase") or "related"
        edges.append(
            {
                "source": source,
                "target": target,
                "type": phase,
                "label": phase.replace("_", " ").title(),
                "timestamp": _ts_to_iso(edge.get("ts")),
            }
        )
    # Build a simple linear path from sorted edges for UI display
    path_nodes: List[str] = []
    for edge in edges:
        if edge["source"] not in path_nodes:
            path_nodes.append(edge["source"])
        if edge["target"] not in path_nodes:
            path_nodes.append(edge["target"])
    paths = []
    if path_nodes:
        stages = sorted({edge["type"] for edge in edges if edge.get("type")})
        paths.append(
            {
                "path_id": "path_1",
                "nodes": path_nodes,
                "description": "HopGraphLite reconstruction based on recent telemetry.",
                "mitre_stages": stages,
                "risk_score": 7.5 if any(s in {"lateral", "c2_connection"} for s in stages) else 5.0,
            }
        )
    timeline: List[Dict[str, Any]] = []
    for edge in edges:
        timeline.append(
            {
                "timestamp": edge.get("timestamp") or _ts_to_iso(None),
                "event": f"{edge['source']} -> {edge['target']} ({edge.get('type','related')})",
                "severity": _phase_to_severity(edge.get("type")),
            }
        )
    explanation = [
        f"HopGraphLite traversal depth {max_hops}",
        f"Entities: {len(nodes)}",
        f"Relationships: {len(edges)}",
    ]
    if seeds:
        explanation.append(f"Pivot artifacts: {', '.join(sorted(seeds))}")
    unique_phases = {edge.get("type") for edge in edges if edge.get("type")}
    if unique_phases:
        explanation.append(f"Phases observed: {', '.join(sorted(unique_phases))}")
    metadata = {
        "query_type": "hopgraph-lite",
        "max_hops": max_hops,
        "generated_at": datetime.utcnow().isoformat(),
        "org": org,
        "time_window_hours": time_window_hours,
    }
    return {
        "nodes": nodes,
        "edges": edges,
        "paths": paths,
        "timeline": timeline,
        "correlation_explanation": "\n".join(explanation),
        "metadata": metadata,
    }


def _generate_fallback_graph(row: Dict[str, Any], max_hops: int) -> Dict[str, Any]:
    proc = row.get("process_name") or row.get("process") or "unknown.exe"
    host = row.get("host") or "UNKNOWN-HOST"
    sha256 = row.get("sha256") or "unknown"
    node_id_1 = hashlib.md5(f"{proc}{host}".encode("utf-8")).hexdigest()[:8]
    node_id_2 = hashlib.md5(f"{proc}{host}parent".encode("utf-8")).hexdigest()[:8]
    node_id_3 = hashlib.md5(f"{proc}{host}child".encode("utf-8")).hexdigest()[:8]
    nodes = [
        {
            "id": node_id_2,
            "type": "process",
            "label": "explorer.exe",
            "host": host,
            "user": row.get("user") or "SYSTEM",
            "timestamp": "2025-01-22T10:30:00Z",
            "properties": {
                "pid": 1024,
                "commandline": "C:\\Windows\\explorer.exe",
            },
            "risk_score": 2.0,
            "is_pivot": False,
        },
        {
            "id": node_id_1,
            "type": "process",
            "label": proc,
            "host": host,
            "user": row.get("user") or "admin",
            "timestamp": "2025-01-22T10:35:00Z",
            "properties": {
                "pid": 4096,
                "parent_pid": 1024,
                "commandline": row.get("cmdline") or f"C:\\Temp\\{proc}",
                "sha256": sha256[:16] + "...",
            },
            "risk_score": (row.get("_dread") or {}).get("score", 7.5) if isinstance(row.get("_dread"), dict) else 7.5,
            "is_pivot": True,
        },
        {
            "id": node_id_3,
            "type": "network",
            "label": "185.220.101.45:443",
            "host": host,
            "timestamp": "2025-01-22T10:36:00Z",
            "properties": {
                "dst_ip": "185.220.101.45",
                "dst_port": 443,
                "protocol": "TCP",
                "direction": "outbound",
                "bytes_sent": 4096,
            },
            "risk_score": 8.5,
            "is_pivot": False,
        },
    ]
    edges = [
        {
            "source": node_id_2,
            "target": node_id_1,
            "type": "execution",
            "label": "Process Creation",
            "timestamp": "2025-01-22T10:35:00Z",
        },
        {
            "source": node_id_1,
            "target": node_id_3,
            "type": "c2_connection",
            "label": "Network Connection",
            "timestamp": "2025-01-22T10:36:00Z",
        },
    ]
    paths = [
        {
            "path_id": "fallback_path",
            "nodes": [node_id_2, node_id_1, node_id_3],
            "description": "Initial access → execution → command and control",
            "mitre_stages": ["initial_access", "execution", "command_and_control"],
            "risk_score": 8.5,
        }
    ]
    factors = row.get("factors") or []
    factor_str = ", ".join(factors[:3]) if isinstance(factors, list) and factors else "unknown behavior"
    correlation_explanation = (
        "Synthetic attack chain:\n"
        f"1. explorer.exe spawns {proc} on {host}\n"
        f"2. Factors observed: {factor_str}\n"
        "3. Malware beacon observed to 185.220.101.45:443 (Tor exit node)\n"
        "Recommendation: Isolate the endpoint and block the destination IP."
    )
    metadata = {
        "query_type": "synthetic",
        "max_hops": max_hops,
        "generated_at": datetime.utcnow().isoformat(),
        "warning": "HopGraphLite unavailable - using deterministic fallback data",
    }
    timeline = [
        {
            "timestamp": "2025-01-22T10:30:00Z",
            "event": "explorer.exe running (parent process)",
            "severity": "info",
        },
        {
            "timestamp": "2025-01-22T10:35:00Z",
            "event": f"{proc} spawned on {host}",
            "severity": "high",
        },
        {
            "timestamp": "2025-01-22T10:36:00Z",
            "event": "Outbound connection to 185.220.101.45:443",
            "severity": "critical",
        },
    ]
    return {
        "nodes": nodes,
        "edges": edges,
        "paths": paths,
        "timeline": timeline,
        "correlation_explanation": correlation_explanation,
        "metadata": metadata,
    }


def _degraded_graph_response(row: Dict[str, Any], max_hops: int, reason: str) -> Dict[str, Any]:
    return {
        "nodes": [],
        "edges": [],
        "paths": [],
        "timeline": [],
        "correlation_explanation": "HopGraph unavailable. No synthetic attack chain was generated in live mode.",
        "metadata": {
            "query_type": "degraded",
            "max_hops": max_hops,
            "generated_at": datetime.utcnow().isoformat(),
            "warning": reason,
            "dependency_status": {
                "hopgraph": {
                    "available": False,
                    "reason": reason,
                }
            },
            "seed": {
                "host": row.get("host"),
                "user": row.get("user"),
                "process": row.get("process_name") or row.get("process"),
            },
        },
    }


def query_attack_graph(
    row: Dict[str, Any],
    max_hops: int = 3,
    time_window_hours: Optional[int] = 24,
    org: Optional[str] = None,
) -> Dict[str, Any]:
    """Attempt to reconstruct an attack chain for the supplied artifact row."""
    if not isinstance(row, dict):
        raise ValueError("row must be a dict")
    try:
        hops = max(1, min(int(max_hops or 1), 5))
    except Exception:
        hops = 3
    reason = "hopgraph_unavailable"
    if HopGraphLite is not None:
        try:
            graph = _obtain_graph()
            if graph is None:
                graph = HopGraphLite()
            ttl_seconds = None
            if time_window_hours:
                try:
                    ttl_seconds = max(int(time_window_hours) * 3600, 3600)
                except Exception:
                    ttl_seconds = None
            result = graph.reconstruct_attack(seed_alert=row, depth=hops, ttl_seconds=ttl_seconds)
            if result and result.get("nodes"):
                return _format_hopgraph_response(result, row, hops, org, time_window_hours)
            reason = "hopgraph_no_nodes"
        except Exception as exc:  # pragma: no cover - defensive logging only
            reason = str(exc)
            logger.warning("HopGraphLite reconstruction failed: %s", exc, exc_info=True)
    if _allow_synthetic_fallback():
        return _generate_fallback_graph(row, hops)
    return _degraded_graph_response(row, hops, reason)


def enrich_event_with_lateral_chain(
    event: Dict[str, Any],
    user: Optional[str] = None,
    within_seconds: int = 3600,
    min_hosts: int = 3,
    max_hops: int = 5,
) -> Dict[str, Any]:
    """Annotate event with lateral-movement chain metadata sourced from HopGraphLite."""
    if not isinstance(event, dict):
        raise ValueError("event must be a dict")

    def _apply_defaults() -> None:
        event.setdefault("graph_lateral_chain_len", 0)
        event.setdefault("graph_lateral_chain_hosts", 0)
        event.setdefault("graph_lateral_chain", [])
        event.setdefault("graph_lateral_chains", [])
        event.setdefault("graph_lateral_rapid", False)

    user_id = (user or event.get("user") or "").strip()
    if not user_id:
        _apply_defaults()
        return event

    graph = _obtain_graph()
    if graph is None:
        _apply_defaults()
        return event

    try:
        summary = graph.detect_lateral_chain(
            user_id,
            max_hops=max_hops,
            min_hosts=min_hosts,
            within_seconds=within_seconds,
        )
    except Exception:
        _apply_defaults()
        return event

    chains = summary.get("chains") if isinstance(summary, dict) else []
    if not isinstance(chains, list):
        chains = []
    normalized: List[List[str]] = []
    for chain in chains:
        if isinstance(chain, list):
            normalized.append([str(host) for host in chain if host])
    longest = max(normalized, key=len) if normalized else []
    unique_hosts = {host for chain in normalized for host in chain}

    event["graph_lateral_chain_len"] = len(longest)
    event["graph_lateral_chain_hosts"] = len(unique_hosts)
    event["graph_lateral_chain"] = longest
    event["graph_lateral_chains"] = normalized
    event["graph_lateral_rapid"] = bool(summary.get("rapid_lateral_movement")) or len(longest) >= min_hosts
    lookback = summary.get("lookback_seconds")
    if lookback is not None:
        event["graph_lateral_lookback"] = lookback
    else:
        event.pop("graph_lateral_lookback", None)
    return event


__all__ = ["query_attack_graph", "enrich_event_with_lateral_chain"]
