"""Detect lateral movement patterns, including protocol-aware bursts."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Tuple

PROTOCOL_FACTORS = {
    "rdp": "lateral_rdp_burst",
    "smb": "lateral_smb_burst",
    "winrm": "lateral_winrm_burst",
    "ssh": "lateral_ssh_burst",
}

PROTOCOL_HOST_THRESHOLD = 3
PROTOCOL_BURST_WINDOW_SECONDS = 600  # 10 minutes

HOPGRAPH_ACTOR_TYPE = "identity"
HOPGRAPH_ENDPOINT_TYPE = "endpoint"
HOPGRAPH_PROTO_EDGE = "network_connection"


def _parse_ts(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime):
        return value.timestamp()
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "")).timestamp()
        except Exception:
            return 0.0
    return 0.0


def _protocol_burst(entries: List[Dict[str, Any]], host_threshold: int, window_seconds: int) -> Tuple[bool, int]:
    first_seen: Dict[str, float] = {}
    for entry in entries:
        dst = entry.get("dst")
        ts = entry.get("ts")
        if not dst or ts is None:
            continue
        prev = first_seen.get(dst)
        if prev is None or ts < prev:
            first_seen[dst] = ts
    if len(first_seen) < host_threshold:
        return False, len(first_seen)
    times = sorted(first_seen.values())
    for idx in range(len(times) - host_threshold + 1):
        start = times[idx]
        end = times[idx + host_threshold - 1]
        if end - start <= window_seconds:
            return True, len(first_seen)
    return False, len(first_seen)


def detect_lateral_movement(runtime: Any, threshold: int = 5) -> List[Dict[str, Any]]:
    """Return lateral movement factors using host counts + protocol bursts."""
    results: List[Dict[str, Any]] = []
    if runtime is None:
        return results

    try:
        conn_events = getattr(runtime, "conn_events", None) or []
    except Exception:
        conn_events = []

    per_actor_hosts: Dict[str, set] = {}
    per_actor_protocols: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}

    for event in conn_events:
        try:
            actor = event.get("actor") or event.get("src") or "unknown"
            dst = event.get("dst_host") or event.get("dst") or event.get("host")
            if not actor or not dst:
                continue
            per_actor_hosts.setdefault(actor, set()).add(dst)
            protocol = (event.get("protocol") or event.get("service") or "").lower()
            if protocol in PROTOCOL_FACTORS:
                proto_map = per_actor_protocols.setdefault(actor, {})
                proto_entries = proto_map.setdefault(protocol, [])
                proto_entries.append({"dst": dst, "ts": _parse_ts(event.get("timestamp"))})
        except Exception:
            continue

    hopgraph_edges: List[Dict[str, Any]] = []

    def _emit_edges(actor: str, hosts: List[str], protocol: str, reason: str) -> List[Dict[str, Any]]:
        edges: List[Dict[str, Any]] = []
        for host in hosts:
            edges.append(
                {
                    "source": actor,
                    "source_type": HOPGRAPH_ACTOR_TYPE,
                    "target": host,
                    "target_type": HOPGRAPH_ENDPOINT_TYPE,
                    "edge_type": HOPGRAPH_PROTO_EDGE,
                    "protocol": protocol,
                    "reason": reason,
                }
            )
        return edges

    for actor, dsts in per_actor_hosts.items():
        try:
            if len(dsts) >= threshold:
                host_list = sorted(dsts)
                results.append(
                    {
                        "factor": "lateral_movement",
                        "actor": actor,
                        "distinct_hosts": len(dsts),
                        "score": 0.7,
                        "reason": f"actor connected to {len(dsts)} distinct hosts",
                        "metadata": {"mitre": ["T1021", "T1210"], "stride": ["tampering"]},
                    }
                )
                hopgraph_edges.extend(_emit_edges(actor, host_list, "multi-protocol", "fanout"))
        except Exception:
            continue

    for actor, proto_map in per_actor_protocols.items():
        for protocol, entries in proto_map.items():
            factor = PROTOCOL_FACTORS.get(protocol)
            if not factor:
                continue
            try:
                burst, host_count = _protocol_burst(entries, PROTOCOL_HOST_THRESHOLD, PROTOCOL_BURST_WINDOW_SECONDS)
                if burst:
                    host_list = list({entry.get("dst") for entry in entries if entry.get("dst")})
                    results.append(
                        {
                            "factor": factor,
                            "actor": actor,
                            "protocol": protocol,
                            "distinct_hosts": host_count,
                            "window_seconds": PROTOCOL_BURST_WINDOW_SECONDS,
                            "score": 0.82,
                            "reason": f"{protocol.upper()} burst across {host_count} hosts in <= {PROTOCOL_BURST_WINDOW_SECONDS}s",
                            "metadata": {"mitre": ["T1021"], "stride": ["tampering"]},
                        }
                    )
                    hopgraph_edges.extend(_emit_edges(actor, host_list, protocol, "burst"))
            except Exception:
                continue

    fusion_factors = _detect_protocol_fusion(runtime)
    for factor in fusion_factors:
        edges = factor.pop("hopgraph_edges", [])
        hopgraph_edges.extend(edges)
        results.append(factor)

    if hopgraph_edges:
        results.append(
            {
                "factor": "lateral_movement_edges",
                "hopgraph_edges": hopgraph_edges,
                "reason": "compiled lateral movement edges for HopGraph replay",
            }
        )

    return results


def detect_wmi_process_lateral(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Detect WMI lateral movement from sysmon process-create events (event ID 1).
    Fires when wmiprvse.exe spawns encoded PowerShell, indicating remote WMI command execution."""
    results: List[Dict[str, Any]] = []
    proc = str(event.get("process_name") or "").lower()
    parent = str(event.get("parent_process") or "").lower()
    cmdline = str(event.get("command_line") or "").lower()
    host = str(event.get("host") or "")
    user = str(event.get("user") or "")

    if "wmiprvse.exe" not in parent:
        return results

    is_encoded_exec = any(t in cmdline for t in (
        "-enc ", "-encodedcommand", " iex ", "invoke-expression", "downloadstring",
    ))
    is_suspicious_child = any(p in proc for p in ("powershell", "cmd", "wscript", "cscript", "mshta"))

    if is_encoded_exec or is_suspicious_child:
        results.append({
            "factor": "wmi_encoded_ps_lateral",
            "actor": user or "unknown",
            "host": host,
            "process": proc,
            "parent": "wmiprvse.exe",
            "score": 0.88,
            "reason": f"wmiprvse.exe spawned {proc!r} with encoded/exec payload on {host!r}",
            "metadata": {"mitre": ["T1047", "T1059.001"], "stride": ["tampering", "elevation"]},
        })
    return results


def _detect_protocol_fusion(runtime: Any) -> List[Dict[str, Any]]:
    """Detect Kerberos->WinRM/SMB chains and Azure -> automation joins."""
    results: List[Dict[str, Any]] = []
    if runtime is None:
        return results

    auth_events = getattr(runtime, "auth_events", None) or []
    azure_signins = getattr(runtime, "azure_signins", None) or []
    conn_events = getattr(runtime, "conn_events", None) or []

    kerberos_map: Dict[Tuple[str, str], List[float]] = defaultdict(list)
    for event in auth_events:
        try:
            if str(event.get("protocol", "")).lower() not in {"kerberos", "krb"}:
                continue
            actor = event.get("actor") or event.get("user")
            host = event.get("host") or event.get("resource") or event.get("dst")
            if not actor or not host:
                continue
            kerberos_map[(actor, host)].append(_parse_ts(event.get("timestamp")))
        except Exception:
            continue

    azure_map: Dict[str, List[Tuple[str, float]]] = defaultdict(list)
    for signin in azure_signins:
        try:
            actor = signin.get("user") or signin.get("principal")
            resource = signin.get("resource") or signin.get("application")
            if not actor or not resource:
                continue
            azure_map[actor].append((resource, _parse_ts(signin.get("timestamp"))))
        except Exception:
            continue

    chains: List[Dict[str, Any]] = []
    for event in conn_events:
        try:
            protocol = str(event.get("protocol") or event.get("service") or "").lower()
            if protocol not in {"winrm", "smb"}:
                continue
            actor = event.get("actor") or event.get("src") or "unknown"
            host = event.get("dst_host") or event.get("dst") or event.get("host")
            ts = _parse_ts(event.get("timestamp"))
            if not actor or not host:
                continue
            key = (actor, host)
            prior = kerberos_map.get(key)
            if not prior:
                continue
            recent = [p for p in prior if 0 <= ts - p <= PROTOCOL_BURST_WINDOW_SECONDS]
            if not recent:
                continue
            chains.append(
                {
                    "factor": "lateral_protocol_chain",
                    "actor": actor,
                    "protocol": protocol,
                    "host": host,
                    "reason": f"Kerberos auth followed by {protocol.upper()} within {PROTOCOL_BURST_WINDOW_SECONDS}s",
                    "metadata": {"mitre": ["T1021", "T1550"], "stride": ["elevation"]},
                    "hopgraph_edges": [
                        {
                            "source": actor,
                            "source_type": HOPGRAPH_ACTOR_TYPE,
                            "target": host,
                            "target_type": HOPGRAPH_ENDPOINT_TYPE,
                            "edge_type": HOPGRAPH_PROTO_EDGE,
                            "protocol": protocol,
                            "reason": "kerberos-chained-connection",
                        }
                    ],
                }
            )
        except Exception:
            continue

    for actor, signins in azure_map.items():
        for resource, signin_ts in signins:
            for event in conn_events:
                try:
                    proto = str(event.get("protocol") or "").lower()
                    if proto not in {"winrm", "ssh"}:
                        continue
                    if (event.get("actor") or event.get("src")) != actor:
                        continue
                    host = event.get("dst_host") or event.get("dst") or event.get("host")
                    ts = _parse_ts(event.get("timestamp"))
                    if abs(ts - signin_ts) > PROTOCOL_BURST_WINDOW_SECONDS:
                        continue
                    chains.append(
                        {
                            "factor": "lateral_cloud_access_chain",
                            "actor": actor,
                            "protocol": proto,
                            "resource": resource,
                            "host": host,
                            "reason": f"Azure sign-in to {resource} followed by {proto.upper()} access",
                            "metadata": {"mitre": ["T1078"], "stride": ["elevation"]},
                            "hopgraph_edges": [
                                {
                                    "source": actor,
                                    "source_type": HOPGRAPH_ACTOR_TYPE,
                                    "target": host,
                                    "target_type": HOPGRAPH_ENDPOINT_TYPE,
                                    "edge_type": HOPGRAPH_PROTO_EDGE,
                                    "protocol": proto,
                                    "reason": "azure-chain",
                                }
                            ],
                        }
                    )
                except Exception:
                    continue

    return chains
