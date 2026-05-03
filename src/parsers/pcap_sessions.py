from __future__ import annotations

from typing import Any, Dict, List, Tuple
import hashlib
import time

try:
    from src.graph.hopgraph import GLOBAL_HOPGRAPH
except Exception:
    GLOBAL_HOPGRAPH = None  # type: ignore


def _canonical_flow_key(p: Dict[str, Any]) -> Tuple[str, int, str, int, str]:
    """Return a direction-agnostic key for grouping packets into sessions.

    We canonicalize by ordering endpoint tuples so that reverse directions map
    to the same session.
    """
    a = (p.get('src_ip') or '', int(p.get('src_port') or 0))
    b = (p.get('dst_ip') or '', int(p.get('dst_port') or 0))
    proto = (p.get('proto') or 'TCP').upper()
    if a <= b:
        return (a[0], a[1], b[0], b[1], proto)
    return (b[0], b[1], a[0], a[1], proto)


def build_sessions_from_packets(packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group a list of parsed packet dicts into higher-level sessions.

    Each packet is expected to have keys: `ts`, `src_ip`, `dst_ip`, `src_port`,
    `dst_port`, `proto`, `len`.
    Returns a list of session dicts containing basic metadata and simple
    reassembled payload bytes (directional concatenation of payloads if present).
    """
    groups: Dict[Tuple[str, int, str, int, str], List[Dict[str, Any]]] = {}
    for p in packets:
        k = _canonical_flow_key(p)
        groups.setdefault(k, []).append(p)

    sessions: List[Dict[str, Any]] = []
    for k, pkts in groups.items():
        # sort by timestamp
        pkts_sorted = sorted(pkts, key=lambda x: float(x.get('ts') or 0.0))
        start_ts = float(pkts_sorted[0].get('ts') or time.time()) if pkts_sorted else 0.0
        end_ts = float(pkts_sorted[-1].get('ts') or start_ts) if pkts_sorted else start_ts
        packet_count = len(pkts_sorted)
        byte_count = sum(int(x.get('len') or 0) for x in pkts_sorted)

        # build simple session id from tuple and time window
        raw = f"{k[0]}:{k[1]}-{k[2]}:{k[3]}-{k[4]}-{start_ts}-{end_ts}"
        sid = hashlib.sha1(raw.encode('utf-8')).hexdigest()[:16]

        session = {
            'session_id': sid,
            'start_ts': start_ts,
            'end_ts': end_ts,
            'src_ip': k[0],
            'src_port': k[1],
            'dst_ip': k[2],
            'dst_port': k[3],
            'proto': k[4],
            'packet_count': packet_count,
            'byte_count': byte_count,
            'packets': pkts_sorted,
        }
        sessions.append(session)

    return sessions


def publish_session_to_hopgraph(session: Dict[str, Any], tenant: str = 'default') -> bool:
    """Create a `pcap_session:<id>` node and minimal edges in the HopGraph.

    Returns True if the operation appeared successful. Best-effort; will
    no-op and return False when no hopgraph is available.
    """
    try:
        hg = GLOBAL_HOPGRAPH
    except Exception:
        hg = None
    if not hg:
        return False

    nid = f"pcap_session:{session.get('session_id') or 'unknown'}"
    try:
        # touch node and set attrs
        if hasattr(hg, 'add_node_attr'):
            hg.add_node_attr(nid, type='pcap_session', tenant=tenant, start_ts=session.get('start_ts'), end_ts=session.get('end_ts'), packet_count=session.get('packet_count'), byte_count=session.get('byte_count'))
        # connect to participating hosts
        s_ip = session.get('src_ip')
        d_ip = session.get('dst_ip')
        if s_ip:
            try:
                hg.add_node_attr(f'host:{s_ip}', type='host')
                hg.add_edge(f'host:{s_ip}', nid, 'participates_in', source='pcap', ts=session.get('start_ts'))
            except Exception:
                pass
        if d_ip:
            try:
                hg.add_node_attr(f'host:{d_ip}', type='host')
                hg.add_edge(f'host:{d_ip}', nid, 'participates_in', source='pcap', ts=session.get('start_ts'))
            except Exception:
                pass
        return True
    except Exception:
        return False
