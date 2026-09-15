"""
Lightweight Remote Access HopGraph helpers.

This module provides small helper functions to create VPN/RDP/Bastion nodes
and edges in the HopGraph. It's intentionally import-light and uses
string-based node/edge creation so it can be called from API endpoints
without pulling heavy dependencies at import time.

The real HopGraph ingestion functions should be used when available; for
tests we fall back to returning the constructed payload.
"""
from typing import Dict, Any, Optional
try:
    from src.core.utils.ip_utils import normalize_ip
except Exception:
    def normalize_ip(x):
        return x
import os
from dataclasses import dataclass


@dataclass
class RemoteAccessEvent:
    src_ip: str
    user: str
    dest_host: str
    dest_port: Optional[int] = None
    protocol: str = "vpn"  # vpn|rdp|bastion
    timestamp: Optional[str] = None
    raw: Dict[str, Any] = None
    tenant: Optional[str] = None
    source: Optional[str] = None
    confidence: Optional[float] = None


def make_nodes_and_edges(event: RemoteAccessEvent) -> Dict[str, Any]:
    """Return a minimal representation of nodes and edges to add to HopGraph.

    Nodes:
      - host:{dest_host}
      - user:{user}
      - ip:{src_ip}
      - access:{protocol}:{session_id?}

    Edges:
      - ip -> user (observed_auth_from)
      - user -> host (remote_access)
      - access -> host (access_to)
    """
    session_id = None
    if event.timestamp:
        session_id = f"sess-{event.timestamp}-{event.user}"

    src_ip_norm = normalize_ip(event.src_ip) if event.src_ip else event.src_ip
    nodes = [
        {"id": f"host:{event.dest_host}", "type": "host", "meta": {"host": event.dest_host}},
        {"id": f"user:{event.user}", "type": "user", "meta": {"user": event.user}},
        {"id": f"ip:{src_ip_norm}", "type": "ip", "meta": {"ip": src_ip_norm}},
    ]
    if session_id:
        nodes.append({"id": f"access:{event.protocol}:{session_id}", "type": "access_session", "meta": {"protocol": event.protocol}})

    sig = {}
    try:
        if isinstance(event.raw, dict) and isinstance(event.raw.get('signals'), dict):
            sig = {'signals': dict(event.raw.get('signals'))}
    except Exception:
        sig = {}

    # Compute lightweight factors from signals for downstream risk models
    # normalize factor names as they're produced
    factors = []
    try:
        from src.core.threat_modeling.factor_aliases import normalize_factor
    except Exception:
        normalize_factor = lambda x: x
    try:
        if sig and isinstance(sig.get('signals'), dict):
            s = sig.get('signals')
            if s.get('impossible_travel'): factors.append(normalize_factor('remote:impossible_travel'))
            if s.get('mfa_used') is False: factors.append(normalize_factor('remote:mfa_missing'))
            if s.get('geo_out_of_policy'): factors.append(normalize_factor('remote:geo_out_of_policy'))
            if s.get('user_geo_new_country'): factors.append(normalize_factor('remote:user_geo_new_country'))
            if s.get('bastion_priv_escalation'): factors.append(normalize_factor('remote:bastion_priv_escalation'))
            if s.get('bastion_database_dump'): factors.append(normalize_factor('remote:bastion_database_dump'))
            if s.get('bastion_file_transfer'): factors.append(normalize_factor('remote:bastion_file_transfer'))
    except Exception:
        factors = []

    edges = [
        {"src": f"ip:{src_ip_norm}", "dst": f"user:{event.user}", "type": "observed_auth_from", "meta": {"raw": event.raw}},
        {"src": f"user:{event.user}", "dst": f"host:{event.dest_host}", "type": "remote_access", "meta": {"protocol": event.protocol, "port": event.dest_port, **sig, "factors": factors}},
    ]
    if session_id:
        edges.append({"src": f"access:{event.protocol}:{session_id}", "dst": f"host:{event.dest_host}", "type": "access_to", "meta": {}})

    return {"nodes": nodes, "edges": edges}


def ingest_to_hopgraph(event: RemoteAccessEvent, hopgraph) -> Dict[str, Any]:
    """Ingest the event into the provided hopgraph instance.

    Uses the HopGraph API (add_edge, add_node_attr). If `hopgraph` is None,
    return the constructed payload for unit testing.
    """
    payload = make_nodes_and_edges(event)
    if hopgraph is None:
        return {"status": "mock", "payload": payload}

    # Convert nodes into attributes and ensure nodes exist in the graph
    try:
        for n in payload["nodes"]:
            nid = n.get("id")
            ntype = n.get("type")
            meta = n.get("meta") or {}
            # enrich metadata with tenant/source/confidence if provided
            try:
                if event.tenant:
                    meta.setdefault('tenant', event.tenant)
                if event.source:
                    meta.setdefault('source', event.source)
                if event.confidence is not None:
                    meta.setdefault('confidence', float(event.confidence))
            except Exception:
                pass
            # HopGraph exposes add_node_attr to touch node and set attrs
            try:
                if hasattr(hopgraph, "add_node_attr"):
                    hopgraph.add_node_attr(nid, type=ntype, **meta)
                else:
                    # best-effort: set nodes dict directly if available
                    if hasattr(hopgraph, "nodes") and isinstance(hopgraph.nodes, dict):
                        with getattr(hopgraph, "_lock", DummyLock()):
                            hopgraph.nodes.setdefault(nid, {}).update({"id": nid, "type": ntype, **meta})
            except Exception:
                # don't fail ingestion on node attr setting
                pass

        # Ingest edges using HopGraph.add_edge
        edge_count = 0
        for e in payload["edges"]:
            src = e.get("src")
            dst = e.get("dst")
            etype = e.get("type") or e.get("etype") or e.get("type")
            meta = e.get("meta") or {}
            # HopGraph.add_edge signature: add_edge(src,dst,edge_type,source='event',ts=None,attrs=None,weight=None)
            try:
                # Prefer add_edge for in-memory HopGraph
                if hasattr(hopgraph, "add_edge"):
                    hopgraph.add_edge(src, dst, etype, source=meta.get("source", "event"), ts=None, attrs=meta, weight=meta.get("weight"))
                    edge_count += 1
                else:
                    # If hopgraph has a persistence backend (HopGraphLite), attempt to use it
                    if hasattr(hopgraph, 'backend') and getattr(hopgraph, 'backend'):
                        try:
                            be = hopgraph.backend
                            be.save_node(src, src.split(':',1)[0], meta)
                        except Exception:
                            pass
                        try:
                            be.save_edge(src, dst, etype, weight=meta.get('weight', 1.0), metadata=meta)
                            edge_count += 1
                        except Exception:
                            pass
                    elif hasattr(hopgraph, "save_edge"):
                        hopgraph.save_edge(src, dst, etype, weight=meta.get("weight", 1.0), metadata=meta)
                        edge_count += 1
            except Exception:
                pass
    except Exception:
        return {"status": "error", "message": "ingest_failed"}

    return {"status": "ok", "ingested": {"nodes": len(payload["nodes"]), "edges": edge_count}}


class DummyLock:
    def __enter__(self):
        return None
    def __exit__(self, exc_type, exc, tb):
        return False
