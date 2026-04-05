"""Data domain HopGraph helpers.

Creates canonical nodes for databases/tables and correlates user access
with lightweight DLP-style heuristics.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Optional, List
import re


@dataclass
class DataAccessEvent:
    user: str
    database: str
    table: str
    query: Optional[str] = None
    record_count: Optional[int] = None
    sink: Optional[str] = None  # e.g., s3://bucket/key or external host
    timestamp: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


PII_TOKENS = [
    'ssn', 'social_security', 'credit_card', 'cc_number', 'card_number',
    'cvv', 'cvc', 'dob', 'birth_date', 'first_name', 'last_name', 'email',
    'passport', 'driver_license', 'iban', 'swift', 'routing_number'
]


def _dlp_signals(query: str | None, record_count: int | None, sink: str | None) -> Dict[str, Any]:
    sig: Dict[str, Any] = {}
    q = (query or '').lower()
    if q:
        if any(tok in q for tok in PII_TOKENS):
            sig['pii_query'] = True
        # Bulk export hints
        if re.search(r'\bselect\b\s+\*', q):
            sig['select_all'] = True
        if 'limit' not in q and ('where' not in q or re.search(r'where\s+1\s*=\s*1', q)):
            sig['broad_query'] = True
    try:
        if record_count is not None and int(record_count) >= 10000:
            sig['large_result_set'] = True
    except Exception:
        pass
    if sink:
        s = sink.lower()
        if s.startswith('s3://') and (('/public' in s) or ('.public' in s) or (':public' in s)):
            sig['unusual_sink'] = True
        if s.startswith('http://') or s.startswith('https://'):
            sig['external_sink'] = True
    return sig


def make_nodes_and_edges(ev: DataAccessEvent) -> Dict[str, Any]:
    db_node = f"db:{ev.database}"
    tbl_node = f"table:{ev.database}.{ev.table}"
    user_node = f"user:{ev.user}"
    nodes = [
        {"id": db_node, "type": "database", "meta": {"database": ev.database}},
        {"id": tbl_node, "type": "table", "meta": {"database": ev.database, "table": ev.table}},
        {"id": user_node, "type": "user", "meta": {"user": ev.user}},
    ]
    sig = _dlp_signals(ev.query, ev.record_count, ev.sink)
    factors: List[str] = []
    if sig.get('pii_query'): factors.append('data:pii_query')
    if sig.get('large_result_set'): factors.append('data:large_result_set')
    if sig.get('unusual_sink') or sig.get('external_sink'): factors.append('data:unusual_sink')
    edges = [
        {"src": user_node, "dst": tbl_node, "type": "accesses", "meta": {"query": ev.query, "record_count": ev.record_count, "factors": factors, "signals": sig, "raw": ev.raw or {}}},
        {"src": tbl_node, "dst": db_node, "type": "contains", "meta": {}},
    ]
    if ev.sink:
        sink_node = f"sink:{ev.sink}"
        nodes.append({"id": sink_node, "type": "sink", "meta": {"sink": ev.sink}})
        edges.append({"src": tbl_node, "dst": sink_node, "type": "exported_to", "meta": {"signals": sig}})
    return {"nodes": nodes, "edges": edges}


def ingest_to_hopgraph(ev: DataAccessEvent, hopgraph) -> Dict[str, Any]:
    payload = make_nodes_and_edges(ev)
    if hopgraph is None:
        return {"status": "mock", "payload": payload}
    # ensure nodes
    for n in payload['nodes']:
        try:
            if hasattr(hopgraph, 'add_node_attr'):
                hopgraph.add_node_attr(n['id'], type=n.get('type'), **(n.get('meta') or {}))
        except Exception:
            pass
    # add edges
    ecount = 0
    for e in payload['edges']:
        try:
            if hasattr(hopgraph, 'add_edge'):
                hopgraph.add_edge(e['src'], e['dst'], e['type'], source='data', attrs=e.get('meta') or {})
                ecount += 1
        except Exception:
            pass
    return {"status": "ok", "ingested": {"nodes": len(payload['nodes']), "edges": ecount}}

__all__ = ['DataAccessEvent', 'make_nodes_and_edges', 'ingest_to_hopgraph']

