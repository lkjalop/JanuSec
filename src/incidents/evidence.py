"""Incident evidence HTML exporter blending factors + hopgraph."""
from __future__ import annotations
from typing import Dict
from graph.unified import UG  # type: ignore

try:
    from src.core.threat_modeling.factor_taxonomy import compute_dread_score
except Exception:
    try:
        from core.threat_modeling.factor_taxonomy import compute_dread_score
    except Exception:
        compute_dread_score = None  # type: ignore

HTML_TEMPLATE = """<!DOCTYPE html><html><head><meta charset='utf-8'><title>Incident {iid}</title>
<style>body{{font-family:Arial;background:#111;color:#eee;padding:14px}}h1{{font-size:20px}}table{{border-collapse:collapse;width:100%;margin:12px 0}}td,th{{border:1px solid #444;padding:4px 6px;font-size:12px}}code{{color:#9cf}}</style>
</head><body>
<h1>Incident {iid}</h1>
<p><b>Host:</b> {host} | <b>Score:</b> {score:.2f} | <b>Events:</b> {event_count}</p>
<p><b>DREAD Score:</b> {dread_score} <b>Severity:</b> {dread_sev}</p>
<h2>Factors ({factor_count})</h2>
<ul>{factor_items}</ul>
<h3>DREAD Components</h3>
<ul>{dread_components}</ul>
<h2>HopGraph Subgraph (depth={depth})</h2>
<table><tr><th>Src</th><th>Dst</th><th>Type</th><th>Source</th><th>Ts</th></tr>{edge_rows}</table>
</body></html>"""

def incident_to_html(incident: Dict, depth: int = 2) -> str:
    host = incident.get('host') or ''
    node_id = f'host:{host}' if host else None
    sub = {'edges': []}
    if node_id:
        sub = UG.k_hops(node_id, k=depth)
    edge_rows = ''.join(
        f"<tr><td><code>{e['src']}</code></td><td><code>{e['dst']}</code></td><td>{e['etype']}</td><td>{e.get('source','')}</td><td>{int(e.get('ts',0))}</td></tr>"
        for e in sub.get('edges', [])
    )
    factor_items = ''.join(f"<li><code>{f}</code></li>" for f in sorted(incident.get('factors', [])))
    # DREAD: compute or read from incident
    dread_score = ''
    dread_sev = ''
    dread_components = ''
    try:
        if incident.get('dread_score') is not None:
            dread_score = f"{incident.get('dread_score')}"
        elif compute_dread_score is not None:
            sc = compute_dread_score(list(incident.get('factors', [])))
            dread_score = f"{sc.get('risk_score')}"
        if incident.get('dread_severity'):
            dread_sev = incident.get('dread_severity')
        else:
            try:
                ds = float(dread_score) if dread_score else 0.0
                dread_sev = 'high' if ds>=0.66 else ('medium' if ds>=0.33 else 'low')
            except Exception:
                dread_sev = ''
        comps = incident.get('dread') or (compute_dread_score(list(incident.get('factors', []))).get('components') if compute_dread_score else None)
        if comps and isinstance(comps, dict):
            dread_components = ''.join(f"<li>{k}: {v}</li>" for k,v in comps.items())
    except Exception:
        dread_score = ''
        dread_sev = ''
        dread_components = ''

    html = HTML_TEMPLATE.format(
        iid=incident.get('id'), host=host, score=incident.get('score',0.0),
        event_count=len(incident.get('events', [])), factor_count=len(incident.get('factors', [])),
        factor_items=factor_items, edge_rows=edge_rows, depth=depth,
        dread_score=dread_score or 'n/a', dread_sev=dread_sev or 'n/a', dread_components=dread_components
    )
    return html

__all__ = ['incident_to_html']
