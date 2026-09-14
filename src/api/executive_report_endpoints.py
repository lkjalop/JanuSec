from __future__ import annotations
import os, json, time
from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException, Query
from io import StringIO

from compliance.taxonomy import coverage, load_taxonomy  # type: ignore
from enrichment.kev_epss import kev_lookup, epss_lookup  # type: ignore
from enrichment.cve_lookup import lookup_cve, vulnerability_factors_for  # type: ignore
try:
    from src.reporting.persona_parser import parse_persona_text, validate_parsed_persona
except Exception:
    parse_persona_text = None  # type: ignore
    validate_parsed_persona = None  # type: ignore

router = APIRouter(prefix='/api/v1/executive', tags=['Executive'])

# Helper: collect coverage across a set of frameworks (best-fit names in taxonomy keys)
FRAMEWORKS = ['mitre','stride','dread','maestro','pasta','cvss']

# Recent HopGraph sessions (import graph_sessions store)
try:
    from .graph_sessions import _SESSIONS  # type: ignore
except Exception:
    _SESSIONS = {}

# Recent hunt queries
try:
    from .hunt_endpoints import _HUNT_QUERY_LOG  # type: ignore
except Exception:
    _HUNT_QUERY_LOG = []

# Playbook recommend function via internal request (imported here to reuse scoring)
try:
    from .playbooks_endpoints import recommend_playbooks as _recommend_playbooks  # type: ignore
except Exception:
    _recommend_playbooks = None


def _collect_coverage() -> List[Dict[str, Any]]:
    out = []
    for fw in FRAMEWORKS:
        try:
            out.append(coverage(fw))
        except Exception:
            out.append({'framework': fw, 'error': 'coverage_failed'})
    return out


def _vulnerability_snapshot() -> Dict[str, Any]:
    # KEV / EPSS counts rely on in-memory DB length; if empty returns zeros
    try:
        from enrichment.kev_epss import _KEV_DB, _EPSS_DB  # type: ignore
        kev_count = len(_KEV_DB)
        epss_count = len(_EPSS_DB)
    except Exception:
        kev_count = 0; epss_count = 0
    sample_cves = ['CVE-2024-2193','CVE-2025-1020']
    factors: List[str] = []
    sample_records: List[Dict[str, Any]] = []
    for c in sample_cves:
        rec = lookup_cve(c)
        if rec:
            sample_records.append({'cve': c, 'cvss_base_score': rec.get('cvss_base_score')})
            for f in vulnerability_factors_for(rec):
                factors.append(f)
            if kev_lookup(c):
                factors.append('vuln:kev_listed')
            if epss_lookup(c):
                factors.append('vuln:epss_scored')
    return {
        'kev_cached': kev_count,
        'epss_cached': epss_count,
        'sample_cves': sample_records,
        'factors': sorted(set(factors))
    }


def _recent_sessions(limit: int = 5) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for sid, summary in _SESSIONS.items():
        items.append({
            'session_id': sid,
            'confidence': summary.get('confidence'),
            'verdict': summary.get('verdict'),
            'path_length': summary.get('path_length'),
            'domain_diversity_score': summary.get('domain_diversity_score'),
            'mapping_semantics_score': summary.get('mapping_semantics_score'),
            'factors': [f.get('name') for f in summary.get('factors', []) if isinstance(f, dict)]
        })
    items.sort(key=lambda x: (x.get('confidence') or 0), reverse=True)
    return items[:limit]


def _recent_hunts(limit: int = 5) -> List[Dict[str, Any]]:
    try:
        arr = list(reversed(_HUNT_QUERY_LOG))
    except Exception:
        arr = []
    return [
        {
            'ts': q.get('ts'),
            'spec': q.get('spec'),
            'result_count': q.get('result_count')
        } for q in arr[:limit]
    ]


def _playbook_recommendations(factors: List[str]) -> List[Dict[str, Any]]:
    if not _recommend_playbooks:
        return []
    try:
        # Emulate query param call
        joined = ','.join(factors)
        res = _recommend_playbooks(joined, limit=5)  # type: ignore
        if isinstance(res, dict):
            return res.get('recommendations') or []
    except Exception:
        return []
    return []


def _build_json_summary() -> Dict[str, Any]:
    cov = _collect_coverage()
    vuln = _vulnerability_snapshot()
    sessions = _recent_sessions()
    hunts = _recent_hunts()
    # Aggregate factors from sessions + vuln for playbook recommendation seed
    seed_factors = set(vuln.get('factors', []))
    for s in sessions:
        for f in s.get('factors', []) or []:
            seed_factors.add(f)
    recs = _playbook_recommendations(sorted(seed_factors))
    return {
        'generated_ts': time.time(),
        'coverage': cov,
        'vulnerability_snapshot': vuln,
        'hopgraph_sessions': sessions,
        'recent_hunt_queries': hunts,
        'playbook_recommendations': recs,
        'factor_seed': sorted(seed_factors)
    }


def _render_html(data: Dict[str, Any]) -> str:
    buf = StringIO()
    buf.write('<html><head><title>Executive Security Summary</title><style>body{background:#0B0E14;color:#E8EBF0;font-family:Inter,Segoe UI,sans-serif;padding:20px}table{border-collapse:collapse;width:100%;margin-bottom:18px}th,td{border:1px solid #2A3142;padding:6px 8px;font-size:12px}th{background:#1C2230}h2{margin-top:28px}code{background:#1C2230;padding:3px 6px;border-radius:4px}</style></head><body>')
    buf.write('<h1>Executive Security Summary</h1>')
    buf.write(f"<div style='font-size:12px;opacity:.7'>Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</div>")
    # Coverage
    buf.write('<h2>Framework Coverage</h2><table><thead><tr><th>Framework</th><th>Mapped</th><th>Total</th><th>Coverage %</th></tr></thead><tbody>')
    for c in data.get('coverage', []):
        buf.write(f"<tr><td>{c.get('framework')}</td><td>{c.get('mapped')}</td><td>{c.get('total_factors')}</td><td>{c.get('coverage_percent')}</td></tr>")
    buf.write('</tbody></table>')
    # Vulnerabilities
    vuln = data.get('vulnerability_snapshot', {})
    buf.write('<h2>Vulnerability Snapshot</h2>')
    buf.write(f"<div>KEV Cached: {vuln.get('kev_cached')} • EPSS Cached: {vuln.get('epss_cached')}</div>")
    buf.write('<div style="margin-top:6px">Sample CVEs:</div><ul>')
    for r in vuln.get('sample_cves', []):
        buf.write(f"<li>{r.get('cve')} (CVSS {r.get('cvss_base_score')})</li>")
    buf.write('</ul>')
    buf.write('<div>Factors: ' + ', '.join(vuln.get('factors', [])) + '</div>')
    # HopGraph
    buf.write('<h2>HopGraph Sessions</h2><table><thead><tr><th>ID</th><th>Verdict</th><th>Confidence</th><th>Path Length</th><th>Domain Diversity</th><th>Mapping Semantics</th></tr></thead><tbody>')
    for s in data.get('hopgraph_sessions', []):
        buf.write(f"<tr><td>{s.get('session_id')}</td><td>{s.get('verdict')}</td><td>{s.get('confidence')}</td><td>{s.get('path_length')}</td><td>{s.get('domain_diversity_score')}</td><td>{s.get('mapping_semantics_score')}</td></tr>")
    buf.write('</tbody></table>')
    # Hunting
    buf.write('<h2>Recent Hunt Queries</h2><table><thead><tr><th>Timestamp</th><th>Spec</th><th>Result Count</th></tr></thead><tbody>')
    for h in data.get('recent_hunt_queries', []):
        buf.write(f"<tr><td>{time.strftime('%H:%M:%S', time.localtime(h.get('ts') or time.time()))}</td><td><code>{json.dumps(h.get('spec'))}</code></td><td>{h.get('result_count')}</td></tr>")
    buf.write('</tbody></table>')
    # Log Gap Health
    dep = data.get('dependency_status') or {}
    logs = dep.get('logs') or {}
    gaps = logs.get('gaps') or []
    buf.write('<h2>Log Gap Health</h2>')
    if gaps:
        buf.write('<table><thead><tr><th>Source</th><th>Staleness (s)</th><th>TTL (s)</th><th>Severity</th><th>Message</th></tr></thead><tbody>')
        for g in gaps:
            buf.write(f"<tr><td>{g.get('name')}</td><td>{g.get('seconds_since_ok')}</td><td>{g.get('ttl')}</td><td>{g.get('severity')}</td><td>{g.get('message')}</td></tr>")
        buf.write('</tbody></table>')
    else:
        buf.write('<div>No critical log gaps detected.</div>')
    # Recommendations
    buf.write('<h2>Playbook Recommendations</h2><table><thead><tr><th>ID</th><th>Title</th><th>Score</th><th>SLA (m)</th><th>Roles</th><th>Matched Factors</th></tr></thead><tbody>')
    for r in data.get('playbook_recommendations', []):
        buf.write(f"<tr><td>{r.get('id')}</td><td>{r.get('title')}</td><td>{r.get('score')}</td><td>{r.get('sla_minutes')}</td><td>{', '.join(r.get('roles') or [])}</td><td>{', '.join(r.get('matched_any') or [])}</td></tr>")
    buf.write('</tbody></table>')
    buf.write('</body></html>')
    return buf.getvalue()


def _render_markdown(data: Dict[str, Any]) -> str:
    lines = []
    lines.append('# Executive Security Summary')
    lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append('\n## Framework Coverage')
    lines.append('| Framework | Mapped | Total | Coverage % |')
    lines.append('|-----------|--------|-------|------------|')
    for c in data.get('coverage', []):
        lines.append(f"| {c.get('framework')} | {c.get('mapped')} | {c.get('total_factors')} | {c.get('coverage_percent')} |")
    vuln = data.get('vulnerability_snapshot', {})
    lines.append('\n## Vulnerability Snapshot')
    lines.append(f"KEV Cached: {vuln.get('kev_cached')} • EPSS Cached: {vuln.get('epss_cached')}")
    lines.append('Sample CVEs:')
    for r in vuln.get('sample_cves', []):
        lines.append(f"- {r.get('cve')} (CVSS {r.get('cvss_base_score')})")
    lines.append('Factors: ' + ', '.join(vuln.get('factors', [])))
    lines.append('\n## HopGraph Sessions')
    lines.append('| Session | Verdict | Confidence | Path Length | Domain Diversity | Mapping Semantics |')
    lines.append('|---------|---------|------------|-------------|------------------|-------------------|')
    for s in data.get('hopgraph_sessions', []):
        lines.append(f"| {s.get('session_id')} | {s.get('verdict')} | {s.get('confidence')} | {s.get('path_length')} | {s.get('domain_diversity_score')} | {s.get('mapping_semantics_score')} |")
    lines.append('\n## Recent Hunt Queries')
    for h in data.get('recent_hunt_queries', []):
        lines.append(f"- {time.strftime('%H:%M:%S', time.localtime(h.get('ts') or time.time()))} • results {h.get('result_count')} • spec: `{json.dumps(h.get('spec'))}`")
    lines.append('\n## Playbook Recommendations')
    for r in data.get('playbook_recommendations', []):
        lines.append(f"- {r.get('id')} ({r.get('score')}) SLA {r.get('sla_minutes')}m roles: {', '.join(r.get('roles') or [])} factors: {', '.join(r.get('matched_any') or [])}")
    lines.append('\n## Log Gap Health')
    dep = data.get('dependency_status') or {}
    logs = dep.get('logs') or {}
    gaps = logs.get('gaps') or []
    if gaps:
        for g in gaps:
            lines.append(f"- {g.get('name')}: stale {g.get('seconds_since_ok')}s > TTL {g.get('ttl')}s [{g.get('severity')}] — {g.get('message')}")
    else:
        lines.append('- No critical log gaps detected.')
    return '\n'.join(lines)

@router.get('/summary')
async def executive_summary(format: str = Query('json'), limit_sessions: int = 5) -> Any:
    data = _build_json_summary()
    # Trim sessions if needed
    if limit_sessions and isinstance(data.get('hopgraph_sessions'), list):
        data['hopgraph_sessions'] = data['hopgraph_sessions'][:limit_sessions]
    if format == 'json':
        return data
    if format == 'html':
        return _render_html(data)
    if format in {'md','markdown'}:
        return _render_markdown(data)
    raise HTTPException(status_code=400, detail='unsupported_format')

__all__ = ['router']
