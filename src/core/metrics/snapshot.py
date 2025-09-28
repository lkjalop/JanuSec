"""Metrics Snapshot Aggregator

Generates a point-in-time summary for a tenant over a recent time window.
Sources (MVP): in-memory DECISION_CACHE (recent horizon) + escalation queue +
severity rollup snapshot. Falls back gracefully if data partial.

Intended for: /metrics/snapshot endpoint & Slack pilot reporting.
"""
from __future__ import annotations
from typing import Dict, Any, List, Tuple
import time, os, math

def _decision_iter(decisions: List[Dict[str, Any]], tenant: str | None, window_seconds: int):
    if not decisions:
        return []
    now = time.time()
    cutoff = now - window_seconds
    out = []
    for d in decisions:
        try:
            if tenant and d.get('tenant_id') not in (tenant,):
                continue
            ts = d.get('timestamp') or d.get('ts') or 0
            if ts < cutoff:
                continue
            out.append(d)
        except Exception:
            continue
    return out

def aggregate(decisions: List[Dict[str, Any]], escalations: List[Dict[str, Any]], severity_roll: Dict[str, Any], tenant: str | None, window_seconds: int) -> Dict[str, Any]:
    sample = _decision_iter(decisions, tenant, window_seconds)
    total = len(sample)
    counts = {k:0 for k in ('allow','block','sim_block','escalate')}
    reason_counts: Dict[str,int] = {}
    severity_vals: List[float] = []
    for d in sample:
        dec = d.get('decision') or d.get('verdict')
        if dec in counts:
            counts[dec] += 1
        reasons = d.get('reasons') or []
        for r in reasons:
            reason_counts[r] = reason_counts.get(r,0)+1
        sev = d.get('severity') or d.get('confidence')
        if isinstance(sev,(int,float)):
            severity_vals.append(float(sev))
    sev_dist = {}
    if severity_vals:
        s = sorted(severity_vals)
        def pct(p: float):
            if not s: return 0.0
            idx = min(len(s)-1, int(len(s)*p)-1)
            return s[idx] if idx>=0 else s[0]
        sev_dist = {
            'mean': sum(severity_vals)/len(severity_vals),
            'p50': pct(0.50),
            'p95': pct(0.95),
            'max': s[-1]
        }
    # Escalation stats
    open_esc = [e for e in escalations if e.get('status')=='open'] if escalations else []
    esc_stats = {
        'open': len(open_esc),
        'total_sampled': len(escalations),
    }
    # Top reasons limited
    top_reasons = sorted(reason_counts.items(), key=lambda x: x[1], reverse=True)[:8]
    base = {
        'tenant_id': tenant,
        'window_seconds': window_seconds,
        'decisions_total': total,
        'counts': counts,
        'reason_top': [{'reason': r, 'count': c} for r,c in top_reasons],
        'severity_distribution': sev_dist,
        'severity_rollup': severity_roll or {},
        'escalations': esc_stats,
        'generated_ts': int(time.time())
    }
    return base

def format_slack(snapshot: Dict[str, Any]) -> str:
    c = snapshot.get('counts',{})
    sev = snapshot.get('severity_distribution',{})
    esc = snapshot.get('escalations',{})
    top = snapshot.get('reason_top',[])
    lines = []
    lines.append(f":bar_chart: Detection Snapshot tenant={snapshot.get('tenant_id')} window={snapshot.get('window_seconds')}s")
    lines.append(f"Decisions: total={snapshot.get('decisions_total')} allow={c.get('allow')} sim_block={c.get('sim_block')} block={c.get('block')} escalate={c.get('escalate')}")
    if sev:
        lines.append(f"Severity: mean={sev.get('mean',0):.2f} p95={sev.get('p95',0):.2f} max={sev.get('max',0):.2f}")
    lines.append(f"Escalations: open={esc.get('open')} sampled={esc.get('total_sampled')}")
    if top:
        top_str = ', '.join(f"{t['reason']}:{t['count']}" for t in top)
        lines.append(f"Top reasons: {top_str}")
    lines.append(f"Generated: <t:{snapshot.get('generated_ts')}:R>")
    return '\n'.join(lines)
