"""Policy Suggestions Engine

Generates candidate allow/block suggestions derived from recent decisions & escalations.

Heuristics (MVP):
 - Allow candidates: Events repeatedly escalated (> ALLOW_ESC_THRESHOLD) with benign resolution or ending in allow, sharing same domain/process_name/command token prefix.
 - Block candidates: Domains or process names appearing in >= BLOCK_REPEAT_THRESHOLD block decisions (severity_threshold OR policy_block) with avg severity >= BLOCK_AVG_SEV_MIN.

Inputs: Provided via call (decisions window + escalation records) to avoid direct DB dependency in first pass.
"""
from __future__ import annotations
from typing import List, Dict, Any, Tuple
import math, collections

ALLOW_ESC_THRESHOLD = 3
BLOCK_REPEAT_THRESHOLD = 4
BLOCK_AVG_SEV_MIN = 0.85

def _key_fields(decision: Dict[str, Any]):
    det = decision.get('details') or {}
    domain = det.get('domain') or decision.get('domain') or decision.get('details',{}).get('domain')
    proc = det.get('process_name') or decision.get('process_name')
    cmd = det.get('command_line') or decision.get('command') or ''
    cmd_prefix = ' '.join(cmd.split()[:2]) if isinstance(cmd,str) else ''
    return domain, proc, cmd_prefix

def suggest(decisions: List[Dict[str, Any]], escalations: List[Dict[str, Any]]) -> Dict[str, List[Dict[str,str]]]:
    # Aggregate repeated patterns
    allow_counts: Dict[Tuple[str,str,str], int] = collections.Counter()
    block_stats: Dict[Tuple[str,str,str], Dict[str, Any]] = {}
    for d in decisions:
        verdict = d.get('decision') or d.get('verdict') or d.get('path')
        reasons = d.get('reasons', []) or d.get('factors', [])
        severity = d.get('severity') or d.get('confidence')
        domain, proc, cmd_pref = _key_fields(d)
        key = (domain or '', proc or '', cmd_pref or '')
        if verdict == 'escalate' or (verdict == 'allow' and 'severity_escalate' in reasons):
            allow_counts[key] += 1
        if verdict == 'block':
            st = block_stats.setdefault(key, {'count':0,'sev_sum':0.0,'policy_block':0,'threshold_block':0})
            st['count'] += 1
            if isinstance(severity,(int,float)):
                st['sev_sum'] += severity
            if 'policy_block' in reasons:
                st['policy_block'] += 1
            if 'severity_threshold' in reasons:
                st['threshold_block'] += 1
    # incorporate escalation records (unresolved open escalations count toward allow candidacy)
    for e in escalations:
        if e.get('status') == 'open':
            domain = e.get('domain') or ''
            proc = e.get('process_name') or ''
            cmd_pref = ' '.join((e.get('command_line') or '').split()[:2])
            key = (domain, proc, cmd_pref)
            allow_counts[key] += 1
    allow_suggestions = []
    for key, c in allow_counts.items():
        if c >= ALLOW_ESC_THRESHOLD:
            domain, proc, cmdp = key
            desc = []
            if domain: desc.append(f"domain={domain}")
            if proc: desc.append(f"process={proc}")
            if cmdp: desc.append(f"cmd_prefix='{cmdp}'")
            allow_suggestions.append({
                'match': {k:v for k,v in [('domain',domain),('process_name',proc),('command_prefix',cmdp)] if v},
                'reason': f"escalated_or_allowed_repeated={c}",
                'confidence': 'medium'
            })
    block_suggestions = []
    for key, st in block_stats.items():
        if st['count'] >= BLOCK_REPEAT_THRESHOLD:
            avg_sev = st['sev_sum']/st['count'] if st['count'] else 0.0
            if avg_sev >= BLOCK_AVG_SEV_MIN:
                domain, proc, cmdp = key
                block_suggestions.append({
                    'match': {k:v for k,v in [('domain',domain),('process_name',proc),('command_prefix',cmdp)] if v},
                    'reason': f"repeated_blocks={st['count']} avg_sev={avg_sev:.2f}",
                    'confidence': 'high' if avg_sev > 0.92 else 'medium'
                })
    return {
        'allow_candidates': sorted(allow_suggestions, key=lambda x: x['reason'], reverse=True)[:20],
        'block_candidates': sorted(block_suggestions, key=lambda x: x['reason'], reverse=True)[:20]
    }
