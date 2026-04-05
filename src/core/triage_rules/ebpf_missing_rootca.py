"""Triage rule: correlate missing-root-ca TLS detections with eBPF events."""
from typing import List, Dict, Any

try:
    from src.core.scoring.dread_engine import compute_dread, severity_from_dread
except Exception:  # pragma: no cover - fallback for lightweight runs
    compute_dread = None  # type: ignore
    severity_from_dread = None  # type: ignore

_MITRE_MAP = {
    'docker_sock_access': ['T1610'],  # Container Escape (approx)
    'process_injection': ['T1055'],
    'suspicious_exec_tmp': ['T1105'],  # Ingress Tool Transfer (approx)
}

_CVSS_BASE = {
    'docker_sock_access': 8.8,
    'process_injection': 9.1,
    'suspicious_exec_tmp': 7.4,
}


def correlate_missing_root_ca(missing_root_events: List[Dict[str, Any]], ebpf_events: List[Dict[str, Any]]):
    """Return correlated incidents when missing-root-ca events coincide with suspicious eBPF evidence.

    Simple heuristic:
    - If a missing-root-ca TLS event originates from a process/pod that has recent eBPF events showing docker.sock access, ptrace, or execve of unexpected binaries, flag high.
    """
    correlated = []
    for m in missing_root_events:
        src_container = m.get('container_id') or m.get('container')
        src_pid = m.get('pid')
        # Look for ebpf events matching container or pid in recent window
        hits = []
        for e in ebpf_events:
            if src_container and e.get('container_id') and src_container == e.get('container_id'):
                hits.append(e)
            elif src_pid and e.get('pid') and src_pid == e.get('pid'):
                hits.append(e)
        if not hits:
            continue
        # Heuristic scoring
        score = 0
        reasons = []
        for h in hits:
            et = h.get('event_type','')
            if et in ('open','openat') and (h.get('path') or '').endswith('docker.sock'):
                score += 40
                reasons.append('docker_sock_access')
            if et in ('ptrace','process_vm_writev'):
                score += 50
                reasons.append('process_injection')
            if et == 'execve' and (h.get('cmdline') or '').startswith('/tmp'):
                score += 30
                reasons.append('suspicious_exec_tmp')
        # Combine with missing-root-ca weight
        score += 30
        mitre = sorted({t for r in reasons for t in _MITRE_MAP.get(r, [])})
        cvss_base = max([_CVSS_BASE.get(r, 5.0) for r in reasons] or [5.0])
        dread = None
        severity = None
        if compute_dread and severity_from_dread:
            try:
                base = {'damage': 6, 'reproducibility': 6, 'exploitability': 6, 'affected_users': 5, 'discoverability': 6}
                if 'process_injection' in reasons:
                    base['damage'] += 2
                    base['exploitability'] += 2
                if 'docker_sock_access' in reasons:
                    base['damage'] += 2
                    base['affected_users'] += 2
                dread_score = compute_dread(base)
                dread = {'score': dread_score, **base}
                severity = severity_from_dread(dread_score)
            except Exception:
                dread = None
                severity = None
        correlated.append({
            'missing_event': m,
            'ebpf_hits': hits,
            'score': score,
            'reasons': reasons,
            'mitre': mitre,
            'cvss_base': cvss_base,
            'dread': dread,
            'severity': severity,
        })
    return correlated
