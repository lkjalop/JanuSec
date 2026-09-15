from __future__ import annotations
from typing import Any, Dict, List

PRODUCER = 'supply_chain_detectors'


def _lower(x: Any) -> str:
    try:
        return str(x or '').lower()
    except Exception:
        return ''


def detect_transitive_dependency_vuln(runtime) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if runtime is None:
        return out
    events = list(getattr(runtime, 'sanitized_events', []) or [])
    for ev in events:
        domain = _lower(ev.get('domain') or ev.get('source_type'))
        if 'sbom' not in domain and 'supply' not in domain:
            continue
        vulns = ev.get('vulnerabilities') or []
        if isinstance(vulns, list):
            crit = [v for v in vulns if str(v.get('severity') or '').lower() in {'critical','high'}]
            if crit:
                out.append({'factor':'supply_chain_transitive_vuln','score':0.8,'producer':PRODUCER,'count':len(crit)})
    return out


def detect_behavior_mismatch(runtime) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if runtime is None:
        return out
    events = list(getattr(runtime, 'sanitized_events', []) or [])
    for ev in events:
        signed = bool(ev.get('signed') or ev.get('signature_valid'))
        net = bool(ev.get('network') or ev.get('made_network_connection'))
        proc = _lower(ev.get('process') or ev.get('process_name'))
        if signed and net and proc:
            out.append({'factor':'supply_chain_behavior_mismatch','score':0.7,'producer':PRODUCER,'process':proc})
    return out


def detect_model_provenance(runtime) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if runtime is None:
        return out
    events = list(getattr(runtime, 'sanitized_events', []) or [])
    for ev in events:
        domain = _lower(ev.get('domain') or ev.get('source_type'))
        if domain != 'ai':
            continue
        src = _lower(ev.get('model_source') or '')
        if src and src not in {'trusted','first_party','verified'}:
            out.append({'factor':'ai_model_untrusted_source','score':0.65,'producer':PRODUCER,'model_source':src})
    return out

__all__ = ['detect_transitive_dependency_vuln','detect_behavior_mismatch','detect_model_provenance']
