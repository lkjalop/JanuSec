"""Simple correlation and tagging helpers for eBPF/kernel events.

This module provides mapping utilities to translate low-level kernel events
into higher-level detection tags (MITRE ATT&CK, STRIDE, DREAD/CVSS hints,
KEV/MAESTRO candidate markings) and suggests additional logs to collect.

It is intentionally small and deterministic to support unit testing.
"""
from __future__ import annotations

import hashlib
import json
from typing import Dict, List, Any

# Minimal mapping table: event -> MITRE/STRIDE factors and suggested severity hints
EVENT_MAP: Dict[str, Dict[str, Any]] = {
    # syscall attach or hook attempts on sensitive syscalls
    "kprobe_attach_sensitive": {
        "mitre": ["T1055", "T1218"],
        "stride": ["Elevation", "Tampering"],
        "dread_hint": {"damage": 6, "repro": 4, "exploit": 5},
        "suggested_logs": ["dmesg", "bpf_verifier", "process_ancestry"]
    },
    "bpf_verifier_reject": {
        "mitre": ["T1609"],
        "stride": ["Tampering"],
        "dread_hint": {"damage": 3, "repro": 2, "exploit": 1},
        "suggested_logs": ["bpf_verifier", "loader_logs"]
    },
    "unusual_execve_rate": {
        "mitre": ["T1059", "T1204"],
        "stride": ["Repudiation", "Elevation"],
        "dread_hint": {"damage": 5, "repro": 3, "exploit": 4},
        "suggested_logs": ["procfs_snapshot", "k8s_audit", "container_logs"]
    },
    "network_peer_rare_asn": {
        "mitre": ["T1041"],
        "stride": ["InformationDisclosure"],
        "dread_hint": {"damage": 4, "repro": 2, "exploit": 3},
        "suggested_logs": ["netflow", "conntrack", "dns_logs"]
    }
}


def score_dread(hint: Dict[str, int]) -> float:
    """Compute a simplified DREAD score (0-10) from a hint dict.

    Uses equal weights for components and normalizes to 10.
    """
    keys = ["damage", "repro", "exploit"]
    vals = [float(hint.get(k, 0)) for k in keys]
    # scale: assume hint values on 0-10 scale; average then return
    return sum(vals) / max(1.0, len(vals))


def map_event_to_tags(event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Map a low-level event to enriched tags and actions.

    Returns a dict with `mitre`, `stride`, `dread_score`, `cvss_guess`,
    `kev_tags`, and `suggested_logs`.
    """
    base = EVENT_MAP.get(event_type, {})
    mitre = base.get("mitre", [])
    stride = base.get("stride", [])
    dread_hint = base.get("dread_hint", {})
    dread_score = score_dread(dread_hint) if dread_hint else 0.0
    # naive CVSS guess from dread_score (map 0-10 -> 0-10 CVSS vector base score)
    cvss_guess = round(dread_score, 1)
    kev_tags: List[str] = []
    # KEV candidate heuristics: consult SBOM/enrichment helper when image present
    if payload.get("image"):
        try:
            from src.core import sbom_enrich as _sb
            vulns = _sb.lookup_image_vulns(payload.get('image'))
            vulns = _sb.mark_kev_candidates(vulns)
            for v in vulns:
                if v.get('kev_candidate'):
                    kev_tags.append(v.get('cve'))
            # attach back some vuln metadata for downstream
            payload['image_vulnerabilities'] = vulns
        except Exception:
            pass

    suggested_logs = list(base.get("suggested_logs", []))
    # add context-derived suggestions
    if payload.get("pid"):
        suggested_logs.append(f"proc:{payload.get('pid')}")

    # build fingerprint for deduping correlated alerts
    fingerprint = hashlib.sha256(json.dumps({"t": event_type, "p": payload}, sort_keys=True).encode('utf-8')).hexdigest()[:10]

    return {
        "event_type": event_type,
        "mitre": mitre,
        "stride": stride,
        "dread_score": dread_score,
        "cvss_guess": cvss_guess,
        "kev_tags": kev_tags,
        "suggested_logs": suggested_logs,
        "fingerprint": fingerprint,
    }


def correlate_batch(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Take a batch of low-level events and produce enriched correlation outputs."""
    out = []
    for ev in events:
        typ = ev.get('type') or ev.get('event_type')
        payload = ev.get('payload') or ev
        tags = map_event_to_tags(typ, payload)
        # include original payload and merge
        merged = {**tags, 'original': payload}
        out.append(merged)
    return out


def parse_falco_event(falco_json: Dict[str, Any]) -> Dict[str, Any]:
    """Parse Falco JSON event into our low-level event shape.

    Expects Falco fields like `rule`, `output`, `priority`, and `output_fields`.
    """
    rule = falco_json.get('rule') or falco_json.get('source')
    of = falco_json.get('output_fields') or {}
    # Heuristic mapping: translate some Falco rules into event_type keys
    if 'kprobe' in (rule or '').lower() or of.get('kprobe_attach'):
        et = 'kprobe_attach_sensitive'
    elif 'verifier' in (falco_json.get('output') or '').lower() or of.get('bpf_verifier'):
        et = 'bpf_verifier_reject'
    elif 'execve' in (falco_json.get('output') or '').lower():
        et = 'unusual_execve_rate'
    else:
        et = falco_json.get('priority') or 'unknown'

    payload = {
        'rule': rule,
        'output': falco_json.get('output'),
        'priority': falco_json.get('priority'),
        'source': falco_json.get('source'),
        'pid': of.get('proc.pid') or of.get('pid') or None,
        'proc_name': of.get('proc.name') or of.get('comm') or None,
        'container': of.get('container.id') or of.get('container') or None,
        'image': of.get('container.image') or of.get('image'),
        'extra': of,
    }
    return {'type': et, 'payload': payload}


def emit_incident(enriched: Dict[str, Any]) -> Dict[str, Any]:
    """Emit an incident using the local incident API if available.

    Falls back to returning the payload. Returns incident metadata or result.
    """
    # Attempt to use src.api.incidents or src.api.server helpers if present
    try:
        from src.api import server as _server
        if getattr(_server, 'create_incident', None):
            # The create_incident API shape may vary; use a minimal payload
            payload = {
                'title': f"Kernel event: {enriched.get('event_type')}",
                'description': enriched.get('original') or {},
                'tags': {'mitre': enriched.get('mitre', []), 'stride': enriched.get('stride', [])},
                'severity': enriched.get('cvss_guess', 0),
            }
            try:
                res = _server.create_incident(payload)
                return {'status': 'posted', 'result': res}
            except Exception:
                pass
    except Exception:
        pass
    # Fallback: return the enriched object for caller to persist
    return {'status': 'local', 'result': enriched}

