from typing import Dict, List, Any
from src.core.scoring.dread_engine import compute_dread, severity_from_dread
import random
import requests


def make_email_event(dkim_status: str = 'pass', has_logs: bool = True, factors: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    """Construct a mock email-type artifact for scoring."""
    if factors is None:
        factors = []
    artifact = {
        'type': 'email',
        'dkim_status': dkim_status,  # 'pass'|'fail'|'missing'
        'has_logs': bool(has_logs),
        'destination_ips': ['10.0.0.1'],
        'destination_ports': [],
        'business_tier': 'medium',
    }
    return artifact, factors


def evaluate_event(artifact: Dict[str, Any], factors: List[Dict[str, Any]] | None = None, dread_thresholds: Dict[str, float] | None = None) -> Dict[str, Any]:
    """Compute dread, severity, decide escalation, and whether to request logs."""
    if factors is None:
        factors = []
    # Normalize factor shapes: Accept [{name:..., value:...}] or simple dicts {key: value}
    norm = []
    for f in factors:
        if isinstance(f, dict) and ('name' in f or 'type' in f):
            norm.append(f)
        elif isinstance(f, dict):
            # convert keys into named factor entries
            for k, v in f.items():
                norm.append({'name': k, 'value': v})
        else:
            # unknown shape; pass through
            norm.append(f)
    factors = norm
    dread = compute_dread(artifact, factors)
    sev = severity_from_dread(dread.get('composite', 0.0), dread_thresholds)
    composite = dread.get('composite', 0.0)

    # Heuristic: missing/failed DKIM increases suspicion multiplier
    dk_multiplier = 1.0
    if artifact.get('dkim_status') == 'fail':
        dk_multiplier = 1.15
    elif artifact.get('dkim_status') == 'missing':
        dk_multiplier = 1.25

    adjusted = round(composite * dk_multiplier, 2)

    # Escalate if adjusted >= high threshold
    escalate = adjusted >= (dread_thresholds or {}).get('high', 6.0)

    # If logs missing and adjusted >= medium, ask for logs
    ask_for_logs = (not artifact.get('has_logs')) and (adjusted >= (dread_thresholds or {}).get('medium', 4.0))

    return {
        'artifact': artifact,
        'dread': dread,
        'severity': sev,
        'adjusted_composite': adjusted,
        'escalate': escalate,
        'ask_for_logs': ask_for_logs,
    }


def run_permutations(dkim_states: List[str] = None, log_states: List[bool] = None, factor_sets: List[List[Dict[str, Any]]] | None = None, dread_thresholds: Dict[str, float] | None = None) -> List[Dict[str, Any]]:
    if dkim_states is None:
        dkim_states = ['pass', 'fail', 'missing']
    if log_states is None:
        log_states = [True, False]
    if factor_sets is None:
        factor_sets = [
            [],
            [{'vulnerability_matches': [{'cvss': 8.5, 'exploit_available': True}]}],
            [{'scan_pattern': 'sequential', 'public_dns': True}],
            # high-severity scenario: multiple high-CVEs, prior exploits, public-facing
            [
                {
                    'vulnerability_matches': [
                        {'cvss': 9.0, 'exploit_available': True},
                        {'cvss': 8.8, 'exploit_available': True},
                    ],
                    'prior_exploit_count': 3,
                    'public_dns': True,
                    'public_facing': True,
                    'scan_pattern': 'sequential',
                    'hosts': 120,
                }
            ],
        ]

    results: List[Dict[str, Any]] = []
    for d in dkim_states:
        for l in log_states:
            for f in factor_sets:
                art, _ = make_email_event(dkim_status=d, has_logs=l, factors=f)
                # allow factor hint to inflate host counts for affected calculation
                if isinstance(f, list) and len(f) and isinstance(f[0], dict) and f[0].get('hosts'):
                    hosts = int(f[0].get('hosts'))
                    art['destination_ips'] = [f"10.0.0.{i}" for i in range(min(hosts, 1000))]
                res = evaluate_event(art, f, dread_thresholds)
                results.append(res)
    return results


def prewarm_ollama(model: str = 'llama3:8b') -> Dict[str, Any]:
    """Attempt to ping a local Ollama API to warm the model. No-op if unavailable."""
    try:
        # Ollama default port 11434; local API endpoint /models/{model}
        url = f'http://localhost:11434/models/{model}'
        resp = requests.get(url, timeout=1.0)
        return {'ok': True, 'status_code': resp.status_code}
    except Exception as e:
        return {'ok': False, 'error': str(e)}
