"""Endpoint-focused feature extractor for Sultry.

Provides helpers to summarize endpoint telemetry helpful for correlation: user diversity,
process distribution, and suspicious command patterns.
"""
from collections import Counter
from typing import List, Dict, Any


def summarize_endpoints(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summarize endpoint records (each record with `host`, `user`, `process`, `cmdline`)."""
    hosts = set()
    users = []
    procs = []
    cmd_indicators = 0
    for r in records:
        hosts.add(r.get('host') or r.get('hostname') or 'unknown')
        if r.get('user'):
            users.append(r.get('user'))
        if r.get('process'):
            procs.append(r.get('process'))
        cmd = (r.get('cmdline') or '')
        # crude heuristics for suspicious cmdline patterns
        if any(x in cmd.lower() for x in ['powershell', 'cmd.exe', 'wget', 'curl', 'bitsadmin']):
            cmd_indicators += 1

    return {
        'unique_hosts': len(hosts),
        'user_diversity': len(set(users)),
        'top_processes': Counter(procs).most_common(6),
        'suspicious_cmds': cmd_indicators,
    }


def correlate_with_network(endpoint_summary: Dict[str, Any], network_summary: Dict[str, Any]) -> Dict[str, Any]:
    """Simple correlation helper that combines endpoint and network summaries into signals.

    Returns combined keys useful to feed into Sultry scoring pipeline.
    """
    signals = {
        'hosts_vs_asns_ratio': (endpoint_summary.get('unique_hosts', 1) / max(1, network_summary.get('unique_asns', 1))),
        'nxdomain_rate': network_summary.get('nxdomain_rate', 0.0),
        'suspicious_cmds': endpoint_summary.get('suspicious_cmds', 0),
    }
    return signals
