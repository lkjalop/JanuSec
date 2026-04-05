from typing import Dict, Any, List

def analyze_behavior(declared_manifest: Dict[str, Any], runtime_report: Dict[str, Any]) -> Dict[str, Any]:
    """Compare declared behavior vs runtime observed behavior from sandbox.

    runtime_report example keys: network_calls, file_reads, spawned_processes
    """
    issues = []
    declared = declared_manifest or {}

    # Example checks
    if 'network' not in declared.get('capabilities', []) and runtime_report.get('network_calls'):
        issues.append({'factor': 'supply_chain:behavior_mismatch', 'score': 0.35, 'reason': 'unexpected_network'})

    if runtime_report.get('file_reads'):
        for f in runtime_report.get('file_reads'):
            if '/.ssh/' in f or '/root/' in f:
                issues.append({'factor': 'supply_chain:behavior_mismatch', 'score': 0.40, 'reason': 'sensitive_file_access', 'path': f})

    if runtime_report.get('spawned_processes'):
        for p in runtime_report.get('spawned_processes'):
            if 'curl' in p or 'wget' in p:
                issues.append({'factor': 'supply_chain:behavior_mismatch', 'score': 0.30, 'reason': 'spawned_downloader', 'process': p})

    total = sum(i.get('score', 0) for i in issues)
    return {'issues': issues, 'score': min(total, 1.0), 'verdict': 'suspicious' if total >= 0.25 else 'ok'}
