"""Sandbox adapter scaffold for lightweight behavioral probes (test-mode only).

Provides an interface to submit package artifacts or install scripts for sandboxing.
For production, integrate with Cuckoo / CAPE / commercial sandbox via connectors.

This module intentionally avoids executing untrusted binaries unless TEST_SANDBOX_ENABLED=1
and FAST_TEST_MODE is enabled.
"""
import os
import json
import tempfile
from typing import Dict, Any, List

TEST_ENABLED = os.getenv('TEST_SANDBOX_ENABLED','0').lower() in {'1','true','yes'}
FAST_TEST = os.getenv('FAST_TEST_MODE','0').lower() in {'1','true','yes'}


def submit_package_for_probe(package_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Submit a package (dict with name, version, install_script or data) for sandboxing.

    Returns a lightweight report dict.
    """
    # Safety: do not execute unless explicitly enabled in a test environment
    if not TEST_ENABLED or not FAST_TEST:
        return {'status': 'skipped', 'reason': 'sandbox_disabled'}
    try:
        # write install script to a temp file and run a lightweight analysis (no execution)
        scr = package_payload.get('install_script') or package_payload.get('setup_py') or ''
        report = {'package': package_payload.get('name'), 'version': package_payload.get('version'), 'findings': []}
        if scr:
            # heuristics: look for network calls, downloads, eval
            if 'curl' in scr or 'wget' in scr or 'subprocess' in scr:
                report['findings'].append({'type': 'suspicious_shell', 'detail': scr[:200]})
        # simulate a behavioral verdict
        report['verdict'] = 'suspicious' if report['findings'] else 'clean'
        return report
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def normalize_behavior(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert sandbox report into normalized factors for HopGraph indexing."""
    facs: List[Dict[str, Any]] = []
    pkg = report.get('package')
    ver = report.get('version')
    for f in report.get('findings') or []:
        t = f.get('type')
        if t == 'suspicious_shell':
            facs.append({'factor': 'sandbox:suspicious_shell', 'producer': 'sandbox', 'detail': f.get('detail'), 'target': pkg})
    if (report.get('verdict') or '') == 'suspicious':
        facs.append({'factor': 'sandbox:verdict_suspicious', 'producer': 'sandbox', 'target': pkg})
    return facs


__all__ = ['submit_package_for_probe', 'normalize_behavior']


__all__ = ['submit_package_for_probe']
