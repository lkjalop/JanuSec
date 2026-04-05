from __future__ import annotations

from typing import Any, Dict

from ..registry import register_rule


def _has(event: Dict[str, Any], factor: str) -> bool:
    try:
        return factor in (event.get('factors') or [])
    except Exception:
        return False


@register_rule(
    name='ebpf_sensitive_file_write_egress',
    mitre=['T1222', 'T1041'],  # File Permissions Modification, Exfiltration
    factors_required=['egress_volume_spike'],
    window_seconds=600,
    severity='high',
    confidence_boost=0.45,
)
def sensitive_file_write_plus_egress(event: Dict[str, Any]) -> bool:
    """Sensitive file access (e.g., /etc/shadow) combined with outbound egress spike."""
    # Accept either Falco rule hint or command touching /etc/*
    rule = str(event.get('rule_name') or '').lower()
    cmd = str(event.get('command') or event.get('cmdline') or '').lower()
    sensitive_touch = ('shadow' in cmd or 'passwd' in cmd or 'write below' in rule or 'etc' in cmd)
    if sensitive_touch and _has(event, 'egress_volume_spike'):
        return True
    return False


@register_rule(
    name='ebpf_pkg_install_followed_by_shell',
    mitre=['T1059'],  # Command and Scripting Interpreter
    factors_required=['falco_rule:terminal_shell_in_container'],
    window_seconds=900,
    severity='medium',
    confidence_boost=0.25,
)
def package_install_then_shell(event: Dict[str, Any]) -> bool:
    """Detect package manager usage followed by an interactive shell inside container."""
    cmd = str(event.get('command') or '').lower()
    pkg_mgr = any(x in cmd for x in ('apt-get install', 'apt install', 'yum install', 'dnf install', 'apk add', 'pip install', 'npm install'))
    rule = str(event.get('rule_name') or '').lower()
    shell = ('shell' in rule) or any(x in cmd for x in ('/bin/bash', '/bin/sh'))
    return bool(pkg_mgr and shell)


@register_rule(
    name='ebpf_program_load_detected',
    mitre=['T1562'],  # Impair Defenses (approximation for kernel/eBPF tampering)
    factors_required=['falco_rule:bpf_program_loaded'],
    window_seconds=1800,
    severity='high',
    confidence_boost=0.4,
)
def ebpf_prog_load(event: Dict[str, Any]) -> bool:
    """Detect loading of eBPF programs (possible rootkit/stealth hooks)."""
    rule = str(event.get('rule_name') or '').lower()
    if 'bpf' in rule and 'load' in rule:
        return True
    # Fallback: syscall evidence
    sysc = str(event.get('syscall') or '').lower()
    if sysc == 'bpf':
        return True
    return False

