from __future__ import annotations

from typing import Any, Dict

from ..registry import register_rule


def _has_factor(event: Dict[str, Any], name: str) -> bool:
    try:
        factors = event.get('factors') or []
        if isinstance(factors, (list, tuple)):
            return any(str(f) == name for f in factors)
    except Exception:
        pass
    return False


@register_rule(
    name='ebpf_container_escape_egress',
    mitre=['T1610', 'T1041'],  # Deploy Container, Exfiltration Over C2
    factors_required=['ebpf:container_escape', 'egress_volume_spike'],
    window_seconds=300,
    severity='critical',
    confidence_boost=0.6,
)
def container_escape_with_egress(event: Dict[str, Any]) -> bool:
    """Container escape followed by outbound egress spike.

    Triggers when the event already carries both factors (same-event correlation)
    or the egress heuristic is visible directly on the event payload.
    """
    if _has_factor(event, 'ebpf:container_escape') and _has_factor(event, 'egress_volume_spike'):
        return True
    # Heuristic: prioritize Falco eBPF source and large bytes_out
    try:
        if (event.get('source') == 'falco_ebpf') and _has_factor(event, 'ebpf:container_escape'):
            out = float(event.get('bytes_out') or event.get('http_bytes_out') or 0.0)
            if out >= 10_000_000:  # 10MB as a coarse demo threshold
                return True
    except Exception:
        pass
    return False


@register_rule(
    name='ebpf_terminal_shell_container',
    mitre=['T1059'],  # Command and Scripting Interpreter
    factors_required=['falco_rule:terminal_shell'],
    window_seconds=600,
    severity='high',
    confidence_boost=0.3,
)
def terminal_shell_in_container(event: Dict[str, Any]) -> bool:
    """Correlate Falco rule name for terminal shell in container to MITRE T1059."""
    rule = str(event.get('rule_name') or '').lower()
    if not rule and isinstance(event.get('falco'), dict):
        try:
            rule = str(event['falco'].get('rule') or '').lower()
        except Exception:
            rule = ''
    return bool(rule and 'terminal shell' in rule)

