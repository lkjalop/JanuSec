from __future__ import annotations

from typing import Any, Dict, List

from .registry import register_rule


def _emit(event: Dict[str, Any], rule: str, mitre: List[str], score: float, evidence: Dict[str, Any]) -> None:
    event.setdefault('correlation_emission', {})
    event['correlation_emission'].update({
        'rule': rule,
        'mitre': mitre,
        'computed_score': round(min(max(score, 0.0), 0.99), 3),
        'evidence': evidence,
    })


@register_rule(
    name='recon_port_scan_burst_enriched',
    mitre=['T1595'],
    factors_required=['src_ip'],
    window_seconds=300,
    severity='high',
    confidence_boost=0.4,
)
def recon_port_scan_burst_enriched(event: Dict[str, Any]) -> bool:
    scan_rate = float(event.get('scan_rate') or 0.0)
    unique_ports = int(event.get('unique_ports') or 0)
    unique_hosts = int(event.get('unique_hosts') or 0)
    if scan_rate >= 25 or unique_ports >= 20 or unique_hosts >= 20:
        _emit(
            event,
            'recon_port_scan_burst_enriched',
            ['T1595'],
            0.8,
            {'scan_rate': scan_rate, 'unique_ports': unique_ports, 'unique_hosts': unique_hosts},
        )
        return True
    return False


@register_rule(
    name='recon_dns_enumeration_enriched',
    mitre=['T1046'],
    factors_required=['dns_query_count'],
    window_seconds=900,
    severity='medium',
    confidence_boost=0.3,
)
def recon_dns_enumeration_enriched(event: Dict[str, Any]) -> bool:
    dns_q = int(event.get('dns_query_count') or 0)
    unique_domains = int(event.get('unique_domains') or 0)
    if dns_q >= 200 or unique_domains >= 50:
        _emit(
            event,
            'recon_dns_enumeration_enriched',
            ['T1046'],
            0.7,
            {'dns_query_count': dns_q, 'unique_domains': unique_domains},
        )
        return True
    return False


@register_rule(
    name='weaponization_sandbox_malicious_enriched',
    mitre=['T1204'],
    factors_required=['sandbox_verdict'],
    window_seconds=86400,
    severity='high',
    confidence_boost=0.45,
)
def weaponization_sandbox_malicious_enriched(event: Dict[str, Any]) -> bool:
    verdict = str(event.get('sandbox_verdict') or '').lower()
    score = float(event.get('sandbox_score') or 0.0)
    if verdict in {'malicious', 'suspicious'} or score >= 0.7:
        _emit(
            event,
            'weaponization_sandbox_malicious_enriched',
            ['T1204'],
            0.85,
            {'sandbox_verdict': verdict, 'sandbox_score': score},
        )
        return True
    return False


@register_rule(
    name='weaponization_yara_match_enriched',
    mitre=['T1027'],
    factors_required=['yara_hits'],
    window_seconds=86400,
    severity='medium',
    confidence_boost=0.35,
)
def weaponization_yara_match_enriched(event: Dict[str, Any]) -> bool:
    hits = event.get('yara_hits') or event.get('yara_match') or []
    if isinstance(hits, str):
        hits = [hits]
    if isinstance(hits, list) and hits:
        _emit(
            event,
            'weaponization_yara_match_enriched',
            ['T1027'],
            0.7,
            {'yara_hits': hits[:5]},
        )
        return True
    return False
