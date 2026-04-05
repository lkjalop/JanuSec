from __future__ import annotations

from typing import Any

from .base import StageContext, StageResult


async def threat_intel_stage(event: dict[str, Any], ctx: StageContext) -> StageResult:
    """Threat Intel matching stage.

    - Checks common fields for IoC hits against the ThreatIntelClient.
    - Emits factor tags per type with conservative confidence deltas.
    - Honors client enablement; returns empty when disabled.
    """
    try:
        from src.integrations.threat_intel_client import CLIENT  # type: ignore
    except Exception:
        return StageResult(name='threat_intel', factors=[], confidence_delta=0.0)

    # If intel disabled, no-op
    try:
        if not getattr(CLIENT, 'enabled', True):
            return StageResult(name='threat_intel', factors=[], confidence_delta=0.0)
    except Exception:
        pass

    factors: list[str] = []
    delta_total = 0.0
    metadata: dict[str, Any] = {'hits': {}, 'techniques': {}, 'technique_provenance': {}}

    def _emit(f: str, inc: float):
        nonlocal delta_total
        factors.append(f)
        try:
            from src.core.factors.observe_flags import adjust_delta  # type: ignore
            delta_total += adjust_delta(f, inc)
        except Exception:
            delta_total += inc

    # Domain/url/ip/hash
    domain = (event.get('domain') or event.get('host') or event.get('dst_domain') or '')
    if isinstance(domain, str) and domain:
        try:
            if CLIENT.is_malicious_domain(domain):
                _emit('intel:domain_hit', 0.05)
                try:
                    origin = CLIENT.origin_for(domain)
                    conf = CLIENT.ioc_confidence('domain', str(domain).lower())
                    metadata['hits']['domain'] = {'value': domain, 'origin': origin, 'confidence': conf}
                except Exception:
                    pass
        except Exception:
            pass

    url = (event.get('url') or event.get('request_url') or '')
    if isinstance(url, str) and url:
        try:
            if getattr(CLIENT, 'is_malicious_url', lambda u: False)(url):
                _emit('intel:url_hit', 0.04)
                try:
                    origin = CLIENT.origin_for(url)
                    conf = CLIENT.ioc_confidence('url', str(url).lower())
                    metadata['hits']['url'] = {'value': url, 'origin': origin, 'confidence': conf}
                except Exception:
                    pass
        except Exception:
            pass

    ip = (event.get('ip') or event.get('dst_ip') or event.get('ip_dst') or event.get('remote_ip') or '')
    if isinstance(ip, str) and ip:
        try:
            if CLIENT.is_malicious_ip(ip):
                _emit('intel:ip_hit', 0.05)
                try:
                    origin = CLIENT.origin_for(ip)
                    conf = CLIENT.ioc_confidence('ip', str(ip).lower())
                    metadata['hits']['ip'] = {'value': ip, 'origin': origin, 'confidence': conf}
                except Exception:
                    pass
        except Exception:
            pass

    h = (event.get('sha256') or event.get('file_hash') or event.get('sha1') or event.get('md5') or '')
    if isinstance(h, str) and h:
        try:
            if CLIENT.is_malicious_hash(h):
                _emit('intel:hash_hit', 0.06)
                try:
                    origin = CLIENT.origin_for(h)
                    conf = CLIENT.ioc_confidence('hash', str(h).lower())
                    metadata['hits']['hash'] = {'value': h, 'origin': origin, 'confidence': conf}
                except Exception:
                    pass
        except Exception:
            pass

    # JA3 / Cert fingerprints (network TLS context)
    ja3 = (event.get('ja3') or event.get('ja4') or '')
    if isinstance(ja3, str) and ja3:
        try:
            if CLIENT.is_malicious_ja3(ja3):
                _emit('intel:ja3_hit', 0.05)
                try:
                    origin = CLIENT.origin_for(ja3)
                    conf = CLIENT.ioc_confidence('ja3', str(ja3).lower())
                    metadata['hits']['ja3'] = {'value': ja3, 'origin': origin, 'confidence': conf}
                except Exception:
                    pass
        except Exception:
            pass

    certfp = (event.get('cert_fingerprint') or event.get('tls_cert_fp') or event.get('certfp') or '')
    if isinstance(certfp, str) and certfp:
        try:
            if CLIENT.is_malicious_certfp(certfp):
                _emit('intel:certfp_hit', 0.05)
                try:
                    origin = CLIENT.origin_for(certfp)
                    conf = CLIENT.ioc_confidence('certfp', str(certfp).lower())
                    metadata['hits']['certfp'] = {'value': certfp, 'origin': origin, 'confidence': conf}
                except Exception:
                    pass
        except Exception:
            pass

    # Cap cumulative delta to avoid overweighting
    if delta_total > 0.12:
        scale = 0.12 / delta_total
        delta_total *= scale

    # Techniques mapping for richer explainability in correlator outputs
    try:
        metadata['techniques'] = CLIENT.techniques_for_factors(factors)
        metadata['technique_provenance'] = CLIENT.technique_provenance()
    except Exception:
        pass

    # Surface OSINT hits in event context so downstream rules can use them
    try:
        hits = metadata.get('hits') or {}
        if hits:
            event['threat_intel_hit'] = True
            event['threat_intel_hits'] = len(hits)
            event['threat_intel_types'] = list(hits.keys())
    except Exception:
        pass

    return StageResult(name='threat_intel', factors=factors, confidence_delta=round(delta_total, 4), metadata=metadata)
