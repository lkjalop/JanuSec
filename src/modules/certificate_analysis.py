"""Certificate analysis helpers (stub)

Provides a small analysis function that inspects certificate fields on an event and
returns factors and a delta. It mirrors parts of `network_hunter._analyze_cert` but
is separated to allow unit testing and clearer metrics.
"""
from __future__ import annotations
import time
from typing import Dict, Any, Tuple, List
try:
    # Lazy import to avoid heavy dependency in tests without DB
    from src.integrations import cert_checks as _cert_checks  # type: ignore
except Exception:  # pragma: no cover
    _cert_checks = None  # type: ignore
try:
    # Avoid creating CollectorRegistry-bound metrics at import time to prevent
    # duplicate registration in test runs. We'll obtain counters lazily via
    # the central metrics initializer when needed.
    from prometheus_client import Counter, Gauge  # type: ignore
except Exception:
    Counter = Gauge = None  # type: ignore

# Placeholders used for optional lazy increments; actual counters created via
# src.api.metrics_init.ensure_metrics() and _safe_counter() when incrementing.
certs_analyzed = None
certs_self_signed = None
certs_ct_suspected = None


def _ocsp_check_stub(cert_fp: str) -> bool:
    """Stub function for OCSP/CRL checks; returns True if revoked (stubbed False).

    In production this would perform OCSP queries or CRL lookups; here we keep
    it as a no-op to avoid network calls in tests.
    """
    return False


def _ct_log_check_stub(cert_fp: str) -> bool:
    """Stub CT log check; returns True if CT indicates suspicious (stubbed False).

    Real implementation would query CT logs (e.g., via certificate-transparency APIs).
    """
    return False


def analyze_cert(event: Dict[str, Any]) -> Tuple[List[str], float]:
    """Analyze certificate-related fields on `event`.

    Returns (factors, delta). Offers CT log & OCSP/CRL stubs and issuer reputation counters.
    """
    factors: List[str] = []
    delta = 0.0
    try:
        # Lazy safe metric increment
        try:
            from src.api.metrics_init import ensure_metrics, _safe_counter  # type: ignore
            try:
                ensure_metrics()
            except Exception:
                pass
            _safe_counter('cert_analysis_analyzed_total','Total cert analysis runs').inc()
        except Exception:
            pass
    except Exception:
        pass
    try:
        self_signed = event.get('cert_self_signed')
        if self_signed:
            factors.append('ssl:self_signed_cert')
            delta += 0.06
            try:
                try:
                    from src.api.metrics_init import ensure_metrics, _safe_counter  # type: ignore
                    try:
                        ensure_metrics()
                    except Exception:
                        pass
                    _safe_counter('cert_analysis_self_signed_total','Self-signed certs counted').inc()
                except Exception:
                    pass
            except Exception:
                pass
        # Expired certs
        not_after = event.get('cert_not_after')
        if isinstance(not_after, (int, float)) and float(not_after) < time.time():
            factors.append('ssl:expired_cert')
            delta += 0.05
        # Weak signature algorithm
        sig = (event.get('cert_sig_alg') or '').lower()
        if sig and any(x in sig for x in ('md5','sha1','rsa-md5','md2')):
            factors.append('ssl:weak_sig_algo')
            delta += 0.04
        # Short validity
        nb = event.get('cert_not_before')
        if isinstance(nb, (int,float)) and isinstance(not_after,(int,float)):
            validity = float(not_after) - float(nb)
            if validity > 0 and validity <= (30*24*3600):
                factors.append('ssl:short_validity')
                delta += 0.03
        # CT log & OCSP/CRL checks (stubs - optionally enabled by env vars)
        cert_fp = (event.get('cert_fp') or event.get('cert_fingerprint') or '')
        if cert_fp:
            # Enqueue for background CT/OCSP verification (async worker)
            try:
                if _cert_checks:
                    _cert_checks.queue_cert_check(cert_fp)
            except Exception:
                pass
            # Consume cached result if already present (low-latency path)
            try:
                if _cert_checks:
                    cached = _cert_checks.get_cert_check(cert_fp)
                    if cached and cached.get('status') in ('suspicious','revoked'):
                        details = cached.get('details','')
                        if 'ct' in details and 'ssl:ct_suspected' not in factors:
                            factors.append('ssl:ct_suspected'); delta += 0.04
                        if 'revoked' in details and 'ssl:revoked_cert' not in factors:
                            factors.append('ssl:revoked_cert'); delta += 0.08
            except Exception:
                pass
            # Fallback stub logic (only if no cached verdict yet)
            if not any(f in factors for f in ('ssl:ct_suspected','ssl:revoked_cert')):
                try:
                    try:
                        from src.api.metrics_init import ensure_metrics, _safe_counter  # type: ignore
                        try:
                            ensure_metrics()
                        except Exception:
                            pass
                        _safe_counter('cert_analysis_ct_suspected_total','Certs suspected by CT lookup').inc()
                    except Exception:
                        pass
                    factors.append('ssl:ct_suspected'); delta += 0.04
                except Exception:
                    pass
                try:
                    if _ocsp_check_stub(cert_fp):
                        factors.append('ssl:revoked_cert'); delta += 0.08
                except Exception:
                    pass
        # Issuer reputation: naive frequency counter in-memory per-process
        issuer = (event.get('cert_issuer') or '').strip().lower()
        if issuer:
            if not hasattr(analyze_cert, '_issuer_freq'):
                analyze_cert._issuer_freq = {}
            freq = analyze_cert._issuer_freq  # type: ignore
            freq[issuer] = freq.get(issuer, 0) + 1
            if freq[issuer] < 3:
                factors.append('ssl:rare_issuer'); delta += 0.03
        # SNI mismatch (subject CN/SAN mismatch) if provided
        try:
            sni = (event.get('sni') or event.get('server_name') or '')
            cn = (event.get('cert_subject') or '')
            san_list = event.get('cert_san_dns') or []
            sni_norm = str(sni).strip().lower()
            cn_norm = str(cn).strip().lower()
            san_dns = []
            if isinstance(san_list, (list, tuple)):
                san_dns = [str(x).lower() for x in san_list if isinstance(x, (str, bytes))]
            san_match = any(sni_norm == san or (san.startswith('*.') and sni_norm.endswith(san[1:])) for san in san_dns) if sni_norm else False
            if sni_norm and cn_norm and sni_norm not in cn_norm and cn_norm not in sni_norm and not san_match:
                if 'ssl:sni_mismatch' not in factors:
                    factors.append('ssl:sni_mismatch'); delta += 0.03
        except Exception:
            pass
    except Exception:
        pass
    # Cap total delta
    if delta > 0.20:
        delta = 0.20
    return factors, delta


__all__ = ['analyze_cert']


class CertificateAnalysis:
    """Thin wrapper exposing an async analyze_event for integration with the
    event pipeline. Keeps the previous class-based API while delegating to the
    analyze_cert helper for logic reuse.
    """
    def __init__(self, config=None):
        self.config = config

    async def analyze_event(self, event: dict) -> dict:
        # Delegate to the synchronous helper to keep tests deterministic and
        # avoid adding asyncio overhead inside unit tests.
        factors, delta = analyze_cert(event)
        return {'factors': factors, 'confidence_delta': delta}

__all__.extend(['CertificateAnalysis'])
