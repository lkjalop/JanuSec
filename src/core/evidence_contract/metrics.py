"""Operational telemetry for evidence custody and replay."""

from __future__ import annotations

try:
    from prometheus_client import Counter, Gauge

    EVIDENCE_APPEND = Counter(
        "janusec_evidence_ledger_append_total", "Evidence ledger appends", ["record_type", "result"]
    )
    EVIDENCE_OBJECT_WRITE = Counter(
        "janusec_evidence_object_write_total", "Immutable object writes", ["backend", "result"]
    )
    EVIDENCE_KERNEL_DEGRADED = Gauge("janusec_evidence_kernel_degraded", "1 when evidence custody is degraded")
except Exception:  # pragma: no cover

    class _Noop:
        def labels(self, *args, **kwargs):
            return self

        def inc(self, *args, **kwargs):
            return None

        def set(self, *args, **kwargs):
            return None

    EVIDENCE_APPEND = EVIDENCE_OBJECT_WRITE = EVIDENCE_KERNEL_DEGRADED = _Noop()


__all__ = ["EVIDENCE_APPEND", "EVIDENCE_KERNEL_DEGRADED", "EVIDENCE_OBJECT_WRITE"]
