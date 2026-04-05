from __future__ import annotations
import time, sys

from src.correlation.dispatcher import correlate
import src.metrics.correlation_impact as impact

def _reset_metrics():
    sys.modules.pop('src.metrics.correlation_impact', None)
    import src.metrics.correlation_impact as ci  # noqa: F401

def test_correlation_impact_tp_only(monkeypatch):
    _reset_metrics()
    import src.metrics.correlation_impact as ci
    host = 'impactH1'
    base = time.time()
    correlate({'host':host,'ts':base}, ['endpoint:rare_lineage'])
    correlate({'host':host,'ts':base+1}, ['endpoint:lsass_access'])
    correlate({'host':host,'ts':base+2}, ['net:beacon_periodic'], had_tp=True, had_fp=False)
    if getattr(ci,'correlation_tp_only_total', None):
        assert ci.correlation_tp_only_total._value.get() >= 1  # type: ignore

def test_correlation_impact_fp_only(monkeypatch):
    _reset_metrics()
    import src.metrics.correlation_impact as ci
    host = 'impactH2'
    base = time.time()
    correlate({'host':host,'ts':base}, ['endpoint:rare_lineage'])
    correlate({'host':host,'ts':base+1}, ['endpoint:lsass_access'])
    correlate({'host':host,'ts':base+2}, ['net:beacon_periodic'], had_tp=False, had_fp=True)
    if getattr(ci,'correlation_fp_only_total', None):
        assert ci.correlation_fp_only_total._value.get() >= 1  # type: ignore

def test_correlation_impact_neutral(monkeypatch):
    _reset_metrics()
    import src.metrics.correlation_impact as ci
    host = 'impactNeutral'
    base = time.time()
    correlate({'host':host,'ts':base}, ['endpoint:rare_lineage'])
    correlate({'host':host,'ts':base+1}, ['endpoint:lsass_access'])
    correlate({'host':host,'ts':base+2}, ['net:beacon_periodic'], had_tp=False, had_fp=False)
    if getattr(ci,'correlation_neutral_context_total', None):
        assert ci.correlation_neutral_context_total._value.get() >= 1  # type: ignore

def test_correlation_impact_tp_and_fp(monkeypatch):
    _reset_metrics()
    import src.metrics.correlation_impact as ci
    host = 'impactBoth'
    base = time.time()
    correlate({'host':host,'ts':base}, ['endpoint:rare_lineage'])
    correlate({'host':host,'ts':base+1}, ['endpoint:lsass_access'])
    correlate({'host':host,'ts':base+2}, ['net:beacon_periodic'], had_tp=True, had_fp=True)
    # Both TP and FP context increments generic context counters (not *_only_)
    if getattr(ci,'correlation_tp_context_total', None):
        assert ci.correlation_tp_context_total._value.get() >= 1  # type: ignore
    if getattr(ci,'correlation_fp_context_total', None):
        assert ci.correlation_fp_context_total._value.get() >= 1  # type: ignore
