import os
from core.risk_score import compose_risk_score
from src.api.metrics_init import REGISTRY, ensure_metrics


def _read_counter_exact(name: str, labels: dict | None = None) -> float:
    """Read a counter value allowing for both family base names and *_total sample names.

    Accepts `name` as the fully qualified metric (often ending with _total). This reader will:
      - Sum samples where s.name == name
      - Also search the base family (name without _total) and sum samples where s.name == base + '_total'
    """
    total = 0.0
    base = name[:-6] if name.endswith('_total') else name
    for fam in REGISTRY.collect():
        if fam.name not in (name, base):
            continue
        for s in fam.samples:
            # Only consider the main counter series, skip *_created
            if s.name not in (name, f"{base}_total"):
                continue
            if labels is None or all(s.labels.get(k) == v for k, v in (labels or {}).items()):
                total += s.value
    return total


def test_time_of_day_contribution_and_metric(monkeypatch):
    # Enable feature and configure off-hours
    monkeypatch.setenv('RISK_TOD_FEATURE', '1')
    monkeypatch.setenv('RISK_TOD_OFFHOURS', '20-7')
    monkeypatch.setenv('RISK_TOD_WEIGHT', '0.08')
    tenant = 't1'
    # Pick a fixed UTC timestamp at 02:00 (off-hours for 20-7)
    ts_utc_2am = 1735687200.0  # 2025-01-01 02:00:00 UTC
    decision = {
        'event_id': 'evt-tod-1',
        'factors': [],
        'confidence': 1.0,
        'tenant_id': tenant,
        'ts': ts_utc_2am,
    }
    ensure_metrics()
    before = _read_counter_exact('janusec_risk_offhours_total', {'tenant_id': tenant})
    out = compose_risk_score(decision)
    after = _read_counter_exact('janusec_risk_offhours_total', {'tenant_id': tenant})
    # Validate breakdown contains off-hours factor
    assert any(b.get('factor') == 'context:off_hours' for b in out.get('breakdown', []))
    # Counter should increment by at least 1 for this tenant
    assert after >= before + 1.0


def test_role_profile_contribution_and_metric(monkeypatch):
    # Enable feature and set sensitive prefixes and role weights
    monkeypatch.setenv('RISK_ROLE_FEATURE', '1')
    monkeypatch.setenv('RISK_ROLE_SENSITIVE_PREFIXES', 'scenario:critical,scenario:high')
    monkeypatch.setenv('RISK_ROLE_WEIGHTS', 'user=0.1,contractor=0.15,service=0.05')
    tenant = 't2'
    decision = {
        'event_id': 'evt-role-1',
        'factors': ['scenario:critical_exec', 'net:beacon_periodic'],
        'confidence': 1.0,
        'tenant_id': tenant,
        'role': 'user',
        'ts': 1735687200.0,
    }
    ensure_metrics()
    before = _read_counter_exact('janusec_risk_role_mismatch_total', {'tenant_id': tenant})
    out = compose_risk_score(decision)
    after = _read_counter_exact('janusec_risk_role_mismatch_total', {'tenant_id': tenant})
    # Validate breakdown contains role-based factor
    assert any(b.get('factor') == 'role:user:sensitive_activity' for b in out.get('breakdown', []))
    # Counter should increment for this tenant
    assert after >= before + 1.0
