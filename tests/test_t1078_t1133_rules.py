from __future__ import annotations
import pytest

from src.core.correlation.rules.registry import CORRELATION_RULES, set_fired_counter_for_tests
from prometheus_client import CollectorRegistry, Counter


def test_t1078_valid_accounts_fires_and_not_fires():
    # Inject a test counter to capture fires (avoid global registry issues)
    reg = CollectorRegistry(auto_describe=True)
    c = Counter('test_corr_fired_total','test', ['rule'], registry=reg)
    set_fired_counter_for_tests(c)

    # event that should fire: multiple auth successes from unusual source
    ev = {'auth_success_count': 6, 'src_unusual': True}
    fired = CORRELATION_RULES.evaluate(ev)
    names = [r.name for r in fired]
    assert 'ia_valid_accounts_t1078' in names

    # safe event: low count and not unusual
    ev2 = {'auth_success_count': 1, 'src_unusual': False}
    fired2 = CORRELATION_RULES.evaluate(ev2)
    names2 = [r.name for r in fired2]
    assert 'ia_valid_accounts_t1078' not in names2


def test_t1133_external_remote_fires_and_not_fires():
    reg = CollectorRegistry(auto_describe=True)
    c = Counter('test_corr_fired_total','test', ['rule'], registry=reg)
    set_fired_counter_for_tests(c)

    # event: AD group change + remote service access
    ev = {'ad_group_change': True, 'remote_service_access': True}
    fired = CORRELATION_RULES.evaluate(ev)
    names = [r.name for r in fired]
    assert 'ext_remote_services_t1133' in names

    # safe: remote service access but internal source and no group change
    ev2 = {'ad_group_change': False, 'remote_service_access': True, 'src_external': False}
    fired2 = CORRELATION_RULES.evaluate(ev2)
    names2 = [r.name for r in fired2]
    assert 'ext_remote_services_t1133' not in names2
