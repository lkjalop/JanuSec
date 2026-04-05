import json
from src.core.correlation.rules.registry import CORRELATION_RULES

def _load_vec(name):
    p = f'tests/data/top50/{name}.json'
    with open(p, 'r', encoding='utf-8') as f:
        return json.load(f)


def test_top50_rules_registered_and_fire():
    rules = [
        'suspicious_rundll32_usage', 'one_drive_unauthorized_sync', 'staged_scripts_in_temp',
        'suspicious_certutil_usage', 'wevtutil_clear_events', 'autorun_registry_persistence',
        'suspicious_schtasks_create', 'powershell_encoded_command', 'suspicious_at_command',
        'netstat_listening_high_ports'
    ]
    registered = {r.name for r in CORRELATION_RULES.list()}
    for r in rules:
        assert r in registered, f'{r} not registered'

    # positive vectors
    assert CORRELATION_RULES.evaluate(_load_vec('vec_suspicious_rundll32'))[0]
    assert CORRELATION_RULES.evaluate(_load_vec('vec_onedrive_unauth'))[0]
    assert CORRELATION_RULES.evaluate(_load_vec('vec_staged_scripts_temp'))[0]
    assert CORRELATION_RULES.evaluate(_load_vec('vec_certutil'))[0]
    assert CORRELATION_RULES.evaluate(_load_vec('vec_wevtutil'))[0]
    assert CORRELATION_RULES.evaluate(_load_vec('vec_autorun_registry'))[0]
    assert CORRELATION_RULES.evaluate(_load_vec('vec_schtasks'))[0]
    assert CORRELATION_RULES.evaluate(_load_vec('vec_powershell_enc'))[0]
    assert CORRELATION_RULES.evaluate(_load_vec('vec_at_command'))[0]
    assert CORRELATION_RULES.evaluate(_load_vec('vec_netstat_highport'))[0]
