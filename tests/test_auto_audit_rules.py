import json
import pathlib
import pytest

# Lazy import to avoid heavy package loading during pytest collection
def get_rules():
    from src.core.correlation.rules.registry import CORRELATION_RULES
    return CORRELATION_RULES


DATA_DIR = pathlib.Path(__file__).parent / "data" / "auto_audit"


def load_vector(name: str):
    p = DATA_DIR / name
    with p.open('r', encoding='utf-8') as fh:
        return json.load(fh)


@pytest.mark.parametrize(
    "vector,expected_rule",
    [
        ("office_macro_chain_docm.json", ("office_macro_spawn_powershell", "corr_office_macro_ps")),
        ("amsi_bypass_powershell_encoded.json", "corr_amsi_bypass"),
        ("ca_lsass_access_seq.json", "ca_lsass_access_seq"),
        ("pe_token_theft_combo.json", "pe_token_theft_combo"),
        ("filesystem_encryption_trigger.json", "filesystem_encryption_trigger"),
        ("registry_run_key.json", "corr_registry_run_keys"),
        ("new_service_nonstandard.json", ("corr_new_service_nonstandard_path", "corr_new_service_nonstandard")),
        ("imp_stop_security_services.json", "imp_stop_security_services"),
    ],
)
def test_auto_audit_vector_triggers_rule(vector, expected_rule):
    payload = load_vector(vector)
    # CORRELATION_RULES.evaluate returns list of matched rules (Rule objects) or []
    fired = get_rules().evaluate(payload)
    fired_names = [r.name for r in fired]
    if isinstance(expected_rule, (list, tuple)):
        assert any(e in fired_names for e in expected_rule), f"Expected one of {expected_rule} in {fired_names} for vector {vector}"
    else:
        assert expected_rule in fired_names, f"Expected {expected_rule} in {fired_names} for vector {vector}"


def test_ca_lsass_access_seq_auto():
    payload = load_vector('ca_lsass_access_seq.json')
    fired = get_rules().evaluate(payload)
    assert any(r.name == 'ca_lsass_access_seq' for r in fired)


def test_imp_stop_security_services_auto():
    payload = load_vector('imp_stop_security_services.json')
    fired = get_rules().evaluate(payload)
    assert any(r.name == 'imp_stop_security_services' for r in fired)


def test_cred_dump_lsass_trace_auto():
    payload = load_vector('cred_dump_lsass_trace.json')
    fired = get_rules().evaluate(payload)
    assert any(r.name == 'cred_dump_lsass_trace' for r in fired)


def test_filesystem_encryption_trigger_auto():
    payload = load_vector('filesystem_encryption_trigger.json')
    fired = get_rules().evaluate(payload)
    assert any(r.name == 'filesystem_encryption_trigger' for r in fired)


def test_registry_run_key_auto():
    payload = load_vector('registry_run_key.json')
    fired = get_rules().evaluate(payload)
    assert any(r.name == 'corr_registry_run_keys' for r in fired)


def test_new_service_nonstandard_auto():
    payload = load_vector('new_service_nonstandard.json')
    fired = get_rules().evaluate(payload)
    assert any(r.name in ('corr_new_service_nonstandard_path','corr_new_service_nonstandard') for r in fired)
