import json
from pathlib import Path
from src.core.correlation.rules.registry import CORRELATION_RULES


def load_vector(name):
    p = Path(__file__).parent / "data" / "top30" / f"{name}.json"
    return json.loads(p.read_text())


def test_exfil_stealth_cloud_metadata():
    evt = load_vector("exfil_stealth_cloud_metadata")
    matches = CORRELATION_RULES.evaluate(evt)
    assert any(r.id == "exfil_stealth_cloud_metadata" for r in matches)


def test_col_keylogger_detected_exfil_2():
    evt = load_vector("col_keylogger_detected_exfil_2")
    matches = CORRELATION_RULES.evaluate(evt)
    assert any(r.id == "col_keylogger_detected_exfil" for r in matches) or any(r.id == "col_keylogger_detected_exfil_2" for r in matches)


def test_discovery_dns_reverse_enum():
    evt = load_vector("discovery_dns_reverse_enum")
    matches = CORRELATION_RULES.evaluate(evt)
    assert any(r.id == "discovery_dns_reverse_enum" for r in matches)


def test_staged_payload_chain():
    evt = load_vector("staged_payload_chain")
    matches = CORRELATION_RULES.evaluate(evt)
    assert any(r.id == "staged_payload_chain" for r in matches)


def test_script_lateral_execution_by_wmi():
    evt = load_vector("script_lateral_execution_by_wmi")
    matches = CORRELATION_RULES.evaluate(evt)
    assert any(r.id == "script_lateral_execution_by_wmi" for r in matches)


def test_impostor_domain_beacon():
    evt = load_vector("impostor_domain_beacon")
    matches = CORRELATION_RULES.evaluate(evt)
    assert any(r.id == "impostor_domain_beacon" for r in matches)


def test_stealth_proc_injection_combo():
    evt = load_vector("stealth_proc_injection_combo")
    matches = CORRELATION_RULES.evaluate(evt)
    assert any(r.id == "stealth_proc_injection_combo" for r in matches)


def test_config_file_tamper():
    evt = load_vector("config_file_tamper")
    matches = CORRELATION_RULES.evaluate(evt)
    assert any(r.id == "config_file_tamper" for r in matches)


def test_lateral_ssh_sweep_internal():
    evt = load_vector("lateral_ssh_sweep_internal")
    matches = CORRELATION_RULES.evaluate(evt)
    assert any(r.id == "lateral_ssh_sweep_internal" for r in matches)


def test_supply_chain_downloader():
    evt = load_vector("supply_chain_downloader")
    matches = CORRELATION_RULES.evaluate(evt)
    assert any(r.id == "supply_chain_downloader" for r in matches)
