import json
from pathlib import Path
from src.core.correlation.rules.registry import CORRELATION_RULES


def load_vector(name):
    p = Path(__file__).parent / "data" / "top20" / f"{name}.json"
    return json.loads(p.read_text())


def test_c2_dns_tunnel_exfil():
    evt = load_vector("c2_dns_tunnel_exfil")
    matches = CORRELATION_RULES.evaluate(evt)
    assert any(r.id == "c2_dns_tunnel_exfil" for r in matches)


def test_defense_evasion_amsi_bypass_combo():
    evt = load_vector("defense_evasion_amsi_bypass_combo")
    matches = CORRELATION_RULES.evaluate(evt)
    assert any(r.id == "defense_evasion_amsi_bypass_combo" for r in matches)


def test_graph_lateral_chain_burst():
    evt = load_vector("graph_lateral_chain_burst")
    matches = CORRELATION_RULES.evaluate(evt)
    assert any(r.id == "graph_lateral_chain_burst" for r in matches)


def test_exec_office_macro_chain():
    evt = load_vector("exec_office_macro_chain")
    matches = CORRELATION_RULES.evaluate(evt)
    assert any(r.id == "exec_office_macro_chain" for r in matches)


def test_persistence_new_service_nonstandard():
    evt = load_vector("persistence_new_service_nonstandard")
    matches = CORRELATION_RULES.evaluate(evt)
    assert any(r.id == "persistence_new_service_nonstandard" for r in matches)


def test_c2_http_small_periodic_payload():
    evt = load_vector("c2_http_small_periodic_payload")
    matches = CORRELATION_RULES.evaluate(evt)
    assert any(r.id == "c2_http_small_periodic_payload" for r in matches)


def test_c2_ssl_odd_sni_beacon():
    evt = load_vector("c2_ssl_odd_sni_beacon")
    matches = CORRELATION_RULES.evaluate(evt)
    assert any(r.id == "c2_ssl_odd_sni_beacon" for r in matches)


def test_lateral_smb_admin_burst():
    evt = load_vector("lateral_smb_admin_burst")
    matches = CORRELATION_RULES.evaluate(evt)
    assert any(r.id == "lateral_smb_admin_burst" for r in matches)


def test_exfil_ftp_large_payload():
    evt = load_vector("exfil_ftp_large_payload")
    matches = CORRELATION_RULES.evaluate(evt)
    assert any(r.id == "exfil_ftp_large_payload" for r in matches)


def test_persistence_service_binary_change():
    evt = load_vector("persistence_service_binary_change")
    matches = CORRELATION_RULES.evaluate(evt)
    assert any(r.id == "persistence_service_binary_change" for r in matches)
