import json
from pathlib import Path

from src.core.correlation.rules.recon_weaponization_enriched import (
    recon_port_scan_burst_enriched,
    recon_dns_enumeration_enriched,
    weaponization_sandbox_malicious_enriched,
    weaponization_yara_match_enriched,
)

DATA_DIR = Path(__file__).parent / "data"


def _load(name: str) -> dict:
    return json.loads((DATA_DIR / name).read_text(encoding="utf-8"))


def test_recon_port_scan_burst_fixture():
    event = _load("recon_port_scan_burst_event.json")
    assert recon_port_scan_burst_enriched(event) is True


def test_recon_dns_enum_fixture():
    event = _load("recon_dns_enumeration_event.json")
    assert recon_dns_enumeration_enriched(event) is True


def test_weaponization_sandbox_fixture():
    event = _load("weaponization_sandbox_verdict_event.json")
    assert weaponization_sandbox_malicious_enriched(event) is True


def test_weaponization_yara_fixture():
    event = _load("weaponization_yara_match_event.json")
    assert weaponization_yara_match_enriched(event) is True
