"""Golden CEO-export contract: a VALIDATED_BREACH must produce a fully-populated report.

This is the net for the class of bug that made the report come back empty for a confirmed
breach: aggregate_decisions() classified `flagged_events` by verdict in
('review','escalate','suspicious') and silently dropped the breach verdicts
(validated_breach/likely_breach/...), so every framework rollup was blank. This contract
asserts the CEO-facing sections are all non-empty for a real breach.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("PLATFORM_LITE_INIT", "1")

# The detection factors a real VALIDATED_BREACH carries (must map to all frameworks).
_BREACH_FACTORS = [
    "iam:oauth_consent_excessive_scope",
    "discovery:ad_enumeration",
    "iam:kerberoasting",
    "iam:golden_ticket",
    "endpoint:wmi_lateral_exec",
    "exfil:cumulative_bytes_anomaly",
]


def _clear_all_decision_caches():
    # aggregate_decisions() merges DECISION_CACHE from several module objects (a symptom
    # of the import sprawl); clearing one leaves the others polluted. Clear them all so
    # this contract isn't flaky in-suite.
    import importlib
    for path in ("src.api.runtime_state", "src.api.server", "src.api.app", "api.runtime_state"):
        try:
            cache = getattr(importlib.import_module(path), "DECISION_CACHE", None)
            if cache is not None:
                cache.clear()
        except Exception:
            pass


@pytest.fixture()
def ceo_report():
    from fastapi.testclient import TestClient
    from src.api.server import app, _record_decision
    from tests._helpers import default_test_headers

    _clear_all_decision_caches()
    _record_decision("ceo-breach-1", "VALIDATED_BREACH", 0.95, _BREACH_FACTORS)
    client = TestClient(app)
    r = client.get(
        "/api/v1/report/ingestion?format=json&include_scenarios=true&include_model=true",
        headers=default_test_headers(),
    )
    assert r.status_code == 200, r.text
    return r.json()


def test_validated_breach_appears_in_flagged_events(ceo_report):
    fe = ceo_report.get("flagged_events") or []
    assert len(fe) >= 1, "VALIDATED_BREACH dropped from flagged_events (verdict-class bug)"
    assert any(str(e.get("verdict", "")).upper() == "VALIDATED_BREACH" for e in fe)


@pytest.mark.parametrize("section", [
    "kill_chain_phases", "top_stride", "maestro_phases", "controls_overview",
])
def test_ceo_framework_rollups_non_empty(ceo_report, section):
    val = ceo_report.get(section)
    assert val, f"CEO report section '{section}' is empty for a confirmed breach"


def test_scenario_summary_observed(ceo_report):
    assert (ceo_report.get("scenario_summary") or {}).get("observed_count", 0) >= 1


def test_kill_chain_covers_multiple_stages(ceo_report):
    # A multi-stage breach must narrate as multiple kill-chain stages, not one.
    stages = {p.get("phase") for p in (ceo_report.get("kill_chain_phases") or [])}
    assert len(stages) >= 3, f"kill chain too thin: {sorted(stages)}"
