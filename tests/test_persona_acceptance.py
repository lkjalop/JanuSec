"""Per-persona acceptance — each persona report must be non-empty AND carry its signature
actionable section.

Every persona shipped EMPTY when the verdict-classification bug dropped breaches from the
report, and unit tests were green. This locks each persona at the integration level: a
VALIDATED_BREACH must render that persona's distinctive, action-oriented content.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("PLATFORM_LITE_INIT", "1")

pytestmark = pytest.mark.acceptance

_BREACH_FACTORS = [
    "iam:oauth_consent_excessive_scope", "discovery:ad_enumeration", "iam:kerberoasting",
    "iam:golden_ticket", "endpoint:wmi_lateral_exec", "exfil:cumulative_bytes_anomaly",
]

# persona query value -> a signature section that MUST appear (lower-cased substring).
_PERSONA_SIGNATURE = {
    "soc_analyst":   "containment timeline",  # IOC TRIAGE is entity-conditional (grounding #1)
    "ciso":          "regulatory clock",
    "executive":     "what happened",
    "threat_hunter": "mitre att&ck coverage",
    "forensics":     "evidence acquisition order",
    "compliance":    "framework summary",
}


def _clear_caches():
    import importlib
    for path in ("src.api.runtime_state", "src.api.server", "src.api.app"):
        try:
            c = getattr(importlib.import_module(path), "DECISION_CACHE", None)
            if c is not None:
                c.clear()
        except Exception:
            pass


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from src.api.server import app
    return TestClient(app)


@pytest.mark.parametrize("persona,signature", sorted(_PERSONA_SIGNATURE.items()))
def test_persona_report_renders_signature_section(client, persona, signature):
    from src.api.server import _record_decision
    from tests._helpers import default_test_headers

    _clear_caches()
    _record_decision(f"persona-{persona}", "VALIDATED_BREACH", 0.95, _BREACH_FACTORS)
    r = client.get(
        f"/api/v1/report/ingestion?format=html&persona={persona}&include_scenarios=true",
        headers=default_test_headers(),
    )
    assert r.status_code == 200, r.text
    html = r.text.lower()
    assert len(html) > 800, f"{persona} report suspiciously small ({len(html)} chars)"
    assert signature in html, (
        f"{persona} report missing its signature section '{signature}' — persona render "
        f"regressed or the breach didn't reach it")
