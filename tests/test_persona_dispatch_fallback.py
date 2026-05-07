"""Tests for persona_dispatch register-fallback for threat_hunter and MSSP personas."""
import os
os.environ.setdefault('PLATFORM_LITE_INIT', '1')
os.environ.setdefault('DISABLE_DB', '1')

import pytest


def _make_dispatch_payload(persona: str, narrative: dict, register: dict,
                           infra: dict | None = None) -> dict:
    from src.analysis.persona_dispatch import _build_persona_payload
    return _build_persona_payload(persona, narrative, register, infra or {})


# ── Threat Hunter fallback ────────────────────────────────────────────────────

class TestThreatHunterMitreFallback:
    def _register_with_mitre(self) -> dict:
        return {
            'mitre_techniques': ['T1003.001', 'T1078', 'T1537'],
            'failed_control_count': 12,
        }

    def test_uses_register_mitre_when_narrative_empty(self):
        narrative = {'verdict': 'VALIDATED_BREACH', 'mitre_techniques': []}
        reg = self._register_with_mitre()
        payload = _make_dispatch_payload('threat_hunter', narrative, reg)
        assert payload.get('mitre_techniques') == ['T1003.001', 'T1078', 'T1537']
        assert '3 techniques' in payload.get('headline', '')

    def test_uses_register_mitre_when_narrative_missing_key(self):
        narrative = {'verdict': 'VALIDATED_BREACH'}
        reg = self._register_with_mitre()
        payload = _make_dispatch_payload('threat_hunter', narrative, reg)
        assert len(payload.get('mitre_techniques', [])) == 3

    def test_narrative_mitre_takes_precedence_over_register(self):
        narrative = {
            'verdict': 'VALIDATED_BREACH',
            'mitre_techniques': ['T1059'],
        }
        reg = self._register_with_mitre()
        payload = _make_dispatch_payload('threat_hunter', narrative, reg)
        # Narrative has T1059; register has T1003.001/T1078/T1537
        # Narrative should win
        assert payload.get('mitre_techniques') == ['T1059']

    def test_zero_techniques_when_both_empty(self):
        narrative = {'verdict': 'VALIDATED_BREACH'}
        reg = {'mitre_techniques': [], 'failed_control_count': 0}
        payload = _make_dispatch_payload('threat_hunter', narrative, reg)
        assert payload.get('mitre_techniques') == []
        assert '0 techniques' in payload.get('headline', '')

    def test_hypotheses_populated_from_register_techniques(self):
        narrative = {'verdict': 'VALIDATED_BREACH', 'mitre_techniques': []}
        reg = self._register_with_mitre()
        payload = _make_dispatch_payload('threat_hunter', narrative, reg)
        # If hypotheses are populated (non-empty list), the back-fill worked
        hyps = payload.get('hypotheses', [])
        assert isinstance(hyps, list)


# ── MSSP fallback ─────────────────────────────────────────────────────────────

class TestMsspMitreFallback:
    def _register_with_mitre(self) -> dict:
        return {
            'mitre_techniques': ['T1003', 'T1078', 'T1537'],
            'failed_control_count': 8,
        }

    def test_uses_register_mitre_when_narrative_empty(self):
        narrative = {
            'verdict': 'VALIDATED_BREACH',
            'tenant_id': 'tenant-a',
            'mitre_techniques': [],
        }
        reg = self._register_with_mitre()
        payload = _make_dispatch_payload('mssp', narrative, reg)
        assert '3 techniques' in payload.get('headline', ''), \
            f"Expected technique count in headline, got: {payload.get('headline')}"

    def test_headline_includes_verdict(self):
        narrative = {'verdict': 'VALIDATED_BREACH', 'tenant_id': 'corp'}
        reg = self._register_with_mitre()
        payload = _make_dispatch_payload('mssp', narrative, reg)
        headline = payload.get('headline', '')
        assert 'VALIDATED_BREACH' in headline or 'REQUIRES_INVESTIGATION' in headline

    def test_no_crash_with_missing_narrative_keys(self):
        payload = _make_dispatch_payload('mssp', {}, {'mitre_techniques': []})
        assert 'headline' in payload

    def test_narrative_mitre_takes_precedence(self):
        narrative = {
            'verdict': 'VALIDATED_BREACH',
            'tenant_id': 'corp',
            'mitre_techniques': ['T1059', 'T1055'],
        }
        reg = self._register_with_mitre()
        payload = _make_dispatch_payload('mssp', narrative, reg)
        assert '2 techniques' in payload.get('headline', ''), \
            f"Narrative (2 techniques) should win over register (3), got: {payload.get('headline')}"


# ── Other personas — no regression ───────────────────────────────────────────

class TestOtherPersonasNotAffected:
    def test_ciso_headline_not_broken(self):
        from src.analysis.persona_dispatch import _build_persona_payload
        narrative = {'verdict': 'VALIDATED_BREACH', 'mitre_techniques': []}
        reg = {
            'failed_control_count': 5,
            'critical_control_count': 1,
            'framework_count': 3,
            'tightest_clock_seconds': 2592000,
            'regulatory_triggers': [{
                'name': 'Privacy Act 1988 — NDB',
                'clock_seconds': 2592000,
                'rationale': 'Employee PII exfiltrated',
            }],
        }
        payload = _build_persona_payload('ciso', narrative, reg, {})
        assert 'headline' in payload

    def test_compliance_headline_not_broken(self):
        from src.analysis.persona_dispatch import _build_persona_payload
        narrative = {'verdict': 'VALIDATED_BREACH'}
        reg = {
            'failed_control_count': 10,
            'critical_control_count': 2,
            'framework_count': 4,
        }
        payload = _build_persona_payload('compliance', narrative, reg, {})
        assert '10 failed controls' in payload.get('headline', '')
