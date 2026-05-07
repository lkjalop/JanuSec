"""Tests for framework_mapper enrichment: affected_data synthesis, Unknown TTPs keyword,
control register regulatory triggers."""
import os
os.environ.setdefault('PLATFORM_LITE_INIT', '1')
os.environ.setdefault('DISABLE_DB', '1')

import pytest
from src.analysis.framework_mapper import (
    _synthesize_affected_data_from_techniques,
    build_control_failure_register,
    _infer_mitre_from_cluster,
)


# ── _synthesize_affected_data_from_techniques ─────────────────────────────────

class TestSynthesizeAffectedData:
    def test_no_classes_when_no_techniques(self):
        narrative = {}
        _synthesize_affected_data_from_techniques(narrative, [], None)
        assert narrative.get('affected_data', {}).get('classes') is None

    def test_exfil_techniques_add_exfiltrated_data(self):
        narrative = {}
        _synthesize_affected_data_from_techniques(narrative, ['T1537', 'T1567.002'], None)
        classes = narrative['affected_data']['classes']
        assert 'exfiltrated_data' in classes

    def test_credential_techniques_add_credentials(self):
        narrative = {}
        _synthesize_affected_data_from_techniques(narrative, ['T1003.001'], None)
        assert 'credentials' in narrative['affected_data']['classes']

    def test_users_plus_cred_techniques_add_employee_pii(self):
        narrative = {'affected_principals': {'users': ['alice', 'bob']}}
        _synthesize_affected_data_from_techniques(narrative, ['T1003.001', 'T1537'], None)
        classes = narrative['affected_data']['classes']
        assert 'employee_pii' in classes

    def test_no_employee_pii_without_users(self):
        narrative = {}
        _synthesize_affected_data_from_techniques(narrative, ['T1003.001', 'T1537'], None)
        classes = narrative.get('affected_data', {}).get('classes', [])
        assert 'employee_pii' not in classes

    def test_cloud_plus_exfil_adds_financial(self):
        narrative = {}
        _synthesize_affected_data_from_techniques(
            narrative, ['T1552.005', 'T1078.004', 'T1537'], None
        )
        classes = narrative['affected_data']['classes']
        assert 'financial' in classes

    def test_no_overwrite_when_classes_already_present(self):
        narrative = {'affected_data': {'classes': ['existing_class']}}
        _synthesize_affected_data_from_techniques(narrative, ['T1537', 'T1003'], None)
        # Should not modify — already populated
        assert narrative['affected_data']['classes'] == ['existing_class']

    def test_sensitivity_critical_for_employee_pii(self):
        narrative = {'affected_principals': {'users': ['user1']}}
        _synthesize_affected_data_from_techniques(
            narrative, ['T1003.001', 'T1078', 'T1537'], None
        )
        assert narrative['affected_data']['sensitivity'] == 'critical'

    def test_sensitivity_high_for_credentials_only(self):
        narrative = {}
        _synthesize_affected_data_from_techniques(narrative, ['T1003.001'], None)
        assert narrative['affected_data']['sensitivity'] == 'high'

    def test_cluster_shared_users_triggers_employee_pii(self):
        narrative = {}
        cluster = {'shared_users': ['sophie.reid']}
        _synthesize_affected_data_from_techniques(
            narrative, ['T1003.001', 'T1078'], cluster
        )
        assert 'employee_pii' in narrative['affected_data']['classes']


# ── Unknown TTPs keyword in _CAP_TO_MITRE ────────────────────────────────────

class TestUnknownTTPsKeyword:
    """Alice DNS clusters have diamond.caps=['Unknown TTPs'] — must infer T1078."""

    def _make_cluster(self, caps: list, phases: list | None = None) -> dict:
        return {
            'tier1_prefill': {
                'diamond_model': {'capability': caps},
            },
            'phases': [{'name': p, 'case_role': 'c2'} for p in (phases or [])],
        }

    def test_unknown_ttps_infers_t1078(self):
        cluster = self._make_cluster(['Unknown TTPs'])
        techniques = _infer_mitre_from_cluster(cluster)
        assert 'T1078' in techniques

    def test_unknown_string_infers_t1078(self):
        cluster = self._make_cluster(['unknown activity'])
        techniques = _infer_mitre_from_cluster(cluster)
        assert 'T1078' in techniques

    def test_dns_beaconing_infers_t1071(self):
        cluster = self._make_cluster(['DNS beaconing'])
        techniques = _infer_mitre_from_cluster(cluster)
        assert any(t.startswith('T1071') for t in techniques)

    def test_lsass_keyword_infers_t1003(self):
        cluster = self._make_cluster(['LSASS memory access (credential harvest)'])
        techniques = _infer_mitre_from_cluster(cluster)
        assert 'T1003' in techniques or 'T1003.001' in techniques


# ── build_control_failure_register with synthesis ────────────────────────────

class TestBuildControlFailureRegisterSynthesis:
    """Regulatory triggers should fire when techniques imply employee PII."""

    def _santos_main_cluster(self) -> dict:
        return {
            'tier1_prefill': {
                'diamond_model': {'capability': [
                    'Rclone (cloud sync exfil)', 'LSASS memory access (credential harvest)',
                    'Snowflake COPY INTO (bulk data unload)', 'AWS GetSecretValue (secrets theft)',
                ]},
                'kill_chain_summary': 'Credential Theft > Snowflake Bulk Exfil',
            },
            'shared_users': ['sophie.reid', 'aaron.blackwood'],
        }

    def test_ndb_trigger_fires_for_exfil_with_users(self):
        cluster = self._santos_main_cluster()
        narrative = {
            'affected_principals': {'users': ['sophie.reid'], 'hosts': []},
            'verdict': 'VALIDATED_BREACH',
        }
        reg = build_control_failure_register(narrative, cluster=cluster)
        trigger_names = [t['name'] for t in reg.get('regulatory_triggers', [])]
        assert any('Privacy Act' in n or 'NDB' in n for n in trigger_names), \
            f"Expected NDB trigger, got: {trigger_names}"

    def test_alice_dns_unknown_ttps_gets_controls(self):
        cluster = {
            'tier1_prefill': {'diamond_model': {'capability': ['Unknown TTPs']}},
            'shared_users': ['azureuser'],
        }
        narrative = {
            'affected_principals': {'users': ['azureuser'], 'hosts': ['az-linux-01']},
            'verdict': 'VALIDATED_BREACH',
        }
        reg = build_control_failure_register(narrative, cluster=cluster)
        assert reg['failed_control_count'] > 0, "DNS cluster should have controls via T1078 fallback"

    def test_ndb_not_triggered_without_users(self):
        """IP-only cluster with no users should not trigger NDB."""
        cluster = {
            'tier1_prefill': {'diamond_model': {'capability': ['Unknown TTPs']}},
        }
        narrative = {'verdict': 'VALIDATED_BREACH'}
        reg = build_control_failure_register(narrative, cluster=cluster)
        trigger_names = [t['name'] for t in reg.get('regulatory_triggers', [])]
        assert not any('Privacy Act' in n for n in trigger_names), \
            "No users → no NDB trigger expected"

    def test_mitre_back_filled_into_narrative(self):
        cluster = self._santos_main_cluster()
        narrative = {'affected_principals': {'users': ['u1']}, 'verdict': 'VALIDATED_BREACH'}
        build_control_failure_register(narrative, cluster=cluster)
        assert narrative.get('mitre_techniques'), "Techniques should be back-filled into narrative"

    def test_no_crash_on_empty_inputs(self):
        reg = build_control_failure_register({})
        assert isinstance(reg, dict)
        assert reg['failed_control_count'] == 0
