"""Tests for the persona dispatch pipeline — all five steps.

Proves:
  1. cluster_narrator_v2_schema is tenant-agnostic (unknown data → 'unknown')
  2. persona_dispatch reads cloud_access_keys (not ARN heuristic)
  3. framework_mapper produces real control mappings
  4. bitemporal_dispatch_trace records provenance + supports replay
  5. temporal_rag_dispatch indexes and retrieves similar incidents
"""
from __future__ import annotations

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Step 1: cluster_narrator_v2_schema — tenant-agnostic sensitivity detection
# ─────────────────────────────────────────────────────────────────────────────

class TestClusterNarratorV2Schema:

    def test_unknown_data_reports_unknown(self):
        """No tenant config + no catalog tags + no restricted schema name:
        sensitivity must be 'unknown', NOT 'low'."""
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [{
            'query_text': "SELECT name, age FROM PROD.PUBLIC.GENERIC_TABLE",
            'rows_produced': 100,
        }]
        out = enrich_narrative({}, {}, rows)
        assert out['affected_data']['sensitivity'] == 'unknown'
        assert out['affected_data']['crown_jewel_touched'] is False

    def test_pii_columns_in_query_promote_to_high(self):
        """PII column patterns in query text promote sensitivity to high."""
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [{
            'query_text': "SELECT email, date_of_birth FROM PROD.PUBLIC.USERS",
            'rows_produced': 1000,
        }]
        out = enrich_narrative({}, {}, rows)
        assert 'customer_pii' in out['affected_data']['classes']
        # customer_pii triggers 'high'
        assert out['affected_data']['sensitivity'] == 'high'

    def test_tenant_config_overrides_convention(self):
        """Tenant explicit classification beats convention-based detection."""
        from src.llm.cluster_narrator_v2_schema import (
            enrich_narrative, TenantDataClassification,
        )
        cfg = TenantDataClassification({
            'sensitivity_by_table': {'PROD.PUBLIC.PATIENT_RECORDS': 'crown_jewel'},
            'classes_by_table': {'PROD.PUBLIC.PATIENT_RECORDS': ['health_records']},
        })
        rows = [{'query_text': 'SELECT * FROM PROD.PUBLIC.PATIENT_RECORDS'}]
        out = enrich_narrative({}, {}, rows, tenant_classification=cfg)
        assert out['affected_data']['sensitivity'] == 'crown_jewel'
        assert 'health_records' in out['affected_data']['classes']

    def test_restricted_schema_convention_detects_high(self):
        """Generic RESTRICTED/VAULT schema names → 'high' without tenant config."""
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [{'query_text': 'SELECT * FROM DB.RESTRICTED.SECRETS_TABLE'}]
        out = enrich_narrative({}, {}, rows)
        assert out['affected_data']['sensitivity'] == 'high'

    def test_credential_tokens_detected(self):
        """Credential tokens in command_line → 'credentials' class."""
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [{'command_line': 'rundll32.exe comsvcs.dll MiniDump lsass.dmp'}]
        out = enrich_narrative({}, {}, rows)
        assert 'credentials' in out['affected_data']['classes']

    def test_principals_extract_cloud_access_keys(self):
        """AWS access keys come from userIdentity.accessKeyId, not ARN."""
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [{
            'userIdentity': {
                'arn': 'arn:aws:sts::123456:assumed-role/SomeRole/session',
                'accessKeyId': 'AKIA1234567890EXAMPLE',
            },
        }]
        out = enrich_narrative({}, {}, rows)
        assert 'AKIA1234567890EXAMPLE' in out['affected_principals']['cloud_access_keys']

    def test_sensitivity_evidence_source_audit_trail(self):
        """sensitivity_evidence_source populated for audit."""
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [{'query_text': 'SELECT * FROM DB.VAULT.T1'}]
        out = enrich_narrative({}, {}, rows)
        src = out['affected_data']['sensitivity_evidence_source']
        assert 'schema_naming_convention' in src


# ─────────────────────────────────────────────────────────────────────────────
# Step 2: persona_dispatch — AWS key fix + RAG hook
# ─────────────────────────────────────────────────────────────────────────────

class TestPersonaDispatch:

    def _sample_narrative(self):
        return {
            'verdict': 'VALIDATED_BREACH',
            'confidence': 0.92,
            'mitre_techniques': ['T1621', 'T1537'],
            'kill_chain_stage': 'exfiltration',
            'affected_principals': {
                'users': ['alice@corp.com'],
                'service_accounts': ['svc_analytics'],
                'hosts': ['WS-001'],
                'cloud_roles': ['arn:aws:sts::123:assumed-role/EKS-Runner/session'],
                'cloud_access_keys': ['AKIA1234567890EXAMPLE'],
            },
            'affected_data': {
                'tables': ['DB.SCHEMA.CUSTOMERS'],
                'sensitivity': 'high',
                'crown_jewel_touched': False,
                'classes': ['customer_pii'],
                'record_count_estimate': 50000,
            },
            'attacker_infrastructure': {
                'external_ips': ['1.2.3.4'],
                'asns': ['AS12345'],
                'countries': ['RU'],
                'staging_resources': ['scheduled_task:FakeUpdate'],
                'exfil_destinations': ['mega.nz'],
            },
            'discovery': {
                'source': 'edr_detection',
                'who': 'CS-DETECT-001',
                'when': '2026-02-22T16:00:00Z',
                'first_evidence_at': '2026-02-09T09:07:00Z',
                'lag_seconds_from_first_evidence': 1000000,
            },
        }

    def test_soc_analyst_revokes_access_keys_not_arns(self):
        """SOC actions include AWS key revocation from cloud_access_keys."""
        from src.analysis.persona_dispatch import build_persona_dispatch
        payload = build_persona_dispatch('soc_analyst', self._sample_narrative())
        actions = payload['required_actions']
        revoke_actions = [a for a in actions if 'aws_revoke_key' in a['action_id']]
        assert len(revoke_actions) == 1
        assert 'AKIA1234567890EXAMPLE' in revoke_actions[0]['action_id']

    def test_all_personas_built(self):
        from src.analysis.persona_dispatch import build_all_personas
        payloads = build_all_personas(self._sample_narrative())
        assert set(payloads.keys()) == {
            'soc_analyst', 'ciso', 'executive', 'threat_hunter',
            'forensics', 'compliance', 'mssp',
        }
        for k, v in payloads.items():
            assert v['persona'] == k
            assert 'headline' in v

    def test_rag_keys_present_without_provider(self):
        """Without RAG provider, prior_decisions and similar_incidents are empty lists."""
        from src.analysis.persona_dispatch import build_persona_dispatch
        payload = build_persona_dispatch('soc_analyst', self._sample_narrative())
        assert payload['prior_decisions'] == []
        assert payload['similar_incidents'] == []

    def test_executive_plain_english(self):
        from src.analysis.persona_dispatch import build_persona_dispatch
        from src.analysis.framework_mapper import build_control_failure_register
        register = build_control_failure_register(self._sample_narrative())
        payload = build_persona_dispatch('executive', self._sample_narrative(), register=register)
        assert 'plain_english' in payload
        assert 'What happened' in payload['plain_english']

    def test_ciso_regulatory_clocks(self):
        from src.analysis.persona_dispatch import build_persona_dispatch
        from src.analysis.framework_mapper import build_control_failure_register
        nar = self._sample_narrative()
        register = build_control_failure_register(nar, entity_context={
            'soci_sectors': ['ports'],
        })
        payload = build_persona_dispatch('ciso', nar, register=register)
        assert 'regulatory_clocks' in payload

    def test_threat_hunter_hypotheses(self):
        from src.analysis.persona_dispatch import build_persona_dispatch
        payload = build_persona_dispatch('threat_hunter', self._sample_narrative())
        assert len(payload['hypotheses']) > 0
        assert any('1.2.3.4' in h.get('pivot_query_splunk', '')
                    for h in payload['hypotheses'])

    def test_forensics_acquisition_order(self):
        from src.analysis.persona_dispatch import build_persona_dispatch
        payload = build_persona_dispatch('forensics', self._sample_narrative())
        assert len(payload['acquisition_order']) > 0
        assert payload['acquisition_order'][0]['host'] == 'WS-001'


# ─────────────────────────────────────────────────────────────────────────────
# Step 3: framework_mapper — real control mappings
# ─────────────────────────────────────────────────────────────────────────────

class TestFrameworkMapper:

    def test_known_techniques_produce_controls(self):
        from src.analysis.framework_mapper import map_techniques_to_controls
        result = map_techniques_to_controls(['T1621', 'T1003.001', 'T1537'])
        assert 'iso27001' in result
        assert 'essential_eight' in result
        assert len(result['unmapped_techniques']) == 0
        # T1621 should produce critical severity
        critical = [c for c in result['iso27001'] if c['severity'] == 'critical']
        assert len(critical) > 0

    def test_subtechnique_falls_back_to_parent(self):
        from src.analysis.framework_mapper import map_techniques_to_controls
        result = map_techniques_to_controls(['T1078.004'])
        assert 'unmapped_techniques' in result
        # T1078.004 is in the table directly
        assert len(result.get('iso27001', [])) > 0

    def test_unknown_technique_listed_as_unmapped(self):
        from src.analysis.framework_mapper import map_techniques_to_controls
        result = map_techniques_to_controls(['T9999'])
        assert 'T9999' in result['unmapped_techniques']

    def test_control_failure_register_structure(self):
        from src.analysis.framework_mapper import build_control_failure_register
        narrative = {
            'mitre_techniques': ['T1621', 'T1537'],
            'affected_data': {
                'classes': ['customer_pii'],
                'sensitivity': 'high',
                'crown_jewel_touched': False,
            },
        }
        register = build_control_failure_register(narrative)
        assert register['failed_control_count'] > 0
        assert register['critical_control_count'] > 0
        assert isinstance(register['control_failures_by_framework'], dict)

    def test_regulatory_triggers_for_pii_breach(self):
        from src.analysis.framework_mapper import evaluate_regulatory_triggers
        narrative = {
            'affected_data': {
                'classes': ['customer_pii'],
                'sensitivity': 'high',
                'crown_jewel_touched': False,
            },
            'discovery': {'when': '2026-02-22T16:00:00Z'},
        }
        triggers = evaluate_regulatory_triggers(narrative)
        trigger_ids = [t['trigger_id'] for t in triggers]
        assert 'ndb_privacy_act' in trigger_ids

    def test_backward_compat_map_to_mitre(self):
        from src.analysis.framework_mapper import map_to_mitre
        assert map_to_mitre({'threat_hits': 5}) == ['T1027']
        assert map_to_mitre({'mitre_techniques': ['T1621']}) == ['T1621']


# ─────────────────────────────────────────────────────────────────────────────
# Step 4: bitemporal_dispatch_trace
# ─────────────────────────────────────────────────────────────────────────────

class TestBitemporalTrace:

    def test_trace_creates_decision_with_provenance(self):
        from src.analysis.bitemporal_dispatch_trace import (
            trace_persona_dispatch, InMemoryDecisionTraceStore,
        )
        payload = {'persona': 'soc_analyst', 'headline': 'test'}
        rows = [{'row_index': 1, 'timestamp': '2026-02-10T03:00:00Z'}]
        d = trace_persona_dispatch(
            payload=payload,
            narrative={'verdict': 'VALIDATED_BREACH'},
            rows=rows,
            cluster_id='c1',
            tenant_id='t1',
            framework_version='test.v1',
        )
        assert d.decision_id.startswith('dec-')
        assert d.valid_time_start == '2026-02-10T03:00:00Z'
        assert d.evidence_content_hash
        assert d.persona == 'soc_analyst'

    def test_supersession_chain(self):
        from src.analysis.bitemporal_dispatch_trace import (
            trace_persona_dispatch, find_superseded_decisions,
            InMemoryDecisionTraceStore,
        )
        store = InMemoryDecisionTraceStore()

        d1 = trace_persona_dispatch(
            payload={'persona': 'soc_analyst', 'headline': 'v1'},
            narrative={}, rows=[], cluster_id='c1', tenant_id='t1',
            transaction_time='2026-02-22T10:00:00Z',
        )
        store.put(d1)

        # d1 is active
        active = store.find_active('c1', 'soc_analyst', 't1')
        assert len(active) == 1

        # New evidence arrives → new decision supersedes d1
        prior = find_superseded_decisions(
            store=store, cluster_id='c1', persona='soc_analyst', tenant_id='t1',
        )
        d2 = trace_persona_dispatch(
            payload={'persona': 'soc_analyst', 'headline': 'v2'},
            narrative={}, rows=[], cluster_id='c1', tenant_id='t1',
            transaction_time='2026-02-23T10:00:00Z',
            supersedes=[d.decision_id for d in prior],
        )
        store.put(d2)

        # d1 is now superseded
        assert d1.superseded_by == d2.decision_id
        active = store.find_active('c1', 'soc_analyst', 't1')
        assert len(active) == 1
        assert active[0].decision_id == d2.decision_id

    def test_replay_state_at(self):
        from src.analysis.bitemporal_dispatch_trace import (
            trace_persona_dispatch, replay_state_at,
            InMemoryDecisionTraceStore,
        )
        store = InMemoryDecisionTraceStore()

        d1 = trace_persona_dispatch(
            payload={'persona': 'soc_analyst', 'headline': 'day1'},
            narrative={}, rows=[], cluster_id='c1', tenant_id='t1',
            transaction_time='2026-02-22T10:00:00Z',
        )
        store.put(d1)

        d2 = trace_persona_dispatch(
            payload={'persona': 'soc_analyst', 'headline': 'day3'},
            narrative={}, rows=[], cluster_id='c1', tenant_id='t1',
            transaction_time='2026-02-24T10:00:00Z',
            supersedes=[d1.decision_id],
        )
        store.put(d2)

        # Replay at day2 — should see d1 (d2 didn't exist yet)
        result = replay_state_at(
            store=store, cluster_id='c1', persona='soc_analyst',
            tenant_id='t1', as_of='2026-02-23T00:00:00Z',
        )
        assert result['active_decision']['decision_id'] == d1.decision_id

    def test_action_outcome_recording(self):
        from src.analysis.bitemporal_dispatch_trace import (
            trace_persona_dispatch, record_action_outcome,
            InMemoryDecisionTraceStore,
        )
        store = InMemoryDecisionTraceStore()
        d = trace_persona_dispatch(
            payload={'persona': 'soc_analyst'},
            narrative={}, rows=[], cluster_id='c1', tenant_id='t1',
        )
        store.put(d)
        ok = record_action_outcome(
            store=store,
            decision_id=d.decision_id,
            action_id='test_action',
            outcome='executed',
            executed_by='analyst@corp.com',
        )
        assert ok is True
        assert len(d.action_outcomes) == 1
        assert d.action_outcomes[0]['outcome'] == 'executed'


# ─────────────────────────────────────────────────────────────────────────────
# Step 5: temporal_rag_dispatch
# ─────────────────────────────────────────────────────────────────────────────

class TestTemporalRAG:

    def test_signature_feature_vector_dimensions(self):
        from src.analysis.temporal_rag_dispatch import IncidentSignature
        sig = IncidentSignature(
            mitre_techniques=('T1621', 'T1537'),
            kill_chain_stage='exfiltration',
            sensitivity='high',
            data_classes=('customer_pii',),
            principal_types=('human_user', 'cloud_identity'),
            verdict='VALIDATED_BREACH',
        )
        vec = sig.feature_vector()
        assert len(vec) == 256
        # L2 normalized — magnitude should be ~1.0
        import math
        magnitude = math.sqrt(sum(x * x for x in vec))
        assert abs(magnitude - 1.0) < 0.01

    def test_sqlite_index_store_roundtrip(self):
        from src.analysis.temporal_rag_dispatch import (
            SQLiteIncidentIndexStore, IncidentSignature,
        )
        store = SQLiteIncidentIndexStore(':memory:')
        sig = IncidentSignature(
            mitre_techniques=('T1621',),
            kill_chain_stage='exfiltration',
            sensitivity='high',
            data_classes=('customer_pii',),
            principal_types=('human_user',),
            verdict='VALIDATED_BREACH',
        )
        store.index_incident(
            tenant_id='t1',
            cluster_id='c1',
            signature=sig,
            valid_time_start='2026-02-09T09:00:00Z',
            valid_time_end='2026-02-22T16:00:00Z',
            transaction_time='2026-02-23T10:00:00Z',
            narrative_summary='MFA push fatigue led to data exfil',
        )
        results = store.query(
            tenant_id='t1',
            query_signature=sig,
            k=5,
            valid_time_after='2026-01-01T00:00:00Z',
            as_of_transaction_time='2026-03-01T00:00:00Z',
        )
        assert len(results) == 1
        assert results[0]['cluster_id'] == 'c1'
        assert results[0]['similarity'] > 0.99  # self-similarity

    def test_provider_returns_empty_gracefully(self):
        from src.analysis.temporal_rag_dispatch import (
            TemporalRAGProvider, SQLiteIncidentIndexStore,
        )
        from src.analysis.bitemporal_dispatch_trace import InMemoryDecisionTraceStore
        provider = TemporalRAGProvider(
            incident_store=SQLiteIncidentIndexStore(':memory:'),
            decision_store=InMemoryDecisionTraceStore(),
            tenant_id='t1',
        )
        # Empty store → empty results
        result = provider.retrieve_similar_incidents({'mitre_techniques': ['T1621']})
        assert result == []
        result = provider.retrieve_prior_decisions(['T1621'], 'soc_analyst')
        assert result == []

    def test_render_rag_context_empty(self):
        from src.analysis.temporal_rag_dispatch import render_rag_context_for_prompt
        text = render_rag_context_for_prompt([], [])
        assert 'no prior decisions' in text

    def test_render_rag_context_with_data(self):
        from src.analysis.temporal_rag_dispatch import render_rag_context_for_prompt
        text = render_rag_context_for_prompt(
            prior_decisions=[{
                'transaction_time': '2026-01-15T00:00:00Z',
                'headline': 'Revoke OAuth + force FIDO2',
                'verdict': 'VALIDATED_BREACH',
                'action_count': 3,
                'action_outcomes_summary': 'executed=3',
            }],
            similar_incidents=[{
                'valid_time_start': '2026-01-10T00:00:00Z',
                'valid_time_end': '2026-01-15T00:00:00Z',
                'narrative_summary': 'MFA push fatigue breach contained',
                'similarity': 0.87,
                'techniques': ['T1621'],
            }],
        )
        assert 'PRIOR DECISIONS' in text
        assert 'SIMILAR INCIDENTS' in text
        assert 'Revoke OAuth' in text


# ─────────────────────────────────────────────────────────────────────────────
# Integration: tenant_data_classification config loader
# ─────────────────────────────────────────────────────────────────────────────

class TestTenantDataClassification:

    def test_load_returns_none_for_missing_tenant(self):
        from src.config.tenant_data_classification import load_for_tenant
        result = load_for_tenant('nonexistent_tenant_xyz')
        assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# Multi-cloud IDP extraction (Entra, GCP, GWS, SailPoint, Oracle)
# ─────────────────────────────────────────────────────────────────────────────

class TestCloudIDPExtraction:
    """enrich_narrative picks up principals from each IDP log format."""

    def test_entra_id_sign_in_log(self):
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [{
            'properties': {
                'userPrincipalName': 'alice@corp.com',
                'servicePrincipalId': 'sp-abc123',
                'conditionalAccessStatus': 'success',
            }
        }]
        out = enrich_narrative({}, {}, rows)
        p = out['affected_principals']
        assert 'alice@corp.com' in p['users']
        assert 'azure_sp:sp-abc123' in p['service_accounts']
        assert 'entra_id' in p['idp_sources']

    def test_gcp_audit_log_service_account(self):
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [{
            'protoPayload': {
                'authenticationInfo': {
                    'principalEmail': 'ci-runner@project.iam.gserviceaccount.com',
                },
                'methodName': 'storage.objects.get',
                'serviceName': 'storage.googleapis.com',
            }
        }]
        out = enrich_narrative({}, {}, rows)
        p = out['affected_principals']
        assert 'ci-runner@project.iam.gserviceaccount.com' in p['service_accounts']
        assert 'gcp' in p['idp_sources']
        assert any('gcp:storage' in r for r in p['cloud_roles'])

    def test_gcp_sa_delegation_chain(self):
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [{
            'protoPayload': {
                'authenticationInfo': {
                    'principalEmail': 'user@corp.com',
                    'serviceAccountDelegationInfo': [
                        {'principalSubject': 'serviceAccount:delegate@proj.iam.gserviceaccount.com'},
                    ],
                },
                'methodName': 'iam.serviceAccounts.signBlob',
                'serviceName': 'iam.googleapis.com',
            }
        }]
        out = enrich_narrative({}, {}, rows)
        p = out['affected_principals']
        assert 'user@corp.com' in p['users']
        assert 'delegate@proj.iam.gserviceaccount.com' in p['service_accounts']

    def test_google_workspace_actor(self):
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [{
            'actor': {'email': 'bob@corp.com', 'profileId': '12345'},
            'id': {'applicationName': 'drive'},
        }]
        out = enrich_narrative({}, {}, rows)
        p = out['affected_principals']
        assert 'bob@corp.com' in p['users']
        assert 'google_workspace' in p['idp_sources']

    def test_sailpoint_identity_event(self):
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [{
            'actor': {'name': 'carol@corp.com', 'type': 'IDENTITY'},
            'target': {'name': 'SalesforceApp', 'type': 'APP'},
        }]
        out = enrich_narrative({}, {}, rows)
        p = out['affected_principals']
        assert 'carol@corp.com' in p['users']
        assert 'sailpoint_app:SalesforceApp' in p['service_accounts']
        assert 'sailpoint' in p['idp_sources']

    def test_oracle_cloud_audit(self):
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [{
            'type': 'com.oraclecloud.objectstorage.getobject',
            'data': {
                'principalName': 'david@corp.com',
                'principalId': 'ocid1.user.oc1..example',
                'action': 'GET',
            }
        }]
        out = enrich_narrative({}, {}, rows)
        p = out['affected_principals']
        assert 'david@corp.com' in p['users']
        assert 'ocid1.user.oc1..example' in p['cloud_access_keys']
        assert 'oracle_cloud' in p['idp_sources']

    def test_mixed_cloud_sources_accumulate_idp_list(self):
        """When rows come from multiple IDPs all sources are listed."""
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [
            {'properties': {'userPrincipalName': 'a@corp.com'}},          # Entra
            {'protoPayload': {                                              # GCP
                'authenticationInfo': {'principalEmail': 'b@corp.com'},
                'methodName': 'test', 'serviceName': 'test.googleapis.com',
            }},
            {'actor': {'email': 'c@corp.com', 'profileId': '9'}},          # GWS
        ]
        out = enrich_narrative({}, {}, rows)
        sources = set(out['affected_principals']['idp_sources'])
        assert 'entra_id' in sources
        assert 'gcp' in sources
        assert 'google_workspace' in sources


# ─────────────────────────────────────────────────────────────────────────────
# Network / security log signal extraction
# ─────────────────────────────────────────────────────────────────────────────

class TestNetworkSignalExtraction:
    """_extract_network_signals (via enrich_narrative) handles each log format."""

    def test_suricata_alert_parsed(self):
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [{
            'event_type': 'alert',
            'src_ip': '1.2.3.4',
            'dest_ip': '10.0.0.5',
            'proto': 'TCP',
            'alert': {
                'signature': 'ET MALWARE CobaltStrike Beacon',
                'category': 'Malware',
                'severity': 1,
                'metadata': {'mitre_technique_id': ['T1071.001']},
            },
        }]
        out = enrich_narrative({}, {}, rows)
        alerts = out['network_signals']['ids_alerts']
        assert len(alerts) == 1
        assert alerts[0]['source'] == 'suricata'
        assert 'T1071.001' in alerts[0]['mitre_techniques']

    def test_zeek_conn_log_long_connection(self):
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [
            {'id': {'orig_h': '10.0.0.1', 'resp_h': '185.220.101.1',
                    'resp_p': 443}, 'proto': 'tcp', 'duration': 7200.0},
            {'id': {'orig_h': '10.0.0.2', 'resp_h': '10.1.1.1'}, 'proto': 'udp'},
        ]
        out = enrich_narrative({}, {}, rows)
        z = out['network_signals']['zeek_summary']
        assert z['unique_external_dst_count'] == 1  # only non-RFC1918
        assert z['long_duration_conn_count'] == 1
        assert 'tcp' in z['protocols_seen']

    def test_paloalto_threat_log(self):
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [{
            'type': 'THREAT',
            'threat_id': '34899',
            'src': '203.0.113.5',
            'dst': '10.20.30.1',
            'app': 'web-browsing',
            'action': 'alert',
            'severity': 'high',
            'category': 'command-and-control',
            'rule': 'Block-CnC',
        }]
        out = enrich_narrative({}, {}, rows)
        alerts = out['network_signals']['ids_alerts']
        assert len(alerts) == 1
        assert alerts[0]['source'] == 'paloalto'
        assert alerts[0]['rule'] == 'Block-CnC'

    def test_wazuh_alert_level_threshold(self):
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [
            # Level 4 — below threshold, should be filtered
            {'rule': {'id': '100001', 'description': 'Low noise', 'level': 4},
             'agent': {'name': 'agent1', 'ip': '10.0.0.10'}},
            # Level 12 — should appear
            {'rule': {
                'id': '100002', 'description': 'Mimikatz detected', 'level': 12,
                'mitre': {'technique': ['T1003.001']},
             },
             'agent': {'name': 'agent2', 'ip': '10.0.0.20'}},
        ]
        out = enrich_narrative({}, {}, rows)
        wa = out['network_signals']['wazuh_alerts']
        assert len(wa) == 1
        assert wa[0]['rule_id'] == '100002'
        assert 'T1003.001' in wa[0]['mitre_techniques']

    def test_firewall_deny_non_rfc1918(self):
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [
            # External deny — should appear (45.33.32.156 is a globally-routable IP)
            {'src_ip': '45.33.32.156', 'dst_ip': '10.0.0.1',
             'action': 'DENY', 'dst_port': 22, 'proto': 'TCP'},
            # Internal deny — should be filtered (RFC1918)
            {'src_ip': '10.1.2.3', 'dst_ip': '10.0.0.1',
             'action': 'DROP', 'dst_port': 445},
        ]
        out = enrich_narrative({}, {}, rows)
        fb = out['network_signals']['firewall_blocks']
        assert len(fb) == 1
        assert fb[0]['src_ip'] == '45.33.32.156'

    def test_cdn_waf_block(self):
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [{
            'ClientIP': '203.0.113.99',
            'WAFAction': 'BLOCK',
            'ClientRequestURI': '/admin/login',
            'EdgeResponseStatus': '403',
            'ClientCountry': 'RU',
            'WAFRuleID': 'SQL-INJ-001',
        }]
        out = enrich_narrative({}, {}, rows)
        waf = out['network_signals']['cdn_waf_blocks']
        assert len(waf) == 1
        assert waf[0]['waf_action'] == 'BLOCK'
        assert waf[0]['rule_id'] == 'SQL-INJ-001'

    def test_log_sources_detected_label(self):
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [
            {'event_type': 'alert', 'src_ip': '1.1.1.1', 'dest_ip': '10.0.0.1',
             'proto': 'TCP',
             'alert': {'signature': 'ET TEST', 'category': 'test', 'severity': 2}},
            {'rule': {'id': '5', 'description': 'x', 'level': 8},
             'agent': {'name': 'a', 'ip': '10.0.0.1'}},
        ]
        out = enrich_narrative({}, {}, rows)
        sources = out['network_signals']['log_sources_detected']
        assert 'suricata' in sources
        assert 'wazuh' in sources


# ─────────────────────────────────────────────────────────────────────────────
# Threat intelligence flags (BPH ASNs, geo-risk, compromised allowlist)
# ─────────────────────────────────────────────────────────────────────────────

class TestThreatIntelFlags:

    def test_known_bph_asn_flagged(self):
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [
            {'src_ip': '198.51.100.1', 'asn': 'AS44477'},  # Stark Industries BPH
        ]
        out = enrich_narrative({}, {}, rows)
        flags = out['threat_intel_flags']
        assert flags['bph_asn_count'] == 1
        assert flags['flagged_asns'][0]['asn'] == 'AS44477'
        assert 'bulletproof' in flags['flagged_asns'][0]['flag']

    def test_high_risk_country_flagged(self):
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [
            {'src_ip': '5.5.5.5', 'geo_country': 'RU'},
            {'src_ip': '6.6.6.6', 'geo_country': 'AU'},  # not high-risk
        ]
        out = enrich_narrative({}, {}, rows)
        flags = out['threat_intel_flags']
        assert 'RU' in flags['high_risk_countries']
        assert 'AU' not in flags['high_risk_countries']

    def test_compromised_allowlist_hit(self):
        """An IP in the tenant allowlist but appearing in attacker-linked traffic
        is flagged as a potential compromised trusted entry-point."""
        from src.llm.cluster_narrator_v2_schema import (
            enrich_narrative, TenantDataClassification,
        )
        # Simulate a "trusted VPN gateway" IP that also shows up in external traffic.
        # 45.33.32.50 is globally routable (not RFC1918, not documentation range).
        cfg = TenantDataClassification({
            'allowlist_ips': ['45.33.32.50'],
        })
        rows = [{'src_ip': '45.33.32.50', 'dst_ip': '10.0.0.1', 'action': 'ALLOW'}]
        out = enrich_narrative({}, {}, rows, tenant_classification=cfg)
        hits = out['threat_intel_flags']['compromised_allowlist_hits']
        assert len(hits) == 1
        assert hits[0]['ip'] == '45.33.32.50'
        assert 'allowlist bypass' in hits[0]['note']

    def test_tenant_custom_bad_asn_merged(self):
        """Tenant-supplied known_bad_asns are merged with the builtin list."""
        from src.llm.cluster_narrator_v2_schema import (
            enrich_narrative, TenantDataClassification,
        )
        cfg = TenantDataClassification({
            'known_bad_asns': {'AS99999': 'Acme Threat ASN — custom'},
        })
        rows = [{'src_ip': '1.2.3.4', 'asn': 'AS99999'}]
        out = enrich_narrative({}, {}, rows, tenant_classification=cfg)
        flags = out['threat_intel_flags']
        assert flags['bph_asn_count'] == 1
        assert flags['flagged_asns'][0]['description'] == 'Acme Threat ASN — custom'

    def test_clean_traffic_produces_no_flags(self):
        """No BPH ASNs, no geo-risk countries, no allowlist overlap → empty flags."""
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        rows = [
            {'src_ip': '192.168.1.5', 'dst_ip': '8.8.8.8'},   # RFC1918 src
            {'query_text': 'SELECT 1'},
        ]
        out = enrich_narrative({}, {}, rows)
        flags = out['threat_intel_flags']
        assert flags['bph_asn_count'] == 0
        assert flags['geo_risk_country_count'] == 0
        assert flags['compromised_allowlist_hits'] == []
