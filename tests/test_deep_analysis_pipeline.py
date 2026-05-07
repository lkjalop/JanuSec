"""Tests for Tier 3 deep analysis: cross-source stitcher, sequence validator,
adversarial reasoner, and deep analysis orchestrator."""
from __future__ import annotations

import pytest


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _zeek_row(row_index: int, orig_h: str, resp_h: str, ts: str, user: str = '') -> dict:
    return {
        'row_index': row_index,
        'id.orig_h': orig_h,
        'id.resp_h': resp_h,
        'id_orig_h': orig_h,
        'id_resp_h': resp_h,
        '_source': 'zeek',
        'timestamp_utc': ts,
        'user': user,
        'description': 'zeek connection',
        'severity': 'medium',
    }


def _okta_row(row_index: int, actor: str, ip: str, ts: str) -> dict:
    return {
        'row_index': row_index,
        'actor_login': actor,
        'client_ipAddress': ip,
        '_source': 'okta',
        'timestamp_utc': ts,
        'description': 'okta authentication',
        'severity': 'high',
    }


def _sysmon_row(row_index: int, user: str, host: str, ts: str, event: str) -> dict:
    return {
        'row_index': row_index,
        'SubjectUserName': user,
        'ComputerName': host,
        '_source': 'sysmon',
        'timestamp_utc': ts,
        'Image': 'C:\\Windows\\System32\\lsass.exe',
        'description': event,
        'severity': 'high',
    }


def _make_cluster_with_rows():
    rows = [
        _zeek_row(0, '10.0.1.5', '203.0.113.50', '2026-01-15T10:00:00Z'),
        _okta_row(1, 'alice@corp.com', '10.0.1.5', '2026-01-15T10:00:30Z'),
        _sysmon_row(2, 'alice', 'workstation-01', '2026-01-15T10:02:00Z', 'credential access lsass'),
        _zeek_row(3, '10.0.1.5', '10.0.2.20', '2026-01-15T10:15:00Z', 'alice'),
        {'row_index': 4, '_source': 'sysmon', 'SubjectUserName': 'alice',
         'ComputerName': 'server-02', 'timestamp_utc': '2026-01-15T10:30:00Z',
         'description': 'lateral movement rdp smb psexec', 'severity': 'critical'},
        {'row_index': 5, '_source': 'cloudtrail', 'userIdentity_arn': 'alice@corp.com',
         'sourceIPAddress': '10.0.2.20', 'eventName': 's3:GetObject',
         'timestamp_utc': '2026-01-15T11:00:00Z', 'description': 'data exfiltration S3',
         'severity': 'critical'},
        {'row_index': 6, '_source': 'zeek', 'id_orig_h': '10.0.2.20',
         'id.resp_h': '198.51.100.99', 'timestamp_utc': '2026-01-15T11:05:00Z',
         'description': 'rclone upload exfiltration outbound', 'severity': 'critical'},
    ]
    cluster = {
        'cluster_id': 'test-cluster-001',
        'verdict': 'CONFIRMED_BREACH',
        'confidence': 0.88,
        'row_refs': list(range(7)),
        'shared_accounts': ['alice@corp.com'],
        'shared_hosts': ['workstation-01', 'server-02'],
        'shared_external_ips': ['10.0.1.5'],
        'phases': [
            {'phase': 'initial_access'},
            {'phase': 'credential_access'},
            {'phase': 'lateral_movement'},
            {'phase': 'exfiltration'},
        ],
        'tier1_prefill': {
            'incident_name': 'Alice Breach - S3 Exfiltration',
            'mitre_techniques': ['T1078', 'T1003', 'T1021', 'T1537'],
        },
    }
    assessment = {
        'normalized_rows': rows,
        'tenant_id': 'test-tenant',
    }
    return cluster, rows, assessment


# ── CrossSourceStitcher tests ─────────────────────────────────────────────────


class TestCrossSourceStitcher:
    def test_normalise_zeek_row(self):
        from src.exec_summary.cross_source_stitcher import normalise_row
        row = _zeek_row(0, '10.0.1.5', '10.0.2.20', '2026-01-15T10:00:00Z', 'alice')
        n = normalise_row(row)
        assert n['ip'] == '10.0.1.5'
        assert n['ip_dst'] == '10.0.2.20'
        assert n['user'] == 'alice'
        assert n['source'] == 'zeek'

    def test_normalise_okta_row(self):
        from src.exec_summary.cross_source_stitcher import normalise_row
        row = _okta_row(1, 'bob@corp.com', '10.0.1.5', '2026-01-15T10:00:30Z')
        n = normalise_row(row)
        assert n['user'] == 'bob@corp.com'
        assert n['ip'] == '10.0.1.5'
        assert n['source'] == 'okta'

    def test_normalise_sysmon_row(self):
        from src.exec_summary.cross_source_stitcher import normalise_row
        row = _sysmon_row(2, 'carol', 'server-01', '2026-01-15T10:00:00Z', 'lsass')
        n = normalise_row(row)
        assert n['user'] == 'carol'
        assert n['host'] == 'server-01'
        assert n['source'] == 'sysmon'

    def test_detect_schema_type(self):
        from src.exec_summary.cross_source_stitcher import detect_schema_type
        assert detect_schema_type(_zeek_row(0, '1.2.3.4', '5.6.7.8', '2026-01-01T00:00:00Z')) == 'zeek'
        assert detect_schema_type(_okta_row(0, 'u', '1.2.3.4', '2026-01-01T00:00:00Z')) == 'okta'
        assert detect_schema_type(_sysmon_row(0, 'u', 'h', '2026-01-01T00:00:00Z', 'e')) == 'sysmon'

    def test_testnet_ips_blanked(self):
        from src.exec_summary.cross_source_stitcher import normalise_row
        row = {'row_index': 0, 'ip': '192.0.2.1', '_source': 'test'}
        n = normalise_row(row)
        assert n['ip'] is None

    def test_stitch_cross_source(self):
        from src.exec_summary.cross_source_stitcher import CrossSourceStitcher
        # Zeek row and Okta row describing the same user+IP within 60s
        rows = [
            _zeek_row(0, '10.0.1.5', '10.0.2.1', '2026-01-15T10:00:00Z', 'alice'),
            _okta_row(1, 'alice', '10.0.1.5', '2026-01-15T10:00:20Z'),
        ]
        stitches = CrossSourceStitcher(time_window_seconds=120).stitch(rows)
        cross = [s for s in stitches if s['cross_source']]
        assert len(cross) >= 1
        assert 0 in cross[0]['row_indices']
        assert 1 in cross[0]['row_indices']

    def test_stitch_same_source_no_cross(self):
        from src.exec_summary.cross_source_stitcher import CrossSourceStitcher
        rows = [
            _zeek_row(0, '10.0.1.5', '10.0.2.1', '2026-01-15T10:00:00Z'),
            _zeek_row(1, '10.0.1.6', '10.0.2.2', '2026-01-15T10:01:00Z'),
        ]
        stitches = CrossSourceStitcher().stitch(rows)
        # No cross-source stitches since both are zeek
        cross = [s for s in stitches if s['cross_source']]
        assert len(cross) == 0

    def test_stitch_cluster_evidence(self):
        from src.exec_summary.cross_source_stitcher import stitch_cluster_evidence
        cluster, rows, assessment = _make_cluster_with_rows()
        stitches = stitch_cluster_evidence(cluster, assessment)
        assert isinstance(stitches, list)
        # Should find cross-source groups (alice appears in zeek+okta+sysmon)
        cross = [s for s in stitches if s['cross_source']]
        assert len(cross) >= 1


# ── SequenceValidator tests ───────────────────────────────────────────────────


class TestSequenceValidator:
    def test_validate_full_chain(self):
        from src.exec_summary.sequence_validator import SequenceValidator
        _, rows, _ = _make_cluster_with_rows()
        result = SequenceValidator().validate(rows)
        # Should find multiple phases
        assert result['phase_count'] >= 2
        assert 'initial_access' in result['phase_coverage'] or 'credential_access' in result['phase_coverage']
        assert result['sequence_narrative']
        assert result['first_event_ts']
        assert result['last_event_ts']

    def test_infer_phase_from_description(self):
        from src.exec_summary.sequence_validator import _infer_phase
        assert _infer_phase({'description': 'brute force login attempt'}) == 'initial_access'
        assert _infer_phase({'description': 'lsass credential dump'}) == 'credential_access'
        assert _infer_phase({'description': 'rclone exfil upload'}) == 'exfiltration'
        assert _infer_phase({'description': 'powershell script exec'}) == 'execution'
        assert _infer_phase({'description': 'rdp lateral movement'}) == 'lateral_movement'

    def test_out_of_order_detection(self):
        from src.exec_summary.sequence_validator import SequenceValidator
        # Exfil before lateral movement = out of order
        rows = [
            {'row_index': 0, 'description': 'rclone exfil upload', 'timestamp_utc': '2026-01-15T10:00:00Z'},
            {'row_index': 1, 'description': 'rdp lateral movement pivot', 'timestamp_utc': '2026-01-15T10:05:00Z'},
        ]
        result = SequenceValidator().validate(rows)
        # exfiltration (9) before lateral_movement (7) is OOO
        assert len(result['out_of_order']) >= 1

    def test_dwell_gap_detection(self):
        from src.exec_summary.sequence_validator import SequenceValidator
        rows = [
            {'row_index': 0, 'description': 'brute force login', 'timestamp_utc': '2026-01-15T10:00:00Z'},
            {'row_index': 1, 'description': 'rclone exfil upload', 'timestamp_utc': '2026-01-17T10:00:00Z'},
        ]
        result = SequenceValidator().validate(rows)
        assert result['total_duration_hours'] is not None
        assert result['total_duration_hours'] > 40  # 48h gap
        large_gaps = [g for g in result['dwell_gaps'] if g['gap_hours'] > 24]
        assert len(large_gaps) >= 1

    def test_empty_rows(self):
        from src.exec_summary.sequence_validator import SequenceValidator
        result = SequenceValidator().validate([])
        assert result['phase_count'] == 0
        assert result['phase_coverage'] == []
        assert result['sequence_narrative']


# ── AdversarialReasoner tests ─────────────────────────────────────────────────


class TestAdversarialReasoner:
    def test_deterministic_synthesis(self):
        from src.exec_summary.adversarial_reasoner import _deterministic_synthesis
        cluster = {'cluster_id': 'c0', 'verdict': 'CONFIRMED_BREACH',
                   'tier1_prefill': {'incident_name': 'Test'}}
        seq_result = {'sequence_coherent': True, 'phase_count': 4, 'anomalies': []}
        vr = {'composite_score': 0.82, 'fp_risk': 0.1, 'evidence_quality': 'strong',
              'grader_caveats': [], 'counter_hypotheses': []}
        synthesis = _deterministic_synthesis(cluster, seq_result, vr)
        assert synthesis['final_verdict'] == 'CONFIRMED_BREACH'
        assert 0.0 <= synthesis['confidence'] <= 1.0
        assert synthesis['ceo_one_liner']
        assert isinstance(synthesis['analyst_escalation_required'], bool)

    def test_deterministic_synthesis_weak_evidence(self):
        from src.exec_summary.adversarial_reasoner import _deterministic_synthesis
        cluster = {'cluster_id': 'c0', 'verdict': 'UNCERTAIN',
                   'tier1_prefill': {'incident_name': 'Test'}}
        seq_result = {'sequence_coherent': False, 'phase_count': 1, 'anomalies': ['OOO transition']}
        vr = {'composite_score': 0.35, 'fp_risk': 0.6, 'evidence_quality': 'weak',
              'grader_caveats': ['single source'], 'counter_hypotheses': ['Could be testing']}
        synthesis = _deterministic_synthesis(cluster, seq_result, vr)
        # Low composite + high fp_risk + anomalies → should flag escalation
        assert synthesis['analyst_escalation_required'] is True

    def test_no_llm_uses_deterministic(self):
        from src.exec_summary.adversarial_reasoner import AdversarialReasoner, _deterministic_synthesis
        cluster, rows, _ = _make_cluster_with_rows()
        seq_result = {'sequence_coherent': True, 'phase_count': 3, 'anomalies': []}
        vr = {'composite_score': 0.8, 'fp_risk': 0.15, 'evidence_quality': 'strong',
              'grader_caveats': [], 'counter_hypotheses': [], 'disposition_breakdown': {}}
        # Call _deterministic_synthesis directly (no LLM path)
        synthesis = _deterministic_synthesis(cluster, seq_result, vr)
        assert synthesis['final_verdict'] == 'CONFIRMED_BREACH'
        assert synthesis['ceo_one_liner']

    def test_parse_json(self):
        from src.exec_summary.adversarial_reasoner import _parse_json
        # Clean JSON
        r = _parse_json('{"final_verdict": "CONFIRMED_BREACH", "confidence": 0.9}')
        assert r['final_verdict'] == 'CONFIRMED_BREACH'
        # Markdown-fenced
        r2 = _parse_json('```json\n{"a": 1}\n```')
        assert r2['a'] == 1
        # Invalid
        r3 = _parse_json('Not JSON at all')
        assert r3 is None


# ── Deep analysis orchestrator tests ─────────────────────────────────────────


class TestDeepAnalysis:
    def test_create_and_get_job(self):
        from src.exec_summary.deep_analysis import create_job, get_job
        job_id = create_job('assessment-abc')
        job = get_job(job_id)
        assert job is not None
        assert job['status'] == 'queued'
        assert job['assessment_id'] == 'assessment-abc'

    def test_get_missing_job(self):
        from src.exec_summary.deep_analysis import get_job
        assert get_job('nonexistent-job-id') is None

    def test_build_deep_rollup(self):
        from src.exec_summary.deep_analysis import _build_deep_rollup
        cluster_results = [
            {
                'cluster_id': 'c0',
                'cross_source_count': 3,
                'sequence': {'sequence_coherent': True},
                'adversarial': {'passes_completed': 3},
                'synthesis': {'final_verdict': 'CONFIRMED_BREACH', 'confidence': 0.9},
                'ceo_one_liner': 'Confirmed breach via stolen credentials.',
            },
            {
                'cluster_id': 'c1',
                'cross_source_count': 0,
                'sequence': {'sequence_coherent': False},
                'adversarial': {'passes_completed': 0},
                'synthesis': {'final_verdict': 'UNCERTAIN', 'confidence': 0.45},
                'ceo_one_liner': 'Uncertain — analyst review required.',
            },
        ]
        rollup = _build_deep_rollup(cluster_results, {})
        assert rollup['cluster_count'] == 2
        assert rollup['cross_source_clusters'] == 1
        assert rollup['coherent_sequences'] == 1
        assert rollup['confirmed_clusters'] == 1
        assert rollup['average_confidence'] > 0
        assert len(rollup['ceo_summary_lines']) == 2

    @pytest.mark.asyncio
    async def test_run_deep_analysis_deterministic(self):
        """Full async pipeline without LLM — deterministic fallback throughout."""
        from src.exec_summary.deep_analysis import create_job, run_deep_analysis_job, get_job
        cluster, rows, assessment = _make_cluster_with_rows()
        assessment['normalized_rows'] = rows

        job_id = create_job('test-deep-001')
        await run_deep_analysis_job(
            job_id=job_id,
            assessment_id='test-deep-001',
            assessment=assessment,
            sorted_clusters=[cluster],
            llm_func=None,
            model='qwen3:14b',
        )

        job = get_job(job_id)
        assert job['status'] == 'ready'
        result = job['result']
        assert result is not None
        assert len(result['cluster_results']) == 1
        cr = result['cluster_results'][0]
        assert cr['cluster_id'] == 'test-cluster-001'
        assert 'stitches' in cr
        assert 'sequence' in cr
        assert 'synthesis' in cr
        assert cr['synthesis']['final_verdict'] == 'CONFIRMED_BREACH'
        assert result['rollup']['cluster_count'] == 1

    @pytest.mark.asyncio
    async def test_subscribe_and_receive_complete_event(self):
        """SSE subscription receives the complete event when job finishes."""
        import asyncio
        from src.exec_summary.deep_analysis import create_job, run_deep_analysis_job, subscribe_job

        cluster, rows, assessment = _make_cluster_with_rows()
        job_id = create_job('test-sse-001')
        q = subscribe_job(job_id)

        # Run job in background
        task = asyncio.create_task(run_deep_analysis_job(
            job_id=job_id,
            assessment_id='test-sse-001',
            assessment=assessment,
            sorted_clusters=[cluster],
            llm_func=None,
        ))
        await task

        # Collect all events
        events = []
        while not q.empty():
            msg = q.get_nowait()
            import json as _json
            events.append(_json.loads(msg))

        event_types = [e['type'] for e in events]
        assert 'complete' in event_types
        # Cluster complete event should have been emitted
        assert 'cluster_complete' in event_types
