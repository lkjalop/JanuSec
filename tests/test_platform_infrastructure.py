"""Tests for new platform infrastructure: backup, connectors, bitemporal T6 LLM."""
from __future__ import annotations

import json
import os
import sys
import time
import tarfile
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Assessment Backup Module
# ---------------------------------------------------------------------------

class TestAssessmentBackup:
    def test_import(self):
        from src.backup.assessment_backup import AssessmentBackupManager, get_backup_manager, schedule_nightly_backup
        assert AssessmentBackupManager is not None

    def test_backup_missing_dir(self, tmp_path):
        from src.backup.assessment_backup import AssessmentBackupManager
        mgr = AssessmentBackupManager()
        with patch.dict(os.environ, {'ASSESSMENTS_DIR': str(tmp_path / 'nonexistent')}):
            result = mgr.run_backup()
        assert result['ok'] is False
        assert 'source_dir_missing' in result['error']

    def test_local_backup_creates_archive(self, tmp_path):
        from src.backup.assessment_backup import AssessmentBackupManager, _build_archive, _cleanup_tmp
        # Create fake assessments dir
        src = tmp_path / 'assessments'
        src.mkdir()
        (src / 'test.json').write_text('{"test": 1}')
        archive = _build_archive(src, 'TEST20260101')
        assert archive.exists()
        assert tarfile.is_tarfile(archive)
        _cleanup_tmp(archive)

    def test_run_backup_local(self, tmp_path, monkeypatch):
        from src.backup.assessment_backup import AssessmentBackupManager
        src = tmp_path / 'assessments'
        src.mkdir()
        (src / 'data.json').write_text('{"assessment": "test"}')
        backup_dir = tmp_path / 'backups'
        monkeypatch.setenv('ASSESSMENTS_DIR', str(src))
        monkeypatch.setenv('BACKUP_LOCAL_DIR', str(backup_dir))
        monkeypatch.setenv('BACKUP_DEST', 'local')
        mgr = AssessmentBackupManager()
        result = mgr.run_backup()
        assert result['ok'] is True
        assert 'destination' in result
        assert backup_dir.exists()
        archives = list(backup_dir.glob('assessments_*.tar.gz'))
        assert len(archives) == 1

    def test_prune_old_backups(self, tmp_path):
        from src.backup.assessment_backup import _prune_local_backups
        for i in range(3):
            p = tmp_path / f'assessments_old{i}.tar.gz'
            p.write_bytes(b'fake')
            # Set mtime to 40 days ago
            old_time = time.time() - 40 * 86400
            os.utime(p, (old_time, old_time))
        recent = tmp_path / 'assessments_new.tar.gz'
        recent.write_bytes(b'recent')
        pruned = _prune_local_backups(tmp_path, retention_days=30)
        assert pruned == 3
        assert recent.exists()
        assert not any(tmp_path.glob('assessments_old*.tar.gz'))

    def test_backup_disabled_by_default(self):
        from src.backup.assessment_backup import _is_enabled
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('BACKUP_ENABLED', None)
            assert _is_enabled() is False

    def test_schedule_nightly_noop_when_disabled(self, monkeypatch):
        monkeypatch.setenv('BACKUP_ENABLED', '0')
        from src.backup import assessment_backup
        assessment_backup._BACKUP_TASK = None
        # Should not create a task when disabled
        with patch('asyncio.get_event_loop') as mock_loop:
            assessment_backup.schedule_nightly_backup()
        mock_loop.assert_not_called()


# ---------------------------------------------------------------------------
# AWS Inspector Connector
# ---------------------------------------------------------------------------

class TestInspectorConnector:
    def test_import(self):
        from src.connectors.aws.inspector import InspectorConnector, _normalize_finding
        assert InspectorConnector is not None

    def test_normalize_ec2_finding(self):
        from src.connectors.aws.inspector import _normalize_finding
        finding = {
            'findingArn': 'arn:aws:inspector2:us-east-1:123:finding/abc',
            'awsAccountId': '123456789',
            'severity': 'CRITICAL',
            'title': 'CVE-2024-1234 in openssl',
            'description': 'OpenSSL vulnerability',
            'status': 'ACTIVE',
            'packageVulnerabilityDetails': {
                'vulnerabilityId': 'CVE-2024-1234',
                'cvss': [{'baseScore': 9.8}],
                'vulnerablePackages': [{'name': 'openssl', 'version': '1.1.1', 'fixedInVersion': '1.1.1w'}],
            },
            'resources': [{
                'type': 'AWS_EC2_INSTANCE',
                'id': 'i-12345',
                'details': {'awsEc2Instance': {'ipV4Addresses': ['10.0.1.5'], 'platform': 'LINUX_AMD64'}},
            }],
            'updatedAt': '2026-04-01T12:00:00Z',
        }
        env = _normalize_finding(finding, 'us-east-1')
        assert env['severity'] == 'CRITICAL'
        assert env['cve_id'] == 'CVE-2024-1234'
        assert env['cvss_score'] == 9.8
        assert env['host'] == '10.0.1.5'
        assert env['ingest_source'] == 'inspector'
        assert 'inspector:vuln_critical' in env['factors']
        assert 'cve:CVE-2024-1234' in env['factors']

    def test_normalize_ecr_finding(self):
        from src.connectors.aws.inspector import _normalize_finding
        finding = {
            'findingArn': 'arn:aws:inspector2:us-east-1:123:finding/ecr1',
            'awsAccountId': '123456789',
            'severity': 'HIGH',
            'title': 'CVE-2024-9999 in requests',
            'packageVulnerabilityDetails': {'vulnerabilityId': 'CVE-2024-9999'},
            'resources': [{
                'type': 'AWS_ECR_CONTAINER_IMAGE',
                'id': 'arn:aws:ecr:us-east-1:123:repository/myapp',
                'details': {'awsEcrContainerImage': {
                    'imageDigest': 'sha256:abc',
                    'imageTags': ['latest'],
                    'repositoryName': 'myapp',
                }},
            }],
        }
        env = _normalize_finding(finding, 'us-east-1')
        assert env['severity'] == 'HIGH'
        assert env['repository_name'] == 'myapp'


# ---------------------------------------------------------------------------
# CloudWatch Logs Connector
# ---------------------------------------------------------------------------

class TestCloudWatchConnector:
    def test_import(self):
        from src.connectors.aws.cloudwatch import CloudWatchConnector, _parse_log_event, _enrich_from_message
        assert CloudWatchConnector is not None

    def test_parse_json_event(self):
        from src.connectors.aws.cloudwatch import _parse_log_event
        event = {
            'eventId': 'evt-123',
            'timestamp': 1712845200000,  # 2024-04-11T15:00:00Z
            'message': json.dumps({
                'eventName': 'ConsoleLogin',
                'sourceIPAddress': '1.2.3.4',
                'userIdentity': {'userName': 'alice'},
            }),
            'logStreamName': 'CloudTrail/us-east-1',
        }
        env = _parse_log_event(event, '/aws/cloudtrail', 'us-east-1', '123')
        assert env['log_group'] == '/aws/cloudtrail'
        assert env['event_name'] == 'ConsoleLogin'
        assert env['src_ip'] == '1.2.3.4'
        assert env['user'] == 'alice'
        assert abs(env['ts'] - 1712845200.0) < 1

    def test_parse_vpc_flow_event(self):
        from src.connectors.aws.cloudwatch import _parse_log_event
        event = {
            'eventId': 'vpcflow-1',
            'timestamp': 1712845300000,
            'message': '2 123456789 eni-abc123 10.0.0.1 10.0.0.2 12345 443 6 100 50000 1712845200 1712845300 ACCEPT OK',
            'logStreamName': 'vpcflow',
        }
        env = _parse_log_event(event, '/aws/vpcflow', 'us-east-1', '123')
        assert env['src_ip'] == '10.0.0.1'
        assert env['dst_ip'] == '10.0.0.2'
        assert env['dst_port'] == 443
        assert env['action'] == 'ACCEPT'

    def test_no_log_groups_returns_empty(self, monkeypatch):
        monkeypatch.delenv('AWS_CW_LOG_GROUPS', raising=False)
        monkeypatch.delenv('AWS_VPCFLOW_LOG_GROUP', raising=False)
        from src.connectors.aws.cloudwatch import CloudWatchConnector
        from src.connectors.aws.base import AWSConnectorConfig
        cfg = AWSConnectorConfig()
        connector = CloudWatchConnector(cfg)
        events = list(connector.fetch_events())
        assert events == []


# ---------------------------------------------------------------------------
# Azure Monitor Connector
# ---------------------------------------------------------------------------

class TestAzureMonitorConnector:
    def test_import(self):
        from src.connectors.azure.monitor import AzureMonitorConnector, _normalize_row
        assert AzureMonitorConnector is not None

    def test_normalize_activity_log_row(self):
        from src.connectors.azure.monitor import _normalize_row
        row = {
            'TimeGenerated': '2026-04-11T12:00:00Z',
            'OperationName': 'Microsoft.Authorization/roleAssignments/write',
            'ActivityStatus': 'Failed',
            'Caller': 'attacker@contoso.com',
            'ResourceGroup': 'prod-rg',
            'ResourceId': '/subscriptions/abc/resourceGroups/prod-rg',
        }
        env = _normalize_row(row)
        assert env['user'] == 'attacker@contoso.com'
        assert env['event_name'] == 'Microsoft.Authorization/roleAssignments/write'
        assert env['status'] == 'Failed'
        assert env['severity'] == 'WARNING'
        assert 'azure_monitor:event' in env['factors']

    def test_normalize_signin_row(self):
        from src.connectors.azure.monitor import _normalize_row
        row = {
            'TimeGenerated': '2026-04-11T12:01:00Z',
            'UserPrincipalName': 'user@corp.com',
            'IPAddress': '8.8.8.8',
            'ResultType': '50126',
            'AppDisplayName': 'Azure Portal',
        }
        env = _normalize_row(row)
        assert env['user'] == 'user@corp.com'
        assert env['src_ip'] == '8.8.8.8'
        assert env['severity'] == 'WARNING'

    def test_missing_workspace_returns_empty(self, monkeypatch):
        monkeypatch.delenv('AZURE_MONITOR_WORKSPACE_ID', raising=False)
        from src.connectors.azure.monitor import AzureMonitorConnector
        connector = AzureMonitorConnector()
        events = list(connector.fetch_events())
        assert events == []


# ---------------------------------------------------------------------------
# CrowdStrike Connector
# ---------------------------------------------------------------------------

class TestCrowdStrikeConnector:
    def test_import(self):
        from src.connectors.crowdstrike.connector import CrowdStrikeConnector, _normalize_detection
        assert CrowdStrikeConnector is not None

    def test_no_credentials_raises(self, monkeypatch):
        monkeypatch.delenv('CS_FALCON_CLIENT_ID', raising=False)
        monkeypatch.delenv('CS_FALCON_CLIENT_SECRET', raising=False)
        from src.connectors.crowdstrike.connector import CrowdStrikeConnector
        with pytest.raises(RuntimeError, match='CS_FALCON'):
            CrowdStrikeConnector()

    def test_normalize_detection(self):
        from src.connectors.crowdstrike.connector import _normalize_detection
        detection = {
            'detection_id': 'det-1',
            'max_severity': 3,
            'max_confidence': 80,
            'status': 'new',
            'first_behavior': '2026-04-11T12:00:00Z',
            'device': {
                'hostname': 'ws-corp-01',
                'local_ip': '10.0.0.5',
                'platform_name': 'Windows',
            },
            'behaviors': [{
                'filename': 'powershell.exe',
                'cmdline': 'powershell -EncodedCommand abc',
                'user_name': 'CORP\\alice',
                'tactic': 'Execution',
                'technique': 'Command and Scripting Interpreter',
                'technique_id': 'T1059.001',
                'severity': 3,
            }],
        }
        env = _normalize_detection(detection)
        assert env['host'] == 'ws-corp-01'
        assert env['severity'] == 'HIGH'
        assert env['process'] == 'powershell.exe'
        assert env['technique_id'] == 'T1059.001'
        assert 'T1059.001' in env['mitre_tags']
        assert 'crowdstrike:detection_high' in env['factors']


# ---------------------------------------------------------------------------
# SentinelOne Connector
# ---------------------------------------------------------------------------

class TestSentinelOneConnector:
    def test_import(self):
        from src.connectors.sentinelone.connector import SentinelOneConnector, _normalize_threat
        assert SentinelOneConnector is not None

    def test_no_credentials_raises(self, monkeypatch):
        monkeypatch.delenv('S1_MGMT_URL', raising=False)
        monkeypatch.delenv('S1_API_TOKEN', raising=False)
        from src.connectors.sentinelone.connector import SentinelOneConnector
        with pytest.raises(RuntimeError, match='S1_'):
            SentinelOneConnector()

    def test_normalize_threat(self):
        from src.connectors.sentinelone.connector import _normalize_threat
        threat = {
            'id': 'threat-1',
            'agentDetectionInfo': {
                'agentComputerName': 'laptop-01',
                'agentIpV4': '192.168.1.10',
                'agentOsName': 'Windows 11',
                'agentLastLoggedInUserName': 'alice',
            },
            'threatInfo': {
                'createdAt': '2026-04-11T12:00:00Z',
                'confidenceLevel': 'high',
                'threatName': 'Malware.Ransomware',
                'filePath': 'C:\\Windows\\Temp\\evil.exe',
                'sha256': 'abc123',
            },
            'indicators': [{
                'tactics': [{
                    'techniques': [{'id': 'T1486', 'name': 'Data Encrypted for Impact'}]
                }]
            }],
        }
        env = _normalize_threat(threat)
        assert env['host'] == 'laptop-01'
        assert env['severity'] == 'HIGH'
        assert 'T1486' in env['mitre_tags']
        assert 'sentinelone:threat_high' in env['factors']


# ---------------------------------------------------------------------------
# Bitemporal T6 LLM re-eval
# ---------------------------------------------------------------------------

class TestBitemporalT6:
    def test_analyst_review_endpoint_registered(self):
        """analyst_review_router is registered in app.py (no silent 404)."""
        os.environ.setdefault('PLATFORM_LITE_INIT', '1')
        os.environ.setdefault('TEST_HELPERS_ENABLED', '1')
        os.environ.setdefault('DISABLE_DB', '1')
        os.environ.setdefault('LLM_MOCK', '1')
        from src.api.app import app
        routes = {getattr(r, 'path', '') for r in app.router.routes}
        analyst_routes = [r for r in routes if 'analyst_review' in r]
        assert analyst_routes, f'analyst_review route not found in: {sorted(routes)}'

    @pytest.mark.asyncio
    async def test_t6_fire_mock(self):
        """T6 LLM re-eval fires in LLM_MOCK=1 mode without calling real LLM."""
        os.environ['LLM_MOCK'] = '1'
        from src.api.analyst_review_endpoints import _fire_t6_llm_reeval
        result = await _fire_t6_llm_reeval(
            assessment={'rows': [{'host': 'ws01', 'process': 'calc.exe'}]},
            delta={'t3_label': 'confirmed_malicious', 'delta_type': 'reversal', 't1_verdict': 'benign', 't1_confidence': 0.3},
            rag_patterns=[],
            reeval_prompt='Test re-eval prompt',
            persona='analyst',
        )
        assert result['error'] is None
        assert result['llm_response'] is not None
        assert 'confirmed_malicious' in result['llm_response']

    def test_custody_hash_deterministic(self):
        from src.api.analyst_review_endpoints import _custody_hash
        data = {'event_id': 'test-1', 'action': 'analyst_label', 'label': 'benign', 'prev_hash': None}
        h1 = _custody_hash(data)
        h2 = _custody_hash(data)
        assert h1 == h2
        assert len(h1) == 64  # SHA256 hex

    def test_bitemporal_delta_reversal(self):
        from src.api.analyst_review_endpoints import _compute_bitemporal_delta
        delta = _compute_bitemporal_delta(
            {'verdict': 'escalate', 'confidence': 0.85},
            'benign',
            'This is a known admin tool',
        )
        assert delta['label_reversal'] is True
        assert delta['delta_type'] == 'reversal'
        assert delta['t3_label'] == 'benign'

    def test_bitemporal_delta_confirmation(self):
        from src.api.analyst_review_endpoints import _compute_bitemporal_delta
        delta = _compute_bitemporal_delta(
            {'verdict': 'escalate', 'confidence': 0.9},
            'confirmed_malicious',
            '',
        )
        assert delta['label_reversal'] is False
        assert delta['delta_type'] == 'confirmation'


# ---------------------------------------------------------------------------
# Connector autopoll security fix
# ---------------------------------------------------------------------------

class TestAutopollSecurity:
    def test_no_devkey123_in_production(self, monkeypatch):
        """devkey123 must NOT be returned when TEST_HELPERS_ENABLED=0."""
        monkeypatch.delenv('CONNECTOR_AUTOPOLL_API_KEY', raising=False)
        monkeypatch.delenv('API_KEY', raising=False)
        monkeypatch.delenv('DEFAULT_API_KEY', raising=False)
        monkeypatch.setenv('TEST_HELPERS_ENABLED', '0')
        import importlib
        import src.api.connector_autopoll as cmod
        importlib.reload(cmod)
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter('always')
            key = cmod._autopoll_api_key()
        assert key == '', f'Expected empty string in production, got: {key!r}'
        assert any('CONNECTOR_AUTOPOLL_API_KEY' in str(warning.message) for warning in w)

    def test_devkey123_allowed_in_test_mode(self, monkeypatch):
        monkeypatch.delenv('CONNECTOR_AUTOPOLL_API_KEY', raising=False)
        monkeypatch.delenv('API_KEY', raising=False)
        monkeypatch.delenv('DEFAULT_API_KEY', raising=False)
        monkeypatch.setenv('TEST_HELPERS_ENABLED', '1')
        import importlib
        import src.api.connector_autopoll as cmod
        importlib.reload(cmod)
        key = cmod._autopoll_api_key()
        assert key == 'devkey123'
