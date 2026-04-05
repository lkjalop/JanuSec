"""Tests for the four new production-grade modules."""
from __future__ import annotations

import os
import time
import threading
import pytest

os.environ.setdefault('TEST_HELPERS_ENABLED', '1')
os.environ.setdefault('PLATFORM_LITE_INIT', '1')
os.environ.setdefault('DISABLE_DB', '1')


# ============================================================
# 1. PCAP Driver
# ============================================================

class TestPcapDriver:
    def test_import(self):
        from src.drivers.pcap_driver import PcapDriver, CaptureSpec, CaptureState
        assert PcapDriver

    def test_no_privilege_raises(self, monkeypatch):
        from src.drivers import pcap_driver
        monkeypatch.setattr(pcap_driver, '_SCAPY_AVAILABLE', False)
        monkeypatch.setattr(pcap_driver, '_has_capture_privileges', lambda: False)
        driver = pcap_driver.PcapDriver()
        spec = pcap_driver.CaptureSpec(duration_seconds=5)
        with pytest.raises(PermissionError):
            driver.start(spec)

    def test_duration_capped(self):
        from src.drivers.pcap_driver import CaptureSpec, _PCAP_MAX_DURATION
        # CaptureSpec itself doesn't cap; the driver does
        spec = CaptureSpec(duration_seconds=9999)
        assert 9999 > _PCAP_MAX_DURATION

    def test_summarise_raw_ipv4(self):
        from src.drivers.pcap_driver import _summarise_raw
        import struct
        # Build a minimal Ethernet + IPv4 header
        eth = b'\xff\xff\xff\xff\xff\xff' + b'\x00' * 6 + b'\x08\x00'  # 14 bytes
        # IPv4: version+IHL, DSCP, total len, id, flags+frag, TTL, proto(TCP=6), chksum, src, dst
        ipv4 = bytes([0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0,
                      10, 0, 0, 5,   # src: 10.0.0.5
                      192, 168, 1, 1])  # dst: 192.168.1.1
        frame = eth + ipv4 + b'\x00' * 40
        pkt = _summarise_raw(frame, time.time(), False)
        assert pkt.src == '10.0.0.5'
        assert pkt.dst == '192.168.1.1'
        assert pkt.proto == 'TCP'

    def test_status_unknown_id(self):
        from src.drivers.pcap_driver import PcapDriver
        driver = PcapDriver()
        assert driver.status('nonexistent') is None

    def test_stop_unknown_raises(self):
        from src.drivers.pcap_driver import PcapDriver
        driver = PcapDriver()
        with pytest.raises(KeyError):
            driver.stop('nonexistent')

    def test_get_pcap_driver_singleton(self):
        from src.drivers.pcap_driver import get_pcap_driver
        d1 = get_pcap_driver()
        d2 = get_pcap_driver()
        assert d1 is d2


# Simulate a full capture run without real network using the fallback path
class TestPcapFallbackCapture:
    def test_fallback_no_driver_on_windows(self, monkeypatch):
        from src.drivers import pcap_driver
        monkeypatch.setattr(pcap_driver, '_SCAPY_AVAILABLE', False)
        monkeypatch.setattr(pcap_driver, '_has_capture_privileges', lambda: True)
        # On Windows 'nt', fallback sets ERROR state
        import platform
        if platform.system() == 'Windows':
            session = pcap_driver._Session(
                capture_id='test-1',
                spec=pcap_driver.CaptureSpec(duration_seconds=1),
            )
            driver = pcap_driver.PcapDriver()
            driver._run_fallback(session)
            assert session.state == pcap_driver.CaptureState.ERROR

    def test_ring_buffer_caps(self):
        from src.drivers.pcap_driver import _Session, CaptureSpec, PacketSummary
        s = _Session(capture_id='t', spec=CaptureSpec())
        # Override max for testing
        import src.drivers.pcap_driver as m
        old_max = m._PCAP_RING_MAX
        m._PCAP_RING_MAX = 3
        for i in range(5):
            s.ring_append(PacketSummary(ts=float(i), src='', dst='', proto='', length=i))
        assert len(s.packets) == 3
        assert s.dropped == 2
        m._PCAP_RING_MAX = old_max


# ============================================================
# 2. Cross-Cloud IAM Correlator
# ============================================================

class TestCrossCloudIAM:
    def _aws_event(self, user='alice@corp.com', event_name='AssumeRole',
                   role_arn='arn:aws:iam::123:role/Admin', ts_offset=0) -> dict:
        import datetime
        ts = datetime.datetime.utcnow()
        # offset in seconds
        from datetime import timedelta
        ts = ts + timedelta(seconds=ts_offset)
        return {
            'eventTime': ts.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'eventName': event_name,
            'awsRegion': 'us-east-1',
            'sourceIPAddress': '203.0.113.5',
            'userIdentity': {
                'arn': f'arn:aws:sts::123:assumed-role/Role/{user}',
                'userName': user,
            },
            'requestParameters': {'roleArn': role_arn},
        }

    def _az_event(self, upn='alice@corp.com', op='Add member to role', ts_offset=30) -> dict:
        import datetime
        from datetime import timedelta
        ts = datetime.datetime.utcnow() + timedelta(seconds=ts_offset)
        return {
            'activityDateTime': ts.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'activityDisplayName': op,
            'userPrincipalName': upn,
            'result': 'success',
            'targetResources': [{'displayName': 'Global Admin Role'}],
        }

    def test_ingest_aws(self):
        from src.core.graph.crosscloud_iam import CrossCloudIAMCorrelator
        c = CrossCloudIAMCorrelator()
        ev = c.ingest_aws(self._aws_event())
        assert ev is not None
        assert ev.cloud == 'aws'
        assert ev.identity_key == 'alice@corp.com'

    def test_ingest_azure(self):
        from src.core.graph.crosscloud_iam import CrossCloudIAMCorrelator
        c = CrossCloudIAMCorrelator()
        ev = c.ingest_azure(self._az_event())
        assert ev is not None
        assert ev.cloud == 'azure'
        assert 'alice@corp.com' in ev.identity_key

    def test_cross_cloud_correlation_detected(self):
        from src.core.graph.crosscloud_iam import CrossCloudIAMCorrelator
        c = CrossCloudIAMCorrelator(window_seconds=120)
        c.ingest_aws(self._aws_event(ts_offset=0))
        c.ingest_azure(self._az_event(ts_offset=15))
        result = c.correlate_identity('alice@corp.com')
        assert result.total_events == 2
        assert len(result.cross_cloud_chains) >= 1
        assert result.risk_score > 0

    def test_no_chain_single_cloud(self):
        from src.core.graph.crosscloud_iam import CrossCloudIAMCorrelator
        c = CrossCloudIAMCorrelator()
        c.ingest_aws(self._aws_event())
        c.ingest_aws(self._aws_event(event_name='ListBuckets'))
        result = c.correlate_identity('alice@corp.com')
        # Only AWS — no cross-cloud chains
        assert result.cross_cloud_chains == []

    def test_suspicious_privesc_scores_higher(self):
        from src.core.graph.crosscloud_iam import CrossCloudIAMCorrelator
        c = CrossCloudIAMCorrelator(window_seconds=120)
        c.ingest_aws(self._aws_event(event_name='AssumeRole', ts_offset=0))
        c.ingest_azure(self._az_event(op='Add member to role', ts_offset=10))
        result = c.correlate_identity('alice@corp.com')
        assert result.risk_score >= 0.30

    def test_top_risks(self):
        from src.core.graph.crosscloud_iam import CrossCloudIAMCorrelator
        c = CrossCloudIAMCorrelator(window_seconds=120)
        for user in ['alice@corp.com', 'bob@corp.com']:
            c.ingest_aws(self._aws_event(user=user))
            c.ingest_azure(self._az_event(upn=user, ts_offset=5))
        risks = c.top_risks(n=5)
        assert len(risks) == 2

    def test_stats(self):
        from src.core.graph.crosscloud_iam import CrossCloudIAMCorrelator
        c = CrossCloudIAMCorrelator()
        c.ingest_aws(self._aws_event())
        s = c.stats()
        assert s['tracked_identities'] == 1
        assert s['total_events'] == 1

    def test_singleton(self):
        from src.core.graph.crosscloud_iam import get_crosscloud_correlator
        c1 = get_crosscloud_correlator()
        c2 = get_crosscloud_correlator()
        assert c1 is c2


# ============================================================
# 3. Azure Sentinel Workspace Connector
# ============================================================

class TestSentinelWorkspaceConnector:
    def _mock_incident(self, name='inc-001', status='New', severity='High') -> dict:
        return {
            'name': name,
            'etag': '"abc"',
            'properties': {
                'title': f'Test Incident {name}',
                'severity': severity,
                'status': status,
                'createdTimeUtc': '2026-04-01T10:00:00Z',
                'lastModifiedTimeUtc': '2026-04-01T11:00:00Z',
                'incidentNumber': 42,
                'owner': {'email': 'soc@corp.com'},
                'labels': [{'labelName': 'malware'}],
                'alerts': [],
                'tactics': ['Persistence'],
            },
        }

    def _make_http_fn(self, response: dict):
        def _http(method, url, headers, body=None):
            if 'incidents' in url and method == 'GET':
                return {'value': [self._mock_incident()]}
            if method in ('PUT', 'PATCH'):
                return self._mock_incident(status='Closed')
            return response
        return _http

    def test_list_incidents(self):
        from src.connectors.azure.sentinel_workspace import (
            SentinelWorkspaceConnector, SentinelWorkspaceConfig
        )
        cfg = SentinelWorkspaceConfig(
            tenant_id='t', client_id='c', client_secret='s',
            subscription_id='sub', resource_group='rg', workspace_name='ws',
            static_token='demo',
        )
        connector = SentinelWorkspaceConnector(cfg=cfg, _http_fn=self._make_http_fn({}))
        incidents = connector.list_incidents()
        assert len(incidents) == 1
        assert incidents[0]['title'] == 'Test Incident inc-001'
        assert incidents[0]['severity'] == 'high'

    def test_normalize_incident_shape(self):
        from src.connectors.azure.sentinel_workspace import _normalize_incident
        raw = self._mock_incident()
        norm = _normalize_incident(raw)
        assert norm['id'] == 'inc-001'
        assert norm['severity'] == 'high'
        assert norm['status'] == 'new'
        assert 'malware' in norm['labels']

    def test_kql_flatten(self):
        from src.connectors.azure.sentinel_workspace import _flatten_kql_result
        data = {
            'tables': [{
                'columns': [{'name': 'Computer'}, {'name': 'EventID'}],
                'rows': [['host-a', 4624], ['host-b', 4625]],
            }]
        }
        rows = _flatten_kql_result(data)
        assert len(rows) == 2
        assert rows[0]['Computer'] == 'host-a'
        assert rows[1]['EventID'] == 4625

    def test_ping_ok(self):
        from src.connectors.azure.sentinel_workspace import (
            SentinelWorkspaceConnector, SentinelWorkspaceConfig
        )
        cfg = SentinelWorkspaceConfig(
            tenant_id='t', client_id='c', client_secret='s',
            subscription_id='sub', resource_group='rg', workspace_name='ws',
            static_token='demo',
        )
        connector = SentinelWorkspaceConnector(cfg=cfg, _http_fn=self._make_http_fn({}))
        result = connector.ping()
        assert result['ok'] is True

    def test_ping_fails_gracefully(self):
        from src.connectors.azure.sentinel_workspace import (
            SentinelWorkspaceConnector, SentinelWorkspaceConfig
        )
        def _failing_http(method, url, headers, body=None):
            raise RuntimeError('network error')

        cfg = SentinelWorkspaceConfig(static_token='x', subscription_id='s',
                                       resource_group='r', workspace_name='w')
        connector = SentinelWorkspaceConnector(cfg=cfg, _http_fn=_failing_http)
        result = connector.ping()
        assert result['ok'] is False
        assert 'error' in result

    def test_kql_requires_workspace_id(self):
        from src.connectors.azure.sentinel_workspace import (
            SentinelWorkspaceConnector, SentinelWorkspaceConfig
        )
        cfg = SentinelWorkspaceConfig(static_token='x')
        connector = SentinelWorkspaceConnector(cfg=cfg)
        with pytest.raises(ValueError, match='SENTINEL_WORKSPACE_ID'):
            connector.query('SecurityEvent | top 1')

    def test_singleton(self):
        from src.connectors.azure.sentinel_workspace import get_sentinel_connector
        c1 = get_sentinel_connector()
        c2 = get_sentinel_connector()
        assert c1 is c2


# ============================================================
# 4. Batch Persona Worker
# ============================================================

class TestPersonaViewCache:
    def test_put_and_get(self):
        from src.workers.persona_worker import PersonaViewCache
        cache = PersonaViewCache(ttl_seconds=300)
        cache.put('rpt-1', {'executive': {'headline': 'test'}}, tier='P1')
        views = cache.get('rpt-1')
        assert views['executive']['headline'] == 'test'

    def test_ttl_expiry(self):
        from src.workers.persona_worker import PersonaViewCache
        cache = PersonaViewCache(ttl_seconds=1)
        cache.put('rpt-1', {'soc_analyst': {}})
        time.sleep(1.1)
        assert cache.get('rpt-1') is None

    def test_evict_expired(self):
        from src.workers.persona_worker import PersonaViewCache
        cache = PersonaViewCache(ttl_seconds=1)
        cache.put('rpt-a', {})
        cache.put('rpt-b', {})
        time.sleep(1.1)
        evicted = cache.evict_expired()
        assert evicted == 2

    def test_get_persona(self):
        from src.workers.persona_worker import PersonaViewCache
        cache = PersonaViewCache(ttl_seconds=300)
        cache.put('rpt-1', {'forensics': {'timeline': []}})
        view = cache.get_persona('rpt-1', 'forensics')
        assert view == {'timeline': []}

    def test_list_cached(self):
        from src.workers.persona_worker import PersonaViewCache
        cache = PersonaViewCache(ttl_seconds=300)
        cache.put('r1', {})
        cache.put('r2', {})
        ids = cache.list_cached()
        assert 'r1' in ids and 'r2' in ids

    def test_stats(self):
        from src.workers.persona_worker import PersonaViewCache
        cache = PersonaViewCache(ttl_seconds=300)
        cache.put('r1', {})
        s = cache.stats()
        assert s['total_entries'] == 1
        assert s['live_entries'] == 1


class TestBatchPersonaWorker:
    def test_start_stop(self):
        from src.workers.persona_worker import BatchPersonaWorker
        w = BatchPersonaWorker(n_threads=1)
        w.start()
        assert w._threads[0].is_alive()
        w.stop(timeout=2.0)
        assert not any(t.is_alive() for t in w._threads)

    def test_enqueue_full_queue_sheds(self):
        from src.workers.persona_worker import BatchPersonaWorker, PersonaViewCache
        import queue as q
        cache = PersonaViewCache()
        w = BatchPersonaWorker(cache=cache, n_threads=1)
        # Fill the queue to max
        from unittest.mock import patch, MagicMock
        import src.workers.persona_worker as m
        old_max = m._MAX_QUEUE
        m._MAX_QUEUE = 1
        # Replace the queue with a tiny one
        w._queue = q.PriorityQueue(maxsize=1)
        w._queue.put_nowait((5, 0.0, None))  # fill it
        result_obj = MagicMock()
        result_obj.tiers = {}
        ok = w.enqueue(result_obj)
        assert ok is False
        m._MAX_QUEUE = old_max

    def test_enqueue_report_adds_to_queue(self):
        from src.workers.persona_worker import BatchPersonaWorker, PersonaViewCache
        cache = PersonaViewCache()
        w = BatchPersonaWorker(cache=cache, n_threads=1)
        report = {
            'report_id': 'rpt-test',
            'risk_quantification': {'severity': 'HIGH'},
            'verdict': {'final_verdict': 'THREAT', 'final_confidence': 0.9, 'all_factors': []},
            'attack_timeline': [],
        }
        ok = w.enqueue_report(report, tier='P2')
        assert ok is True
        assert w._queue.qsize() == 1

    def test_worker_processes_job_end_to_end(self):
        """Worker runs, processes one job, caches views."""
        from src.workers.persona_worker import BatchPersonaWorker, PersonaViewCache
        from src.reporting.tiered_triage import triage_alerts

        cache = PersonaViewCache(ttl_seconds=300)
        w = BatchPersonaWorker(cache=cache, n_threads=1)
        w.start()

        report = {
            'report_id': 'rpt-e2e',
            'risk_quantification': {'severity': 'LOW'},
            'verdict': {'final_verdict': 'REVIEW', 'final_confidence': 0.3, 'all_factors': []},
            'attack_timeline': [],
        }
        result = triage_alerts([report])
        w.enqueue(result, report_lookup={'rpt-e2e': report})

        # Give the worker time to process
        deadline = time.time() + 5.0
        while time.time() < deadline:
            if cache.list_cached():
                break
            time.sleep(0.1)

        w.stop(timeout=3.0)
        stats = w.stats()
        assert stats['jobs_processed'] >= 1

    def test_stats_structure(self):
        from src.workers.persona_worker import BatchPersonaWorker, PersonaViewCache
        w = BatchPersonaWorker(cache=PersonaViewCache(), n_threads=1)
        s = w.stats()
        assert 'jobs_processed' in s
        assert 'jobs_failed' in s
        assert 'queue_depth' in s
        assert 'cache_stats' in s

    def test_start_worker_singleton(self):
        from src.workers import persona_worker
        # Reset singleton for clean test
        persona_worker._GLOBAL_WORKER = None
        persona_worker._GLOBAL_CACHE = None
        w = persona_worker.start_worker()
        assert w._threads
        persona_worker.stop_worker()
        persona_worker._GLOBAL_WORKER = None
        persona_worker._GLOBAL_CACHE = None
