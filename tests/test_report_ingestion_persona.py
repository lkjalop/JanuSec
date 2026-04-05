from __future__ import annotations

from src.api import report_aggregation as agg


class _StubState:
    def recent_alerts(self, *args, **kwargs):
        return []


def _stub_sessions(_session_ids: list[str]):
    return [], {
        'suspicious_cells': 0,
        'base64_matches': 0,
        'powershell_matches': 0,
        'examples': {'base64': [], 'powershell': []},
    }


def _stub_decisions(limit: int = 500):
    return {
        'total': 4,
        'verdict_counts': {'review': 3, 'block': 1},
        'severity_distribution': {'critical': 1, 'high': 1, 'medium': 1, 'low': 1},
        'top_mitre': [],
        'flagged_events': [
            {'event_id': 'evt-exec', 'verdict': 'review', 'confidence': 0.81, 'factors': ['f1'], 'persona_tags': ['executive']},
            {'event_id': 'evt-soc', 'verdict': 'review', 'confidence': 0.73, 'factors': ['f2'], 'persona_tags': ['soc_analyst']},
            {'event_id': 'evt-generic', 'verdict': 'review', 'confidence': 0.65, 'factors': ['f3']},
        ],
        'autoblocked_samples': [
            {'event_id': 'evt-auto', 'verdict': 'block', 'confidence': 0.95, 'factors': ['f4'], 'persona_tags': ['soc_analyst']},
        ],
    }


def _stub_network_snapshot(_tenant: str | None):
    return {
        'generated_at': 123.0,
        'window_seconds': 900,
        'top_talkers': [{'ip': '10.0.0.5', 'count': 4, 'stage': 'Delivery'}],
        'beacon_findings': [{'src_ip': '10.0.0.4', 'dst_ip': '8.8.8.8', 'score': 0.92, 'stage': 'Command and Control'}],
        'suspicious_asn': [{'asn': 'AS64500', 'src_ip': '10.0.0.7', 'dst_ip': '4.4.4.4'}],
        'kill_chain': {'stage_counts': {'Delivery': 4}, 'dominant_stage': 'Delivery'},
        'dread': {'score': 6.2, 'damage': 6, 'reproducibility': 5, 'exploitability': 4, 'affected_users': 3, 'discoverability': 2},
        'missing_log': {'flag': False},
        'narrative': ['demo network narrative'],
        'pasta': {'stage': 'Attack Surface Analysis'},
    }


def test_build_ingestion_report_filters_persona(monkeypatch):
    agg._REPORT_CACHE.clear()
    monkeypatch.setattr(agg, 'aggregate_decisions', _stub_decisions)
    monkeypatch.setattr(agg, 'collect_tabular_sessions', _stub_sessions)
    monkeypatch.setattr(agg, 'aggregate_alerts', lambda *args, **kwargs: ([], 0))
    monkeypatch.setattr(agg, 'get_network_highlights_snapshot', _stub_network_snapshot)

    state = _StubState()
    exec_report = agg.build_ingestion_report(
        session_ids=[],
        include_alerts=False,
        limit_alerts=0,
        state=state,
        persona='executive',
        variant='executive',
    )
    exec_ids = [row['event_id'] for row in exec_report['flagged_events']]
    assert 'evt-exec' in exec_ids
    assert 'evt-soc' not in exec_ids
    assert 'evt-generic' in exec_ids  # unlabeled rows remain visible
    assert exec_report['network_highlights']['top_talkers']
    assert exec_report['network_artifacts'], 'expected network artifacts for executive persona'
    # Same parameters should hit cache without recomputing
    exec_report_cached = agg.build_ingestion_report(
        [], False, 0, state, persona='executive', variant='executive'
    )
    assert exec_report_cached['flagged_events'] == exec_report['flagged_events']

    soc_report = agg.build_ingestion_report(
        session_ids=[],
        include_alerts=False,
        limit_alerts=0,
        state=state,
        persona='soc_analyst',
        variant='technical',
    )
    soc_ids = [row['event_id'] for row in soc_report['flagged_events']]
    assert 'evt-soc' in soc_ids
    assert 'evt-exec' not in soc_ids
    assert 'evt-generic' in soc_ids
    assert soc_report['meta']['persona'] == 'soc_analyst'
    assert soc_report['network_artifacts'], 'persona-scoped artifacts should be present'

    agg._REPORT_CACHE.clear()
