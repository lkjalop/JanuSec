import time

from src.incidents.aggregator import IncidentAggregator


def test_incident_aggregator_tracks_correlation_and_catalog():
    agg = IncidentAggregator(window_seconds=600, factor_overlap=1)
    event = {
        'event_id': 'evt-1',
        'ts': time.time(),
        'correlation_insights': [
            {
                'type': 'multi_domain_chain',
                'chain_id': 'chain-abc',
                'narrative': 'Identity + network overlap',
                'confidence': 0.92,
                'recommendations': ['reset credentials'],
                'recommendation_catalog': [{'domain': 'identity', 'action': 'reset user credentials', 'priority': 'high'}],
                'hopgraph_context': {'summary': 'User pivoted to remote host', 'chains': [{'nodes': ['user:alice', 'host:web01']}]},
                'expires_at': time.time() + 3600,
            }
        ],
    }
    incident = agg.ingest(event, ['factor:test'])
    assert incident['correlation_insights'], "incident should record correlation insights"
    assert incident['recommendation_catalog'][0]['action'] == 'reset user credentials'
    inc_list = agg.list_incidents()
    assert inc_list[0]['correlation_insights'][0]['ttl_seconds'] >= 0
    assert isinstance(inc_list[0]['recommendation_catalog'], list)
    timeline = inc_list[0].get('correlation_timeline') or []
    assert timeline and timeline[-1]['chain_id'] == 'chain-abc'
