from src.incidents.evidence import incident_to_html


def test_incident_to_html_includes_dread_from_metadata():
    incident = {
        'id': 'inc-1',
        'host': 'host-1',
        'score': 0.9,
        'events': [1,2,3],
        'factors': ['net:beacon_periodic','exfiltration:c2_channel'],
        'dread': {'damage':0.8,'reproducibility':0.7,'exploitability':0.6,'affected_users':0.5,'discoverability':0.4},
        'dread_score': 0.6,
        'dread_severity': 'medium'
    }
    html = incident_to_html(incident)
    assert 'DREAD Score' in html
    assert '0.6' in html
    assert 'medium' in html
    # components
    assert 'damage' in html and '0.8' in html


def test_incident_to_html_computes_dread_when_missing():
    incident = {
        'id': 'inc-2',
        'host': 'host-2',
        'score': 0.2,
        'events': [],
        'factors': ['net:beacon_periodic','ssl:ja3_known_bad']
    }
    html = incident_to_html(incident)
    # Should include DREAD Score label and components list (computed)
    assert 'DREAD Score' in html
    assert 'DREAD Components' in html
