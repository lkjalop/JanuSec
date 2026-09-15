from src.reporting.playbooks import map_actions_to_playbook


def test_map_isolate_playbook():
    parsed = {'summary': 'Host exhibiting suspicious behavior', 'actions': [{'desc': 'Isolate the host immediately', 'urgency': 'immediate'}], 'evidence_refs': ['evt_1234']}
    out = map_actions_to_playbook(parsed)
    assert isinstance(out, list)
    assert out[0]['playbook'] == 'isolate_host'


def test_map_collect_playbook():
    parsed = {'summary': 'Possible malware', 'actions': [{'desc': 'Fetch the artifact by SHA256', 'urgency': 'urgent'}], 'evidence_refs': ['deadbeef'*8]}
    out = map_actions_to_playbook(parsed)
    assert any(p['playbook'] == 'collect_artifact' for p in out)
