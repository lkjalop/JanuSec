import pytest
from unittest.mock import patch

from src.reporting import playbooks


def test_map_actions_via_llm_with_mocked_cached_generate():
    # prepare parsed actions that heuristics won't map
    parsed = {'actions': [{'desc': 'Please triage and block the suspicious host', 'urgency': 'high'}], 'evidence_refs': []}

    # mock cached_generate to return a dict-like response containing playbook names
    mocked_resp = {'text': 'I suggest using isolate_host and block_ip playbooks for these actions.'}

    with patch.object(playbooks, 'cached_generate', return_value=mocked_resp):
        result = playbooks.map_actions_via_llm(parsed)
        assert isinstance(result, list)
        # should include at least one recognized playbook mapping
        assert any(r.get('playbook') in playbooks.PLAYBOOKS for r in result)


def test_map_actions_via_llm_no_llm_available(monkeypatch):
    monkeypatch.setattr(playbooks, 'cached_generate', None)
    parsed = {'actions': [{'desc': 'Fetch file by sha256: a'*64, 'urgency': 'low'}], 'evidence_refs': []}
    res = playbooks.map_actions_via_llm(parsed)
    assert res == []
