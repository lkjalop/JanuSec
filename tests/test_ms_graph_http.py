import os
import pytest
from unittest.mock import patch

from src.connectors.email.ms_graph import MSGraphHTTPConnector


def test_token_flow_and_search_and_quarantine(monkeypatch):
    os.environ['MS_GRAPH_ENABLED'] = '1'
    os.environ['MS_GRAPH_CLIENT_ID'] = 'cid'
    os.environ['MS_GRAPH_CLIENT_SECRET'] = 'csecret'
    os.environ['MS_GRAPH_TENANT_ID'] = 'tenant'
    os.environ['MS_GRAPH_SEARCH_ENDPOINT'] = 'https://graph.local/search'
    os.environ['MS_GRAPH_QUARANTINE_ENDPOINT'] = 'https://graph.local/quarantine'

    connector = MSGraphHTTPConnector()

    # mock token response
    def fake_post_token(url, data=None, timeout=None, **k):
        class R:
            def raise_for_status(self):
                pass
            def json(self):
                return {'access_token': 'tok-1', 'expires_in': 3600}
        return R()

    # mock paged search responses: first returns two messages and a nextLink, second returns one
    calls = {'search': 0}

    def fake_get(url, params=None, headers=None, timeout=None, **k):
        class R:
            def raise_for_status(self):
                pass
            def json(self):
                if calls['search'] == 0:
                    calls['search'] += 1
                    return {'messages': [{'id': 'm1'}, {'id': 'm2'}], '@odata.nextLink': 'https://graph.local/search?page=2'}
                else:
                    return {'messages': [{'id': 'm3'}]}
        return R()

    def fake_post_quarantine(url, json=None, headers=None, timeout=None, **k):
        class R:
            def raise_for_status(self):
                pass
            def json(self):
                return {'quarantined': len(json.get('message_ids', [])), 'failed': 0}
        return R()

    def fake_post(url, data=None, json=None, timeout=None, **k):
        # token endpoint
        if 'oauth2' in (url or ''):
            return fake_post_token(url, data=data, timeout=timeout)
        # quarantine endpoint
        if url and url.startswith('https://graph.local/quarantine'):
            return fake_post_quarantine(url, json=json, headers=None, timeout=timeout)
        # fallback
        return fake_post_token(url, data=data, timeout=timeout)

    monkeypatch.setattr('requests.post', fake_post)
    monkeypatch.setattr('requests.get', fake_get)

    res = connector.search_similar_messages('t', 'q', top=10)
    assert len(res) == 3
    qres = connector.quarantine_messages('t', ['m1', 'm2', 'm3'])
    assert qres.get('quarantined') == 3
