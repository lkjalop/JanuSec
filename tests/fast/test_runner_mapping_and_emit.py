from src.core.rules.runner import run_rule, _resolve_mapping_for_join
from src.core.rules.schema import DetectionRule
from types import SimpleNamespace
import src.core.rules.runner as runner_mod


def test_resolve_mapping_for_join_prefix():
    class HG:
        adj = {'user:alice': [], 'host:win1': [], 'process:1': []}
    mapping = {'user': 'alice'}
    c = _resolve_mapping_for_join(HG(), mapping)
    assert 'user:alice' in c


def test_emit_incident_http_called(monkeypatch):
    called = {'count': 0, 'last': None}

    def fake_post(url, json, headers, timeout):
        called['count'] += 1
        called['last'] = {'url': url, 'json': json, 'headers': headers}
        class R: pass
        r = R()
        r.status_code = 201
        return r

    monkeypatch.setattr(runner_mod, 'requests', SimpleNamespace(post=fake_post))

    # construct a simple rule and graph
    meta = {'id':'r2','name':'r2','description':None,'author':None,'version':None,'tags':[]}
    payload = {'meta':meta,'conditions':[{'field':'event.source','op':'eq','value':'office_macro'}],'actions':[], 'enabled':True}
    r = DetectionRule.model_validate(payload)
    class HG:
        adj = {'office_macro':[('proc:1','exec',{})]}
    actions = run_rule(r, HG(), emit_incident=True, dry_run=False, incident_url='http://example.local/api/v1/incidents')
    assert called['count'] >= 1
    assert called['last']['url'] == 'http://example.local/api/v1/incidents'
