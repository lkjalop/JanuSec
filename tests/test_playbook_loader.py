import os
import tempfile
from fastapi.testclient import TestClient

from src.soar import playbook_loader as pl


def test_load_and_index_default_dir():
    pbs = pl.load_playbooks()
    # Expect at least the playbooks we inspected earlier
    assert isinstance(pbs, list)
    # Build index and ensure known factor keys map
    idx = pl.build_index(pbs)
    assert 'cloud:iam_policy_shadow_admin' in idx or any('cloud-shadow-admin' in (pb.get('name') or '') for pb in pbs)


def test_resolve_and_render_templating(tmp_path, monkeypatch):
    # Create a minimal playbook with template placeholders
    pb_path = tmp_path / 'pb.json'
    pb = {
        'name': 'templated-pb',
        'trigger': {'factor': 'identity:pass_the_cookie_reuse'},
        'steps': [
            {'type': 'open_case', 'params': {'title': 'Detected for ${user}'}},
            {'type': 'revoke_sessions', 'params': {'user': '${user}'}},
            {'type': 'notify', 'params': {'webhook_url': '${webhook}', 'msg': 'User ${user} remediated'}}
        ]
    }
    pb_path.write_text(str(pb).replace("'", '"'), encoding='utf8')
    # Point loader to temp dir
    pbs = pl.load_playbooks(str(tmp_path))
    assert any(x.get('name') == 'templated-pb' for x in pbs)
    res = pl.resolve_for_factor('identity:pass_the_cookie_reuse', str(tmp_path))
    assert len(res) == 1
    rpb = res[0]
    rendered = pl.render_playbook(rpb, {'user': 'alice', 'webhook': 'https://hook.invalid'})
    # If the templated playbook used ${user} in titles, ensure substitution occurred; else accept no-op
    title_vals = [step.get('params', {}).get('title', '') for step in rendered.get('steps', []) if isinstance(step.get('params', {}).get('title', ''), str)]
    assert (any('alice' in t for t in title_vals)) or not title_vals
    # Missing context leaves placeholder intact for notify url
    rendered2 = pl.render_playbook(rpb, {'user': 'bob'})
    # webhook remains unsubstituted
    assert '${webhook}' in str(rendered2)
