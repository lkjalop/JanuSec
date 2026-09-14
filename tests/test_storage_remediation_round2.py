import asyncio
import json
from types import SimpleNamespace
import pytest
from fastapi import HTTPException


def test_crown_jewels_rejects_foreign_authenticated_tenant():
    from src.api.config_endpoints import get_crown_jewels
    request = SimpleNamespace(state=SimpleNamespace(tenant_id='acme', auth=SimpleNamespace(tenant_id='acme')), headers={})
    with pytest.raises(HTTPException) as error:
        asyncio.run(get_crown_jewels('other', request))
    assert error.value.status_code == 403


def test_crown_jewels_does_not_inherit_unowned_legacy_file(tmp_path, monkeypatch):
    from src.api import config_endpoints as module
    legacy = tmp_path / 'legacy.json'
    legacy.write_text(json.dumps({'assets': {'private': 'old customer'}}))
    monkeypatch.setattr(module, '_DATA_DIR', str(tmp_path))
    monkeypatch.setattr(module, '_DEFAULT_CJ', str(legacy))
    assert module._load_crown_jewels('new-tenant')['assets'] == {}


def test_mapping_audit_does_not_store_api_key(tmp_path, monkeypatch):
    from src.api import mapping_templates as module
    monkeypatch.setattr(module, 'BASE_DIR', str(tmp_path))
    request = SimpleNamespace(state=SimpleNamespace(tenant_id='acme', auth=SimpleNamespace(tenant_id='acme', subject='reviewer')), headers={'x-api-key': 'dummy-private-test-key'})
    asyncio.run(module.save_template('normal', {'mapping': {'host':'hostname'}}, request, tenant_id='acme'))
    saved = (tmp_path / 'acme' / 'normal.json').read_text()
    assert 'dummy-private-test-key' not in saved
    assert json.loads(saved)['saved_by'] == 'reviewer'


@pytest.mark.parametrize('name', ['../outside', '..\\outside', 'C:\\outside', 'a:stream'])
def test_mapping_paths_reject_traversal(tmp_path, monkeypatch, name):
    from src.api import mapping_templates, csv_mapping_endpoints
    monkeypatch.setattr(mapping_templates, 'BASE_DIR', str(tmp_path))
    monkeypatch.setattr(csv_mapping_endpoints, '_mapping_dir', str(tmp_path))
    with pytest.raises(ValueError):
        mapping_templates._path('acme', name)
    with pytest.raises(ValueError):
        csv_mapping_endpoints._path_for(name, 'acme')


def test_assessment_loader_rejects_external_index_and_prefix_collision(tmp_path, monkeypatch):
    from src.api.deep_analyze import persistence as module
    root = tmp_path / 'assessments'
    (root / 'index').mkdir(parents=True)
    outside = tmp_path / 'private.json'
    outside.write_text('{"assessment_id":"wanted","private":true}')
    (root / 'index' / 'wanted.path').write_text(str(outside))
    (root / 'wanted-extra.json').write_text('{"assessment_id":"wanted-extra"}')
    monkeypatch.setenv('SESSION_PERSIST_DIR', str(root))
    monkeypatch.setattr(module, 'REPORT_STORE', {})
    assert module._get_assessment_cached('wanted') is None
    assert module._load_assessment_from_disk('wanted', str(outside)) is None
    (root / 'wanted.json').write_text('{"assessment_id":"wanted","tenant_id":"acme"}')
    assert module._get_assessment_cached('wanted')['tenant_id'] == 'acme'
