import asyncio
import os
import json
from fastapi import Header
from src.api.mapping_templates import list_templates, save_template, get_template, delete_template

class DummyRequest:
    def __init__(self):
        self.headers = {'x-api-key':'devkey123'}


def arun(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_mapping_template_crud(tmp_path, monkeypatch):
    monkeypatch.setenv('MAPPING_TEMPLATES_DIR', str(tmp_path))
    tenant = 'tenantX'
    # Initially list empty
    res = arun(list_templates(tenant_id=tenant))
    assert res['tenant'] == tenant
    assert res['templates'] == []
    # Save template
    payload = {'mapping': {'user':'username','host':'hostname'}}
    arun(save_template('base', payload, DummyRequest(), tenant_id=tenant))
    # Get template
    got = arun(get_template('base', tenant_id=tenant))
    assert got['mapping']['mapping']['user'] == 'username'
    # List again
    res2 = arun(list_templates(tenant_id=tenant))
    assert len(res2['templates']) == 1
    # Delete
    arun(delete_template('base', tenant_id=tenant))
    res3 = arun(list_templates(tenant_id=tenant))
    assert res3['templates'] == []
