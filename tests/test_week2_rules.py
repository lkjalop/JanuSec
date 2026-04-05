import json
from src.core.correlation.rules.week2.registry_run_keys import registry_run_key
from src.core.correlation.rules.week2.new_service_nonstandard_path import new_service_nonstandard
from src.core.correlation.rules.week2.lsass_openprocess import lsass_openprocess


def _load(p):
    with open(p,'r',encoding='utf-8') as f:
        return json.load(f)


def test_registry_run_key():
    evt = _load('tests/data/registry_run_key_event.json')
    assert registry_run_key(evt)


def test_new_service_nonstandard():
    evt = _load('tests/data/new_service_nonstandard_event.json')
    assert new_service_nonstandard(evt)


def test_lsass_openprocess():
    evt = _load('tests/data/lsass_openprocess_event.json')
    assert lsass_openprocess(evt)
