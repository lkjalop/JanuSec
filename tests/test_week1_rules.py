import json
from src.core.correlation.rules.week1.powershell_encoded import powershell_encoded
from src.core.correlation.rules.week1.amsi_bypass import amsi_bypass
from src.core.correlation.rules.week1.office_macro_chain import office_macro_chain
from src.core.correlation.rules.week1.office_spawn_ps import office_spawn_ps
from src.core.correlation.rules.week1.scheduled_task_lolbin import scheduled_task_lolbin
from src.core.correlation.rules.week1.office_macro_chain_enriched import office_macro_chain_enriched


def _load(path: str):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def test_powershell_encoded_positive():
    evt = _load('tests/data/powershell_encoded_event.json')
    assert powershell_encoded(evt)


def test_powershell_encoded_negative():
    assert not powershell_encoded({'command_line': 'powershell -NoProfile'})


def test_amsi_bypass_pattern():
    evt = _load('tests/data/amsi_bypass_event.json')
    assert amsi_bypass(evt)


def test_office_macro_chain():
    evt = _load('tests/data/office_macro_chain_event.json')
    assert office_macro_chain(evt)


def test_office_spawn_ps_simple():
    evt = _load('tests/data/office_spawn_ps_event.json')
    assert office_spawn_ps(evt)


def test_scheduled_task_lolbin():
    evt = _load('tests/data/scheduled_task_lolbin_event.json')
    assert scheduled_task_lolbin(evt)


def test_office_macro_chain_enriched():
    evt = _load('tests/data/office_macro_chain_enriched_event.json')
    assert office_macro_chain_enriched(evt)
