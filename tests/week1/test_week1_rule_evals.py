import json
import os
from src.core.correlation.rules.registry import CORRELATION_RULES

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
DATA_DIR = os.path.join(ROOT, 'tests', 'data')


def load_vector(name: str):
    path = os.path.join(DATA_DIR, name)
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def test_powershell_encoded_fires():
    evt = load_vector('powershell_encoded_event.json')
    fired = CORRELATION_RULES.evaluate(evt)
    names = [r.name for r in fired]
    assert 'powershell_encoded_command' in names


def test_office_macro_chain_fires():
    evt = load_vector('office_macro_chain_event.json')
    fired = CORRELATION_RULES.evaluate(evt)
    names = [r.name for r in fired]
    assert 'office_macro_external_c2_chain' in names


def test_amsi_bypass_fires():
    evt = load_vector('amsi_bypass_event.json')
    fired = CORRELATION_RULES.evaluate(evt)
    names = [r.name for r in fired]
    assert 'powershell_amsi_bypass_pattern' in names


def test_powershell_encoded_fp_not_fire():
    evt = load_vector('powershell_fp_missing_enc.json')
    fired = CORRELATION_RULES.evaluate(evt)
    names = [r.name for r in fired]
    assert 'powershell_encoded_command' not in names


def test_office_macro_fp_not_fire():
    evt = load_vector('office_macro_fp_no_network.json')
    fired = CORRELATION_RULES.evaluate(evt)
    names = [r.name for r in fired]
    assert 'office_macro_external_c2_chain' not in names


def test_office_spawn_fp_not_fire():
    evt = load_vector('office_spawn_fp_non_office_parent.json')
    fired = CORRELATION_RULES.evaluate(evt)
    names = [r.name for r in fired]
    assert 'office_spawn_powershell' not in names


def test_scheduled_task_fp_not_fire():
    evt = load_vector('scheduled_task_fp_no_lolbin.json')
    fired = CORRELATION_RULES.evaluate(evt)
    names = [r.name for r in fired]
    assert 'scheduled_task_lolbin_anomaly' not in names
